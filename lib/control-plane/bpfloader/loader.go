package bpfloader

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"bytes"
    "os"
    "os/exec"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -I../bpf/include" -target amd64 xdpforward ../bpf/xdp_forward.c
//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -I../bpf/include" -target amd64 tcreturn   ../bpf/tc_return.c

type Loader struct {
	xdpObjs xdpforwardObjects
	tcObjs  tcreturnObjects

	xdpLink link.Link
	tcLink  link.Link
	tcIface    string       // new — used by legacy path for DetachTC
    tcPinPath  string       // new — used by legacy path for DetachTC
	// slotMap maps backend IP → BPF map slot for fast load score updates.
	// Protected by slotMu since SetBackend and UpdateBackendLoadScore
	// can run from different goroutines.
	slotMu  sync.Mutex
	slotMap map[string]uint32
}

// BackendEntry mirrors "struct backend_entry" in xdp_forward.c.
// Field order, padding, and total size match exactly
type BackendEntryBPF struct {
	IP        uint32 // network byte order in memory
	Port      uint16 // network byte order in memory
	Pad1      uint16
	LoadScore uint32
	Mac       [6]byte
	Pad2      uint16
}

type Pool uint32

const (
	PoolTCP Pool = 1
	PoolUDP Pool = 2
)

// htons swaps a u16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func New() (*Loader, error) {
	// Remove memory limit on locked memory (BPF maps live in locked memory)
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("[BPF_LOADER] remove memlock: %w", err)
	}

	l := &Loader{
		slotMap: make(map[string]uint32),
	}

	if err := loadXdpforwardObjects(&l.xdpObjs, nil); err != nil {
		return nil, fmt.Errorf("[BPF_LOADER] load XDP objects: %w", err)
	}

	// We use the same underlying BPF maps in both XDP and TC programs, so we need to tell the TC loader to
	// reuse the already loaded maps instead of trying to create new ones
	tcOpts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"tcp_pool":              l.xdpObjs.TcpPool,
			"udp_pool":              l.xdpObjs.UdpPool,
			"pool_meta":             l.xdpObjs.PoolMeta,
			"vip_map":               l.xdpObjs.VipMap,
			"tcp_conntrack_reverse": l.xdpObjs.TcpConntrackReverse,
		},
	}
	if err := loadTcreturnObjects(&l.tcObjs, tcOpts); err != nil {
		l.xdpObjs.Close()
		return nil, fmt.Errorf("[BPF_LOADER] load TC objects: %w", err)
	}

	log.Printf("[BPF_LOADER] BPF programs loaded successfully")
	return l, nil
}

func (l *Loader) AttachXDP(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("[BPF_LOADER] interface %s: %w", ifaceName, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   l.xdpObjs.XdpForward,
		Interface: iface.Index,
		// Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("[BPF_LOADER] attach XDP to %s: %w", ifaceName, err)
	}

	l.xdpLink = link
	log.Printf("[BPF_LOADER] XDP attached to %s", ifaceName)
	return nil
}

func (l *Loader) AttachTC(ifaceName string) error {
	// Try the modern tcx API first (kernel >= 6.6). If it fails because the
	// kernel doesn't support it, fall back to the legacy clsact+filter approach
	// via the `tc` command. This keeps both newer and older kernels working.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("[BPF_LOADER] interface %s: %w", ifaceName, err)
	}

	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   l.tcObjs.TcReturn,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err == nil {
		l.tcLink = tcLink
		log.Printf("[BPF_LOADER] TC ingress attached to %s (tcx)", ifaceName)
		return nil
	}

	// tcx unsupported (typically "tcx not supported (requires >= v6.6)").
	// Fall back to the legacy clsact + tc filter path.
	log.Printf("[BPF_LOADER] tcx unavailable (%v), falling back to clsact+tc", err)

	return l.attachTCLegacy(ifaceName)
}

// attachTCLegacy uses the `tc` userspace tool to install a clsact qdisc on the
// interface and pin the BPF program as an ingress filter. Requires the BPF
// object to exist on disk (pinned), since the `tc` command reads from a file
// path rather than an fd.
func (l *Loader) attachTCLegacy(ifaceName string) error {
	// Pin the loaded TC program to a bpffs path so the `tc` command can attach
	// it by path. The pin survives across runs of the control plane; we unpin
	// in DetachTC.
	const pinDir = "/sys/fs/bpf/lb"
	pinPath := pinDir + "/tc_return"

	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return fmt.Errorf("[BPF_LOADER] mkdir %s: %w", pinDir, err)
	}

	// Remove any stale pin from a previous run.
	_ = os.Remove(pinPath)

	if err := l.tcObjs.TcReturn.Pin(pinPath); err != nil {
		return fmt.Errorf("[BPF_LOADER] pin TC program to %s: %w", pinPath, err)
	}
	l.tcPinPath = pinPath

	// Ensure the clsact qdisc exists on the interface. `tc qdisc add` errors
	// with "RTNETLINK answers: File exists" if it's already there; we treat
	// that as success.
	if out, err := exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact").CombinedOutput(); err != nil {
		if !bytes.Contains(out, []byte("File exists")) {
			return fmt.Errorf("[BPF_LOADER] tc qdisc add clsact dev %s: %w (output: %s)",
				ifaceName, err, bytes.TrimSpace(out))
		}
	}

	// Attach the pinned BPF program as an ingress filter.
	//   `da` = "direct action" (let the BPF program's return value be the TC action).
	//   `pinned <path>` = load the program from bpffs rather than an .o file.
	out, err := exec.Command("tc", "filter", "add", "dev", ifaceName,
		"ingress", "bpf", "da", "pinned", pinPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("[BPF_LOADER] tc filter add on %s: %w (output: %s)",
			ifaceName, err, bytes.TrimSpace(out))
	}

	// Stash the interface so DetachTC can clean up.
	l.tcIface = ifaceName

	log.Printf("[BPF_LOADER] TC ingress attached to %s (clsact+filter legacy)", ifaceName)
	return nil
}

// DetachTC reverses AttachTC. Safe to call even if attach failed partway.
func (l *Loader) DetachTC() {
	// tcx path
	if l.tcLink != nil {
		_ = l.tcLink.Close()
		l.tcLink = nil
		return
	}

	// legacy path: remove filter, qdisc, and pin
	if l.tcIface != "" {
		_ = exec.Command("tc", "filter", "del", "dev", l.tcIface, "ingress").Run()
		_ = exec.Command("tc", "qdisc", "del", "dev", l.tcIface, "clsact").Run()
		l.tcIface = ""
	}
	if l.tcPinPath != "" {
		_ = os.Remove(l.tcPinPath)
		l.tcPinPath = ""
	}
}

// SetVIP writes the given IPv4 address into the VIP map.
// The value is stored such that its in-memory byte representation
// matches the network byte order of __be32 packet fields.
func (l *Loader) SetVIP(vip net.IP) error {
	ipv4 := vip.To4()
	if ipv4 == nil {
		return fmt.Errorf("[BPF_LOADER] not an IPv4 address: %s", vip)
	}

	// binary.LittleEndian.Uint32 reads bytes [a,b,c,d] and returns
	// the u32 whose memory representation on a little-endian host
	// is the same bytes [a,b,c,d]. This matches __be32 in packet headers.
	vipU32 := binary.LittleEndian.Uint32(ipv4)

	key := uint32(0)
	if err := l.xdpObjs.VipMap.Update(key, vipU32, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("[BPF_LOADER] update vip_map: %w", err)
	}

	log.Printf("[BPF_LOADER] VIP set to %s (raw u32: 0x%X)", vip, vipU32)
	return nil
}

// SetLBBridgeIP writes the LB's bridge IP to the TC config map.
// This is the IP that TC BPF will use to identify "control plane traffic"
// and bypass for those packets.
func (l *Loader) SetLBBridgeIP(ip net.IP) error {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}
	val := binary.LittleEndian.Uint32(ipv4)
	key := uint32(0)
	if err := l.tcObjs.LbBridgeIp.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update lb_bridge_ip: %w", err)
	}
	log.Printf("[bpfloader] LB bridge IP set to %s", ip)
	return nil
}

// SetVIPTCPPort writes the VIP's TCP port to the TC config map.
// TC uses this to know what port to rewrite backend reply source ports back to.
func (l *Loader) SetVIPTCPPort(port uint16) error {
	val := uint32(port)
	key := uint32(0)
	if err := l.tcObjs.VipTcpPort.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update vip_tcp_port: %w", err)
	}
	log.Printf("[bpfloader] VIP TCP port set to %d", port)
	return nil
}

// SetBackend writes a backend into the next available slot of the given pool's BPF map
// and increments the pool's active count.
//
// For now we only support adding (no removal, no slot reuse).
// We'll add proper slot management when we integrate with the registry's full lifecycle.
func (l *Loader) SetBackend(pool Pool, ip net.IP, port uint16, loadScore uint32, mac net.HardwareAddr) error {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("[BPF_LOADER] not an IPv4 address: %s", ip)
	}

	entry := BackendEntryBPF{
		IP:        binary.LittleEndian.Uint32(ipv4),
		Port:      htons(port),
		LoadScore: loadScore,
		Mac:       [6]byte{mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]},
	}

	// Pick the right pool map and the right meta slot
	var poolMap *ebpf.Map
	var metaKey uint32
	var poolName string

	switch pool {
	case PoolTCP:
		poolMap = l.xdpObjs.TcpPool
		metaKey = 0
		poolName = "tcp"
	case PoolUDP:
		poolMap = l.xdpObjs.UdpPool
		metaKey = 1
		poolName = "udp"
	default:
		return fmt.Errorf("[BPF_LOADER] unknown pool: %d", pool)
	}

	// Read current active count to know which slot to write to
	var currentCount uint32
	if err := l.xdpObjs.PoolMeta.Lookup(metaKey, &currentCount); err != nil {
		return fmt.Errorf("[BPF_LOADER] read pool_meta[%s]: %w", poolName, err)
	}

	// Write the entry into slot = currentCount
	slot := currentCount
	if err := poolMap.Update(slot, entry, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("[BPF_LOADER] update %s_pool[%d]: %w", poolName, slot, err)
	}

	// Increment active count
	newCount := currentCount + 1
	if err := l.xdpObjs.PoolMeta.Update(metaKey, newCount, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("[BPF_LOADER] update pool_meta[%s]: %w", poolName, err)
	}

	// Record the slot(currentCount) for later load score updates
	l.slotMu.Lock()
	// keyed by "poolName:ip" to distinguish TCP vs UDP backends with the same IP
	l.slotMap[fmt.Sprintf("%s:%s", poolName, ip.String())] = slot
	l.slotMu.Unlock()

	log.Printf("[BPF_LOADER] %s backend added at slot %d: %s:%d (active count now %d)",
		poolName, slot, ip, port, newCount)

	return nil
}

// UpdateBackendLoadScore writes a new load score into the BPF pool entry
// for the backend at the given IP. The slot is looked up via the slot map
// populated by SetBackend.
//
// Returns an error if the backend isn't registered or the BPF update fails.
func (l *Loader) UpdateBackendLoadScore(pool Pool, ip net.IP, loadScore uint32) error {
	var poolMap *ebpf.Map
	var poolName string

	switch pool {
	case PoolTCP:
		poolMap = l.xdpObjs.TcpPool
		poolName = "tcp"
	case PoolUDP:
		poolMap = l.xdpObjs.UdpPool
		poolName = "udp"
	default:
		return fmt.Errorf("[BPF_LOADER] unknown pool: %d", pool)
	}

	// Look up slot for this backend
	key := fmt.Sprintf("%s:%s", poolName, ip.String())
	l.slotMu.Lock()
	slot, ok := l.slotMap[key]
	l.slotMu.Unlock()

	if !ok {
		return fmt.Errorf("[BPF_LOADER] no slot recorded for %s", key)
	}

	// Read current entry, update load_score, write back.
	// Concurrency with SetBackend is fine because BPF map updates
	// are per-entry atomic and we're only changing the load_score field
	var entry BackendEntryBPF
	if err := poolMap.Lookup(slot, &entry); err != nil {
		return fmt.Errorf("[BPF_LOADER] lookup %s_pool[%d]: %w", poolName, slot, err)
	}

	entry.LoadScore = loadScore

	if err := poolMap.Update(slot, entry, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("[BPF_LOADER] update %s_pool[%d]: %w", poolName, slot, err)
	}

	return nil
}

func (l *Loader) Close() error {
	if l.xdpLink != nil {
		l.xdpLink.Close()
	}
	if l.tcLink != nil {
		l.tcLink.Close()
	}
	l.xdpObjs.Close()
	l.tcObjs.Close()
	return nil
}
