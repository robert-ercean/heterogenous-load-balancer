package bpfloader

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

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
}

// BackendEntry mirrors "struct backend_entry" in xdp_forward.c.
// Field order, padding, and total size match exactly
type BackendEntryBPF struct {
	IP        uint32 // network byte order in memory
	Port      uint16 // network byte order in memory
	_Pad      uint16
	LoadScore uint32
	_Pad2     uint32
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

	l := &Loader{}

	if err := loadXdpforwardObjects(&l.xdpObjs, nil); err != nil {
		return nil, fmt.Errorf("[BPF_LOADER] load XDP objects: %w", err)
	}

	if err := loadTcreturnObjects(&l.tcObjs, nil); err != nil {
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
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("[BPF_LOADER] attach XDP to %s: %w", ifaceName, err)
	}

	l.xdpLink = link
	log.Printf("[BPF_LOADER] XDP attached to %s", ifaceName)
	return nil
}

func (l *Loader) AttachTC(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("[BPF_LOADER] interface %s: %w", ifaceName, err)
	}

	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   l.tcObjs.TcReturn,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("[BPF_LOADER] attach TC ingress to %s: %w", ifaceName, err)
	}

	l.tcLink = tcLink
	log.Printf("[BPF_LOADER] TC ingress attached to %s", ifaceName)

	return nil
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

// SetBackend writes a backend into the next available slot of the given pool's BPF map
// and increments the pool's active count.
//
// For now we only support adding (no removal, no slot reuse).
// We'll add proper slot management when we integrate with the registry's full lifecycle.
func (l *Loader) SetBackend(pool Pool, ip net.IP, port uint16, loadScore uint32) error {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("[BPF_LOADER] not an IPv4 address: %s", ip)
	}

	entry := BackendEntryBPF{
		IP:        binary.LittleEndian.Uint32(ipv4),
		Port:      htons(port),
		LoadScore: loadScore,
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

	log.Printf("[BPF_LOADER] %s backend added at slot %d: %s:%d (active count now %d)",
		poolName, slot, ip, port, newCount)
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
