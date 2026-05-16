package bpfloader

import (
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

func New() (*Loader, error) {
	// Remove memory limit on locked memory (BPF maps live in locked memory)
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	l := &Loader{}

	if err := loadXdpforwardObjects(&l.xdpObjs, nil); err != nil {
		return nil, fmt.Errorf("load XDP objects: %w", err)
	}

	if err := loadTcreturnObjects(&l.tcObjs, nil); err != nil {
		l.xdpObjs.Close()
		return nil, fmt.Errorf("load TC objects: %w", err)
	}

	log.Printf("[bpfloader] BPF programs loaded successfully")
	return l, nil
}

func (l *Loader) AttachXDP(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifaceName, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   l.xdpObjs.XdpForward,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
	}

	l.xdpLink = link
	log.Printf("[BPF_LOADER] XDP attached to %s", ifaceName)
	return nil
}

func (l *Loader) AttachTC(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifaceName, err)
	}

	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   l.tcObjs.TcReturn,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach TC ingress to %s: %w", ifaceName, err)
	}

	l.tcLink = tcLink
	log.Printf("[BPF_LOADER] TC ingress attached to %s", ifaceName)

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
