package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lb/control-plane/bpfloader"
	"lb/control-plane/healthpoller"
	"lb/control-plane/heartbeatpruner"
	"lb/control-plane/httplistener"
	"lb/control-plane/registry"
	"lb/control-plane/udplistener"
)

const (
	reportIntervalSec      = 10 * time.Second
	backendFacingInterface = "br0"
	VIPInterface           = "enp7s0"
	vipStr                 = "192.168.1.100"
	UDPlistenPort          = ":9999"
	HTTPlistenPort         = ":9998"
	LBBridgeIP             = "172.16.0.1"
	VIPTCPPort             = 5555
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("[MAIN] starting control plane")

	reg := registry.CreateRegistry()

	loader, err := bpfloader.New()
	if err != nil { 
		log.Fatalf("[MAIN] failed to initialize BPF loader: %v", err)
	}
	defer loader.Close()

	if err := loader.SetVIP(net.ParseIP(vipStr)); err != nil {
		log.Fatalf("[MAIN] set VIP: %v", err)
	}
	if err := loader.SetLBBridgeIP(net.ParseIP(LBBridgeIP)); err != nil {
		log.Fatalf("[MAIN] set LB bridge IP: %v", err)
	}
	if err := loader.SetVIPTCPPort(VIPTCPPort); err != nil {
		log.Fatalf("[MAIN] set VIP TCP port: %v", err)
	}

	// Attach XDP to the specified interface (e.g., "eth0")
	if err := loader.AttachXDP(VIPInterface); err != nil {
		log.Fatalf("[MAIN] failed to attach XDP hook: %v", err)
	}

	if err := loader.AttachTC(backendFacingInterface); err != nil {
		log.Fatalf("[MAIN] failed to attach TC hook: %v", err)
	}

	reg.OnRegister(func(b registry.BackendEntry) {
		var pool bpfloader.Pool
		switch b.Pool {
		case registry.PoolTCP:
			pool = bpfloader.PoolTCP
		case registry.PoolUDP:
			pool = bpfloader.PoolUDP
		default:
			log.Printf("[MAIN] unknown pool %v for backend %s", b.Pool, b.IP)
			return
		}
		if err := loader.SetBackend(pool, b.IP, b.Port, b.LoadScore); err != nil {
			log.Printf("[MAIN] failed to set backend in BPF map: %v", err)
		}
	})

	// Start UDP listener for UDP backends
	go func() {
		if err := udplistener.Start(UDPlistenPort, reg); err != nil {
			log.Fatalf("[MAIN] UDP listener failed: %v", err)
		}
	}()

	// Start HTTP listener for TCP backends
	go func() {
		if err := httplistener.Start(HTTPlistenPort, reg); err != nil {
			log.Fatalf("[MAIN] HTTP listener failed: %v", err)
		}
	}()

	// Start stale UDP backends pruner
	pruner := heartbeatpruner.New(reg)
	go pruner.Run()

	// Start health poller for TCP backends
	poller := healthpoller.New(reg)
	go poller.Run(ctx)

	// Print registry state every 10s for visibility
	go reportLoop(reg)

	// Block on shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("[MAIN] shutting down")
}

func reportLoop(reg *registry.Registry) {
	ticker := time.NewTicker(reportIntervalSec)
	defer ticker.Stop()
	for range ticker.C {
		backends := reg.Listify()
		log.Printf("[MAIN] %d backends registered:", len(backends))
		for _, b := range backends {
			log.Printf("        %s pool=%s port=%d load=%d last_seen=%s ago",
				b.IP, b.Pool, b.Port, b.LoadScore,
				time.Since(b.LastSeen).Round(time.Millisecond))
		}
	}
}
