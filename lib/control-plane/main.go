package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lb/control-plane/httplistener"
	"lb/control-plane/registry"
	"lb/control-plane/udplistener"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("[MAIN] starting control plane")

	reg := registry.CreateRegistry()
	UDPlistenPort := ":9999"
	HTTPlistenPort := ":9998"

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

	// Start stale backend pruner
	go loopForDeadDevices(reg)

	// Print registry state every 10s for visibility
	go reportLoop(reg)

	// Block on shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("[MAIN] shutting down")
}

func loopForDeadDevices(reg *registry.Registry) {
	loopInterval := 5 * time.Second
	staleThreshold := 15 * time.Second

	ticker := time.NewTicker(loopInterval)
	defer ticker.Stop()

	for range ticker.C {
		reg.RemoveDeadBackendEntries(staleThreshold)
	}
}

func reportLoop(reg *registry.Registry) {
	ticker := time.NewTicker(10 * time.Second)
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
