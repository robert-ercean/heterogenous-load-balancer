package controlplane

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lb/control-plane/registry"
	"lb/control-plane/udplistener"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("[main] starting control plane")

	reg := registry.CreateRegistry()
	listenPort := ":9998"

	// Start UDP listener for UDP backends
	go func() {
		if err := udplistener.Start(listenPort, reg); err != nil {
			log.Fatalf("[main] UDP listener failed: %v", err)
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

	log.Println("[main] shutting down")
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
		backends := reg.Stringify()
		log.Printf("[main] %d backends registered:", len(backends))
		for _, b := range backends {
			log.Printf("        %s pool=%s port=%d load=%d last_seen=%s ago",
				b.IP, b.Pool, b.Port, b.LoadScore,
				time.Since(b.LastSeen).Round(time.Millisecond))
		}
	}
}
