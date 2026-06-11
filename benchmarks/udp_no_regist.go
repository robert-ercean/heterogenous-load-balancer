package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	bindIP := flag.String("bind", "0.0.0.0", "IP address to bind to")
	port := flag.Int("port", 50051, "UDP port to listen on")
	packetSize := flag.Int("packet-size", 1024, "Response packet size in bytes")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *bindIP, *port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("[FATAL] Invalid bind address %s: %v", addr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("[FATAL] Failed to listen on %s: %v", addr, err)
	}
	defer conn.Close()

	log.Printf("[UDP_WORKER] Listening for UDP data on %s", addr)

	responsePayload := make([]byte, *packetSize)
	for i := range responsePayload {
		responsePayload[i] = '.'
	}

	payload := fmt.Sprintf("Hello from %s:%d", *bindIP, *port)
	copy(responsePayload, payload)

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		buf := make([]byte, 2048)
		for {
			_, clientAddr, err := conn.ReadFromUDP(buf) 
			if err != nil {
				// Avoid spamming logs on connection closure
				continue
			}

			// Echo back our configured response payload
			_, _ = conn.WriteToUDP(responsePayload, clientAddr)
		}
	}()

	<-sigChan
	log.Printf("[UDP_WORKER] Shutting down agent on %s", addr)
}
