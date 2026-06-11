package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	Magic        uint32 = 0xDEADBEEF
	MsgRegister  uint8  = 0x01
	MsgAck       uint8  = 0x02
	MsgHeartbeat uint8  = 0x03
	PacketSize          = 8
)

// encodeRegister builds the 8-byte REGISTER payload
func encodeRegister(port uint16) []byte {
	b := make([]byte, PacketSize)
	binary.BigEndian.PutUint32(b[0:4], Magic)
	b[4] = MsgRegister
	binary.BigEndian.PutUint16(b[5:7], port)
	b[7] = 0x00
	return b
}

// encodeHeartbeat builds the 8-byte HEARTBEAT payload with a load score
func encodeHeartbeat(load uint8) []byte {
	b := make([]byte, PacketSize)
	binary.BigEndian.PutUint32(b[0:4], Magic)
	b[4] = MsgHeartbeat
	b[5] = load
	b[6] = 0x00
	b[7] = 0x00
	return b
}

func startControlPlaneLoop(cpAddr string, servicePort uint16, bindIP string) {
	rAddr, err := net.ResolveUDPAddr("udp", cpAddr)
	if err != nil {
		log.Fatalf("[CONTROL] Error resolving control plane addr: %v", err)
	}

	lAddrStr := fmt.Sprintf("%s:0", bindIP)
	lAddr, err := net.ResolveUDPAddr("udp", lAddrStr)
	if err != nil {
		log.Fatalf("[CONTROL] Error resolving local bind addr %s: %v", lAddrStr, err)
	}

	// NEW: Pass lAddr instead of nil!
	conn, err := net.DialUDP("udp", lAddr, rAddr)

	if err != nil {
		log.Fatalf("[CONTROL] Error dialing UDP to control plane: %v", err)
	}
	defer conn.Close()

	// 1. Send REGISTER
	regPkt := encodeRegister(servicePort)
	if _, err := conn.Write(regPkt); err != nil {
		log.Fatalf("[CONTROL] Registration send failed: %v", err)
	}
	log.Printf("[CONTROL] Sent REGISTER to %s for port %d", cpAddr, servicePort)

	// 2. Await ACK
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Fatalf("[CONTROL] Failed to set read deadline: %v", err)
	}

	ackBuf := make([]byte, 16)
	n, err := conn.Read(ackBuf)
	if err != nil {
		log.Fatalf("[CONTROL] Failed to receive ACK from LB: %v", err)
	}

	if n != PacketSize || binary.BigEndian.Uint32(ackBuf[0:4]) != Magic || ackBuf[4] != MsgAck {
		log.Fatalf("[CONTROL] Invalid ACK packet received from LB")
	}
	log.Printf("[CONTROL] Registration ACK received successfully!")

	// 3. Persistent HEARTBEAT
	_ = conn.SetReadDeadline(time.Time{})
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		loadScore := uint8(1)
		hbPkt := encodeHeartbeat(loadScore)
		if _, err := conn.Write(hbPkt); err != nil {
			log.Printf("[CONTROL] Heartbeat send failed: %v", err)
		}
	}
}

func main() {
	bindIP := flag.String("bind", "0.0.0.0", "IP address to bind to")
	port := flag.Int("port", 50051, "UDP port to listen on")
	cpAddr := flag.String("cp", "172.31.34.36:5555", "LB control plane UDP address")
	packetSize := flag.Int("packet-size", 1024, "Response packet size in bytes")
	flag.Parse()

	// --- 1. Start Control Plane Loop in Background ---
	go startControlPlaneLoop(*cpAddr, uint16(*port), *bindIP)

	// --- 2. Start Data Plane Worker ---
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

	log.Printf("[DATA_PLANE] Listening for UDP data on %s", addr)

	responsePayload := make([]byte, *packetSize)
	for i := range responsePayload {
		responsePayload[i] = '.'
	}

	payload := fmt.Sprintf("Hello from %s:%d", *bindIP, *port)
	copy(responsePayload, payload)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		buf := make([]byte, 2048)
		for {
			_, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(responsePayload, clientAddr)
		}
	}()

	<-sigChan
	log.Printf("[MAIN] Shutting down agent on %s", addr)
}
