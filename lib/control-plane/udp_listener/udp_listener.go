package udplistener

import (
	"log"
	"net"

	"lb/control-plane/registry"
)

func Start(addr string, reg *registry.Registry) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	log.Printf("[UDP_LISTENER] listening on %s", addr)

	// even though packets are 8 bytes, we'll read into a larger buffer: ~64
	buf := make([]byte, 64)

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[UDP_LISTENER] read error: %v", err)
			continue
		}

		// Copy the packet — buf is reused across iterations
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// Spawn a goroutine for handling each control packet
		go handlePacket(conn, reg, src, pkt)
	}
}

func handlePacket(conn *net.UDPConn, reg *registry.Registry, src *net.UDPAddr, pkt []byte) {
	msgType, payload, err := Decode(pkt)
	if err != nil {
		log.Printf("[UDP_LISTENER] decode error from %s: %v", src.IP, err)
		return
	}

	switch msgType {
	case MsgRegister:
		msg := payload.(RegisterMsg)

		reg.RegisterBackendEntry(registry.PoolUDP, src.IP, msg.Port)

		ack := EncodeAck()
		if _, err := conn.WriteToUDP(ack, src); err != nil {
			log.Printf("[UDP_LISTENER] failed to send ACK to %s: %v", src.IP, err)
		}

	case MsgHeartbeat:
		reg.HandleHeartbeat(src.IP)

	default:
		log.Printf("[UDP_LISTENER] Unknown msg type 0x%02X from %s", msgType, src.IP)
	}
}
