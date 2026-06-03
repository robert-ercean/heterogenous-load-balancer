package udplistener

import (
	"log"
	"net"
	"os"
	"strings"
	"lb/control-plane/registry"
	"bufio"
	"fmt"
	"time"
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

// getMACFromARP reads the Linux ARP table to find the MAC address for a given IP.
func getMACFromARP(targetIP net.IP) (net.HardwareAddr, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("failed to open ARP table: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip the first line (headers)
	scanner.Scan()

	targetIPString := targetIP.String()

	for scanner.Scan() {
		// Example line:
		// 192.168.1.100    0x1         0x2         aa:bb:cc:dd:ee:ff     * eth0
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			tableIP := fields[0]
			tableMAC := fields[3]

			if tableIP == targetIPString {
				macAddr, err := net.ParseMAC(tableMAC)
				if err != nil {
					return nil, fmt.Errorf("found MAC but failed to parse: %w", err)
				}
				return macAddr, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading ARP table: %w", err)
	}

	return nil, fmt.Errorf("MAC address not found in ARP cache")
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
		// This forces the Linux kernel to realize it doesn't know the MAC,
		// triggering an ARP Request
		ack := EncodeAck()
		if _, err := conn.WriteToUDP(ack, src); err != nil {
			log.Printf("[UDP_LISTENER] failed to send ACK to %s: %v", src.IP, err)
		}

		// Poll the ARP table while the kernel performs the ARP exchange
		var mac net.HardwareAddr
		for i := 0; i < 5; i++ {
			mac, err = getMACFromARP(src.IP)
			if err == nil {
				break // Found it!
			}
			time.Sleep(20 * time.Millisecond)
		}

		// Register if successful
		if err != nil {
			log.Printf("[UDP_LISTENER] ARP lookup failed for IP %s after retries: %v", src.IP.String(), err)
			return
		}
		
		reg.RegisterBackendEntry(registry.PoolUDP, src.IP, msg.Port, mac)
		log.Printf("[UDP_LISTENER] Registered UDP backend %s:%d (MAC: %s)", src.IP.String(), msg.Port, mac.String())
	case MsgHeartbeat:
		reg.HandleUDPHeartbeat(src.IP)

	default:
		log.Printf("[UDP_LISTENER] Unknown msg type 0x%02X from %s", msgType, src.IP)
	}
}
