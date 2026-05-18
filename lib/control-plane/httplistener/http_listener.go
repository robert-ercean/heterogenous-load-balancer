package httplistener

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"lb/control-plane/registry"
)

type RegisterRequest struct {
	Pool string `json:"pool"`
	Port uint16 `json:"port"`
}

type RegisterResponse struct {
	Status string `json:"status"`
}

func Start(addr string, reg *registry.Registry) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", makeRegisterHandler(reg))

	log.Printf("[HTTP_LISTENER] listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func makeRegisterHandler(reg *registry.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if req.Pool != "tcp" {
			http.Error(w, "HTTP registration is for TCP pool only", http.StatusBadRequest)
			return
		}

		ip := remoteIP(r.RemoteAddr)
		if ip == nil {
			http.Error(w, "could not determine source IP", http.StatusInternalServerError)
			return
		}
		// get the mac associated with the ip by interrogating th arp table
		mac, err := getMACFromARP(ip)
		if err != nil {
			log.Printf("[HTTP_LISTENER] ARP lookup failed for IP %s: %v", ip.String(), err)
			http.Error(w, "could not determine MAC address from ARP cache", http.StatusInternalServerError)
			return
		}

		reg.RegisterBackendEntry(registry.PoolTCP, ip, req.Port, mac)

		resp := RegisterResponse{Status: "registered"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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

// remoteIP extracts the IP from a "IP:port" RemoteAddr string.
func remoteIP(remoteAddr string) net.IP {
	host := remoteAddr
	if i := strings.LastIndex(remoteAddr, ":"); i >= 0 {
		host = remoteAddr[:i]
	}
	return net.ParseIP(host)
}
