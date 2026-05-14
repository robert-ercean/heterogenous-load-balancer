package httplistener

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
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

		reg.RegisterBackendEntry(registry.PoolTCP, ip, req.Port)

		resp := RegisterResponse{Status: "registered"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// remoteIP extracts the IP from a "IP:port" RemoteAddr string.
func remoteIP(remoteAddr string) net.IP {
	host := remoteAddr
	if i := strings.LastIndex(remoteAddr, ":"); i >= 0 {
		host = remoteAddr[:i]
	}
	return net.ParseIP(host)
}
