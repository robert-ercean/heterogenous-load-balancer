package registry

import (
	"log"
	"net"
	"sync"
	"time"
)

// Registry is the central in-memory store of registered backends.
// Both the TCP & UDP listeners will write to this registry, so it must be thread-safe,
// therefore we use a mutex
type Registry struct {
	mu       sync.RWMutex
	backends map[string]*BackendEntry // keyed by IP str
}

func create_registry() *Registry {
	return &Registry{
		backends: make(map[string]*BackendEntry),
	}
}

func (r *Registry) registerBackendEntry(pool Pool, ip net.IP, port uint16, mac net.HardwareAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := ip.String()
	current_time := time.Now()

	if _, ok := r.backends[key]; ok {
		log.Printf("REGISTRY] Device tried to register, but already exists: %s:%d (%s)", ip, port, pool)
		return
	}

	b := &BackendEntry{
		Pool:       pool,
		IP:         ip,
		Port:       port,
		MAC:        mac,
		LoadScore:  0, // initial load score, in the future the load will be a function parameter, received by the appropiate handler
		LastSeen:   current_time,
		Registered: current_time,
	}
	r.backends[key] = b

	log.Printf("[REGISTRY] Registered device: %s:%d (%s)", ip, port, pool)
}

func (r *Registry) receivedHeartbeat(ip net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := ip.String()
	current_time := time.Now()

	if backendEntry, ok := r.backends[key]; ok {
		backendEntry.LastSeen = current_time
		log.Printf("[REGISTRY] Received heartbeat from: %s", ip)
		return
	}

	log.Printf("[REGISTRY] Received heartbeat from unknown device: %s", ip)
}

func (r *Registry) removeDeadBackendEntries(maxAge time.Duration) []BackendEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	var removed []BackendEntry
	for k, b := range r.backends {
		if b.LastSeen.Before(cutoff) {
			removed = append(removed, *b)
			delete(r.backends, k)
			log.Printf("[REGISTRY] Removed dead backend %s:%d (last seen %s ago)",
				b.IP, b.Port, time.Since(b.LastSeen).Round(time.Second))
		}
	}
	return removed
}
