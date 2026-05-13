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

func CreateRegistry() *Registry {
	return &Registry{
		backends: make(map[string]*BackendEntry),
	}
}

func (r *Registry) RegisterBackendEntry(pool Pool, ip net.IP, port uint16) {
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
		LoadScore:  0, // initial load score, in the future the load will be a function parameter, received by the appropiate handler
		LastSeen:   current_time,
		Registered: current_time,
	}
	r.backends[key] = b

	log.Printf("[REGISTRY] Registered device: %s:%d (%s)", ip, port, pool)
}

func (r *Registry) HandleUDPHeartbeat(ip net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := ip.String()
	current_time := time.Now()

	if backendEntry, ok := r.backends[key]; ok && backendEntry.Pool == PoolUDP {
		backendEntry.LastSeen = current_time
		log.Printf("[REGISTRY] Received UDP heartbeat from: %s", ip)
		return
	}

	log.Printf("[REGISTRY] Received UDP heartbeat from unknown device, or the device is not registered as UDP: %s", ip)
}

func (r *Registry) RemoveDeadBackendEntries(staleThreshold time.Duration) []BackendEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-staleThreshold)
	var removed []BackendEntry
	for k, b := range r.backends {
		if b.LastSeen.Before(cutoff) {
			removed = append(removed, *b)
			delete(r.backends, k)
			log.Printf("[REGISTRY] Removed dead %s backend %s:%d (last seen %s ago)",
				b.Pool, b.IP, b.Port, time.Since(b.LastSeen).Round(time.Second))
		}
	}
	return removed
}

func (r *Registry) Stringify() []BackendEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var entries []BackendEntry
	for _, b := range r.backends {
		entries = append(entries, *b)
	}
	return entries
}
