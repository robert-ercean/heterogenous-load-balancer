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
		LoadScore:  1,
		LastSeen:   current_time,
		Registered: current_time,
	}
	r.backends[key] = b

	log.Printf("[REGISTRY] Registered device: %s:%d (%s)", ip, port, pool)
}

// UpdateLoadScore sets the load score and refreshes LastSeen for the backend
// at the given IP. Returns false if the backend isn't registered.
func (r *Registry) UpdateLoadScore(ip net.IP, score uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if b, ok := r.backends[ip.String()]; ok {
		b.LoadScore = score
		b.LastSeen = time.Now()
		return true
	}
	return false
}

// Removes a backend keyed by IPfrom the registry.
func (r *Registry) Remove(ip net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.backends, ip.String())
}

func (r *Registry) Listify() []BackendEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var entries []BackendEntry
	for _, b := range r.backends {
		entries = append(entries, *b)
	}
	return entries
}

// Updates the LastSeen timestamp for a UDP backend keyed by IP when a heartbeat is received.
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

// Called by the heartbeat pruner to remove UDP backends that haven't
// sent a heartbeat within the stale threshold (number owned by the pruner)
func (r *Registry) RemoveStaleUDPBackend(cutoff time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k, b := range r.backends {
		if b.LastSeen.Before(cutoff) && b.Pool == PoolUDP {
			delete(r.backends, k)
			log.Printf("[REGISTRY] Removed dead UDP backend %s:%d (last seen %s ago)",
				b.IP, b.Port, time.Since(b.LastSeen).Round(time.Second))
		}
	}
}
