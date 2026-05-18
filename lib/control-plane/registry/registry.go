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
	mu                sync.RWMutex
	backends          map[string]*BackendEntry // keyed by IP str
	onRegister        []func(BackendEntry)     // callback for when a backend is registered
	onLoadScoreUpdate []func(BackendEntry)     // callback for when a backend's load score is updated
}

func CreateRegistry() *Registry {
	return &Registry{
		backends: make(map[string]*BackendEntry),
	}
}

// OnRegister installs a callback executed once for each new backend registration,
// for both TCP and UDP pools. The callback receives a copy of the BackendEntry.
// Callbacks are invoked without the registry lock held.
func (r *Registry) OnRegister(fn func(BackendEntry)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRegister = append(r.onRegister, fn)
}

// OnLoadScoreUpdate installs a callback fired every time a backend's
// load score changes. The callback receives a copy of the BackendEntry
// after the update. Hooks are invoked WITHOUT the registry lock held
func (r *Registry) OnLoadScoreUpdate(fn func(BackendEntry)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onLoadScoreUpdate = append(r.onLoadScoreUpdate, fn)
}

func (r *Registry) RegisterBackendEntry(pool Pool, ip net.IP, port uint16, mac net.HardwareAddr) {
	r.mu.Lock()

	key := ip.String()
	current_time := time.Now()
	if _, ok := r.backends[key]; ok {
		log.Printf("[REGISTRY] Device tried to register, but already exists: %s:%d (%s)", ip, port, pool)
		r.mu.Unlock()
		return
	}

	b := &BackendEntry{
		Pool:       pool,
		IP:         ip,
		Port:       port,
		LoadScore:  1,
		LastSeen:   current_time,
		Registered: current_time,
		Mac:        mac,
	}
	r.backends[key] = b
	log.Printf("[REGISTRY] Registered device: %s:%d (%s)", ip, port, pool)

	// Snapshot hooks and copy the entry while holding the lock
	hooks := make([]func(BackendEntry), len(r.onRegister))
	copy(hooks, r.onRegister)
	entryCopy := *b

	r.mu.Unlock()

	// Start hooks without the lock held
	for _, fn := range hooks {
		fn(entryCopy)
	}
}

// UpdateLoadScore sets the load score and refreshes LastSeen for the backend
// at the given IP. Returns false if the backend isn't registered.
func (r *Registry) UpdateLoadScore(ip net.IP, score uint32) bool {
	r.mu.Lock()

	b, ok := r.backends[ip.String()]
	if !ok {
		r.mu.Unlock()
		return false
	}

	b.LoadScore = score
	b.LastSeen = time.Now()

	// Snapshot for hooks
	hooks := make([]func(BackendEntry), len(r.onLoadScoreUpdate))
	copy(hooks, r.onLoadScoreUpdate)
	entryCopy := *b

	r.mu.Unlock()

	// Fire callbacks for updating the bpf map without holding the lock
	for _, fn := range hooks {
		fn(entryCopy)
	}

	return true
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
