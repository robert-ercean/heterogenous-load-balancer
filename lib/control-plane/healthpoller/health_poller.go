package healthpoller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"lb/control-plane/registry"
)

const (
	PollIntervalSec     = 5
	PollTimeoutSec      = 2
	MaxConsecutiveFails = 3
)

// BackendMetrics is what each TCP backend exposes at /metrics
type BackendMetrics struct {
	CPUPercent    float32 `json:"cpu_percent"`
	MemoryPercent float32 `json:"memory_percent"`
}

type Poller struct {
	reg        *registry.Registry
	client     *http.Client
	failsMu    sync.Mutex
	failCounts map[string]int // ip string → consecutive failure count
}

func New(reg *registry.Registry) *Poller {
	return &Poller{
		reg: reg,
		client: &http.Client{
			Timeout: PollTimeoutSec * time.Second,
		},
		failCounts: make(map[string]int),
	}
}

// Run blocks until ctx is canceled, polling all TCP backends on a fixed interval.
func (p *Poller) Run(ctx context.Context) {
	log.Printf("[HEALTH_POLLER] starting, interval=%ds timeout=%ds", PollIntervalSec, PollTimeoutSec)

	ticker := time.NewTicker(PollIntervalSec * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[HEALTH_POLLER] shutting down")
			return
		case <-ticker.C:
			p.pollAll()
		}
	}
}

func (p *Poller) pollAll() {
	backends := p.reg.Listify()

	// Poll each TCP backend in parallel — N goroutines, bounded by N backends
	var wg sync.WaitGroup
	for _, b := range backends {
		if b.Pool != registry.PoolTCP {
			continue
		}
		wg.Add(1)
		go func(b registry.BackendEntry) {
			defer wg.Done()
			p.pollOne(b)
		}(b)
	}
	wg.Wait()
}

func (p *Poller) pollOne(b registry.BackendEntry) {
	metricsPort := 8080
	url := fmt.Sprintf("http://%s:%d/metrics", b.IP, metricsPort)

	metrics, err := p.fetchMetrics(url)
	if err != nil {
		p.recordFailure(b.IP, err)
		return
	}

	score := computeLoadScore(metrics)
	if !p.reg.UpdateLoadScore(b.IP, score) {
		log.Printf("[HEALTH_POLLER] backend %s not in registry, ignoring metrics", b.IP)
		return
	}

	p.recordSuccess(b.IP)
}

func (p *Poller) fetchMetrics(url string) (BackendMetrics, error) {
	var m BackendMetrics

	resp, err := p.client.Get(url)
	if err != nil {
		return m, fmt.Errorf("GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return m, fmt.Errorf("status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return m, fmt.Errorf("decode: %w", err)
	}

	return m, nil
}

func (p *Poller) recordFailure(ip net.IP, err error) {
	p.failsMu.Lock()
	defer p.failsMu.Unlock()

	key := ip.String()
	p.failCounts[key]++
	count := p.failCounts[key]

	log.Printf("[HEALTH_POLLER] poll failed for %s (consecutive=%d): %v", ip, count, err)

	if count >= MaxConsecutiveFails {
		log.Printf("[HEALTH_POLLER] removing %s after %d consecutive failures", ip, count)
		p.reg.Remove(ip)
		delete(p.failCounts, key)
	}
}

func (p *Poller) recordSuccess(ip net.IP) {
	p.failsMu.Lock()
	defer p.failsMu.Unlock()

	if p.failCounts[ip.String()] > 0 {
		log.Printf("[HEALTH_POLLER] %s recovered after failures", ip)
	}
	delete(p.failCounts, ip.String())
}

// computeLoadScore normalizes metrics into a unified 0-255 load score.
func computeLoadScore(m BackendMetrics) uint32 {
	cpuComponent := uint32(m.CPUPercent * 2.55)
	memComponent := uint32(m.MemoryPercent * 2.55)

	score := (cpuComponent*60 + memComponent*20) / 100
	if score > 255 {
		score = 255
	}
	return score
}
