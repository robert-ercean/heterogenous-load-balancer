package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"net"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Protocol types ──────────────────────────────────────────────

type RegisterRequest struct {
	Pool string `json:"pool"`
	Port uint16 `json:"port"`
}

type RegisterResponse struct {
	Status string `json:"status"`
}

type BackendMetrics struct {
	CPUPercent    float32 `json:"cpu_percent"`
	MemoryPercent float32 `json:"memory_percent"`
}

// ─── CPU sampling state ──────────────────────────────────────────

type cpuSample struct {
	usageUsec int64
	wallNanos int64
}

var (
	cpuMu         sync.Mutex
	lastCPUSample *cpuSample

	// quotaRatio represents the cgroup's CPU allocation as a fraction
	// of one core. 0.5 = CPUQuota=50%, 2.0 = CPUQuota=200%.
	// 0 means unlimited (no cgroup quota set).
	quotaRatio    float64
	quotaOnce     sync.Once
	packetSize    int
	ipStr string
)

// ─── Main ────────────────────────────────────────────────────────

func main() {
	cpAddr := flag.String("cp", "", "control plane HTTP address, e.g. 172.31.32.187:9998")
	// should default to 1024 for now
	packet_size := flag.Int("packet-size", 1024, "size of the payload in bytes")
	port := flag.Int("port", 50051, "port this backend serves work on")
	bindIP := flag.String("bind", "0.0.0.0", "IP address to bind work + metrics servers to")
	retryDelay := flag.Duration("retry", 3*time.Second, "delay between registration retries")
	maxRetries := flag.Int("max-retries", 0, "max retries (0 = forever)")
	flag.Parse()
	ipStr = *bindIP
	packetSize = *packet_size
	
	// skip for now while we're running non healthcheck benchmarks
	if *cpAddr == "" {
		log.Fatal("--cp flag is required")
	}
		
	// Take an initial CPU sample so the first /metrics call has a baseline to diff against.
	// Without this, the first poll would always return 0.
	lastCPUSample = takeCPUSample()
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed to get hostname: %v", err)
	}
	//Start metrics server in the background (bound to the configured IP, port 8080).
	metricsAddr := fmt.Sprintf("%s:8080", *bindIP)
	go startMetricsServer(metricsAddr)
	
	// Start the work server bound to the same IP.
	workAddr := fmt.Sprintf("%s:%d", *bindIP, *port)
	log.Printf("[tcp_agent] listening work on: %s:%d", ipStr, *port)
	go startWorkServer(workAddr)

	// Register with the control plane (retrying on failure).
	url := fmt.Sprintf("http://%s/register", *cpAddr)

	body, err := json.Marshal(RegisterRequest{
		Pool: "tcp",
		Port: uint16(*port),
	})
	if err != nil {
		log.Fatalf("failed to encode request: %v", err)
	}

	log.Printf("[tcp_agent %s] starting, bind=%s, will register at %s as port %d",
		hostname, *bindIP, url, *port)

	attempt := 0
	for {
		attempt++

		err := tryRegister(url, body, ipStr)
		if err == nil {
			log.Printf("[tcp_agent %s] registered successfully (attempt %d)", hostname, attempt)
			break
		}

		log.Printf("[tcp_agent %s] registration attempt %d failed: %v", hostname, attempt, err)

		if *maxRetries > 0 && attempt >= *maxRetries {
			log.Fatalf("[tcp_agent %s] gave up after %d attempts", hostname, attempt)
		}

		time.Sleep(*retryDelay)
	}

	// Stay alive — without this main() would return and kill the goroutines.
	log.Printf("[tcp_agent %s] registration complete, idling", hostname)

	select {}
}

// ─── Registration ────────────────────────────────────────────────

func tryRegister(url string, body []byte, bindIP string) error {
	// 1. Parse the string IP into a net.IP object
	localIP := net.ParseIP(bindIP)
	if localIP == nil {
		return fmt.Errorf("invalid bind IP: %s", bindIP)
	}

	transport := &http.Transport	{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			LocalAddr: &net.TCPAddr{IP: localIP},
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("HTTP error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var r RegisterResponse

	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if r.Status != "registered" {
		return fmt.Errorf("unexpected status field: %q", r.Status)
	}

	return nil
}

// ─── Work server ────────────────────────────────────────────────

func startWorkServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/work", workHandler)

	log.Printf("[tcp_agent] work server listening on %s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[tcp_agent] work server failed: %v", err)
	}
}

func workHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(packetSize))

	prefix := fmt.Sprintf("hello from %s || ", ipStr)
	payload := []byte(prefix + strings.Repeat("x", packetSize-len(prefix)))
	
	if _, err := w.Write(payload); err != nil {
		log.Printf("[tcp_agent] failed to write response: %v", err)
	}
}
// ─── Metrics server ──────────────────────────────────────────────

func startMetricsServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metricsHandler)

	log.Printf("[tcp_agent] metrics server listening on %s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[tcp_agent] metrics server failed: %v", err)
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	m := BackendMetrics{
		CPUPercent:    readCgroupCPU(),
		MemoryPercent: readCgroupMemory(),
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(m); err != nil {
		log.Printf("[tcp_agent] failed to encode metrics: %v", err)
	}
}

// ─── cgroup v2 readers ───────────────────────────────────────────

// readCgroupCPU returns this backend's CPU usage as a percentage of its
// allocated quota.
//
// A backend with CPUQuota=50% burning a full half-core returns 100.0,
// not 50.0 — because relative-to-quota is what the load-balancer's
// scoring should use to compare backends with different allocations.
//
// First call returns 0 if no baseline exists. Subsequent calls return
// the percentage over the interval since the previous call.
//
// Reads from /sys/fs/cgroup/cpu.stat which, under a systemd-run scope,
// resolves to the scope's own cgroup via cgroup-namespace remapping —
// no need to know the scope path explicitly.
func readCgroupCPU() float32 {
	quotaOnce.Do(initQuotaRatio)

	current := takeCPUSample()
	if current == nil {
		return 0
	}

	cpuMu.Lock()
	prev := lastCPUSample
	lastCPUSample = current
	cpuMu.Unlock()

	if prev == nil {
		return 0
	}

	deltaWallUsec := float64(current.wallNanos-prev.wallNanos) / 1000.0
	deltaCPUUsec := float64(current.usageUsec - prev.usageUsec)

	if deltaWallUsec <= 0 {
		return 0
	}

	// Raw fraction of wall-clock time spent on CPU. Can exceed 1.0 if the
	// cgroup is using more than one core (multi-core quota).
	rawFraction := deltaCPUUsec / deltaWallUsec

	// Normalize against the cgroup's quota so 1.0 = "saturating my budget".
	var fracOfQuota float64

	if quotaRatio > 0 {
		fracOfQuota = rawFraction / quotaRatio
	} else {
		// No quota set — normalize against the visible CPU count as a
		// reasonable fallback (so e.g. on a 4-core box, one core busy = 25%).
		fracOfQuota = rawFraction / float64(runtime.NumCPU())
	}

	if fracOfQuota < 0 {
		fracOfQuota = 0
	}
	if fracOfQuota > 1 {
		fracOfQuota = 1
	}

	return float32(fracOfQuota * 100.0)
}

// readCgroupMemory returns the cgroup's memory usage as a percentage of
// its memory limit. Returns 0 if no limit is set or files are unreadable.
func readCgroupMemory() float32 {
	current, err := os.ReadFile("/sys/fs/cgroup/memory.current")
	if err != nil {
		log.Printf("[tcp_agent] failed to read memory.current: %v", err)
		return 0
	}

	limit, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		log.Printf("[tcp_agent] failed to read memory.max: %v", err)
		return 0
	}

	cur, err := strconv.ParseInt(strings.TrimSpace(string(current)), 10, 64)
	if err != nil {
		return 0
	}

	limStr := strings.TrimSpace(string(limit))

	if limStr == "max" {
		// No limit set — can't compute a meaningful percentage.
		return 0
	}

	lim, err := strconv.ParseInt(limStr, 10, 64)
	if err != nil || lim == 0 {
		return 0
	}

	pct := float64(cur) * 100.0 / float64(lim)

	if pct > 100 {
		pct = 100
	}

	return float32(pct)
}

// takeCPUSample reads the current cumulative CPU usage from cgroup v2's
// cpu.stat. Returns nil on error.
func takeCPUSample() *cpuSample {
	data, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	if err != nil {
		log.Printf("[tcp_agent] failed to read cpu.stat: %v", err)
		return nil
	}

	var usageUsec int64 = -1

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "usage_usec ") {
			val := strings.TrimPrefix(line, "usage_usec ")

			parsed, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
			if err != nil {
				return nil
			}

			usageUsec = parsed
			break
		}
	}

	if usageUsec < 0 {
		return nil
	}

	return &cpuSample{
		usageUsec: usageUsec,
		wallNanos: time.Now().UnixNano(),
	}
}

// initQuotaRatio reads /sys/fs/cgroup/cpu.max once at startup.
// The cgroup quota doesn't change at runtime, so caching is safe.
//
// cpu.max format: "<quota_usec> <period_usec>" or "max <period_usec>".
// quotaRatio = quota / period (e.g. 30000/100000 = 0.30 for CPUQuota=30%).
func initQuotaRatio() {
	data, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		log.Printf("[tcp_agent] failed to read cpu.max: %v (no quota)", err)
		return
	}

	fields := strings.Fields(strings.TrimSpace(string(data)))

	if len(fields) != 2 {
		log.Printf("[tcp_agent] unexpected cpu.max format: %q", string(data))
		return
	}

	if fields[0] == "max" {
		log.Printf("[tcp_agent] no CPU quota set")
		return
	}

	quota, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return
	}

	period, err := strconv.ParseFloat(fields[1], 64)
	if err != nil || period == 0 {
		return
	}

	quotaRatio = quota / period

	log.Printf("[tcp_agent] CPU quota ratio: %.3f", quotaRatio)
}