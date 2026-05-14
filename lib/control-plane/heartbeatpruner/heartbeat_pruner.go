package heartbeatpruner

import (
	"log"
	"time"

	"lb/control-plane/registry"
)

const (
	loopIntervalSec   = 5 * time.Second
	staleThresholdSec = 15 * time.Second
)

type Pruner struct {
	reg *registry.Registry
}

func New(reg *registry.Registry) *Pruner {
	return &Pruner{reg: reg}
}

func (p *Pruner) Run() {
	log.Printf("[HEARTBEAT_PRUNER] starting, loopInterval=%.0fs staleThreshold=%.0fs", loopIntervalSec.Seconds(), staleThresholdSec.Seconds())

	ticker := time.NewTicker(loopIntervalSec)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-staleThresholdSec)
		p.reg.RemoveStaleUDPBackend(cutoff)
	}
}
