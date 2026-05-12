package registry

import (
	"net"
	"time"
)

type Pool int

const (
	PoolTCP Pool = iota
	PoolUDP
)

func (p Pool) String() string {
	switch p {
	case PoolTCP:
		return "tcp"
	case PoolUDP:
		return "udp"
	default:
		return "unknown"
	}
}

type BackendEntry struct {
	Pool       Pool
	IP         net.IP
	Port       uint16
	MAC        net.HardwareAddr
	LoadScore  uint32    // normalized load, updated by health checks
	LastSeen   time.Time // timestamp of last heartbeat
	Registered time.Time // timestamp of registration
}
