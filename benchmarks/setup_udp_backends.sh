#!/bin/bash
# setup_backends.sh — launch one UDP agent per AWS secondary IP.
#
# AWS assigns multiple secondary private IPs to the instance's primary ENI.
# This script discovers them, writes them to a file, then launches one
# UDP agent bound to each, isolated by a per-process systemd cgroup scope
# with a CPU quota (mirroring Docker --cpus 0.3 / your local netns+quota setup).
#
# Usage: sudo ./setup_backends.sh
#   REGISTER=1 CP_ADDR=<LB_BACKEND_IP>:5555 sudo ./setup_backends.sh
#
# Each agent listens on the same PORT, but on its own IP. The LB registers
# 10 backends as (IP, PORT) pairs.

set -euo pipefail

# ─── Config ───────────────────────────────────────────────
IFACE="${IFACE:-enp39s0}"                # ENI carrying the secondary IPs
PORT="${PORT:-50051}"                    # UDP work port (same across all agents)
CPU_QUOTA="${CPU_QUOTA:-100%}"            # cgroup CPU cap per backend
PRIMARY_IP="${PRIMARY_IP:-}"             # optional: explicit primary IP to exclude
                                          # (auto-detected if empty)

# REGISTER selects which binary to use:
#   0 → udp_no_regist (standalone, for LVS UDP benchmarks)
#   1 → udp_register  (registers with control plane via UDP protocol, for your LB)
REGISTER="${REGISTER:-0}"
CP_ADDR="${CP_ADDR:-172.31.34.223:9999}"
PACKET_SIZE="${PACKET_SIZE:-1024}"          # Defaulting to 64 bytes for your high-PPS UDP tests

BIN_NO_REG="${BIN_NO_REG:-/home/ec2-user/heterogenous-load-balancer/benchmarks/udp_no_regist}"
BIN_REG="${BIN_REG:-/home/ec2-user/heterogenous-load-balancer/benchmarks/udp_register}"

LOG_DIR="${LOG_DIR:-/tmp/udp_agents}"
IP_LIST_FILE="${IP_LIST_FILE:-${LOG_DIR}/backend_ips.txt}"
PIDS_FILE="${PIDS_FILE:-${LOG_DIR}/pids.txt}"

mkdir -p "$LOG_DIR"
: > "$PIDS_FILE"
: > "$IP_LIST_FILE"

# ─── Pick the binary based on REGISTER ────────────────────
if [ "$REGISTER" = "1" ]; then
    BIN="$BIN_REG"
else
    BIN="$BIN_NO_REG"
fi

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary $BIN is missing or not executable" >&2
    exit 1
fi

# ─── Discover secondary IPs on the ENI ────────────────────
# Find the primary IP if not provided
if [ -z "$PRIMARY_IP" ]; then
    PRIMARY_IP=$(ip -4 -o addr show dev "$IFACE" \
        | awk '/dynamic/ {split($4,a,"/"); print a[1]; exit}')
fi

if [ -z "$PRIMARY_IP" ]; then
    echo "WARNING: could not auto-detect primary IP on $IFACE; all IPs treated as backends" >&2
fi

# Collect all IPv4 addresses on the ENI, skip the primary, write to file.
mapfile -t SECONDARY_IPS < <(
    ip -4 -o addr show dev "$IFACE" \
        | awk '{split($4,a,"/"); print a[1]}' \
        | grep -v "^${PRIMARY_IP}\$" || true
)

if [ "${#SECONDARY_IPS[@]}" -eq 0 ]; then
    echo "ERROR: no secondary IPs found on $IFACE" >&2
    echo "Did you assign secondary private IPs to the ENI in the AWS console?" >&2
    exit 1
fi

printf '%s\n' "${SECONDARY_IPS[@]}" > "$IP_LIST_FILE"
echo "Discovered ${#SECONDARY_IPS[@]} secondary IPs on $IFACE:"
cat "$IP_LIST_FILE" | sed 's/^/  /'
echo

# ─── Launch one cgroup-scoped agent per IP ────────────────
N=0
for ip in "${SECONDARY_IPS[@]}"; do
    N=$((N + 1))
    unit="udp-backend-${N}.scope"
    log="${LOG_DIR}/agent_${ip}.log"

    # Build the agent command
    if [ "$REGISTER" = "1" ]; then
        AGENT_CMD=("$BIN" --port "$PORT" --cp "$CP_ADDR" --bind "$ip" --packet-size "$PACKET_SIZE")
    else
        AGENT_CMD=("$BIN" --port "$PORT" --bind "$ip" --packet-size "$PACKET_SIZE")
    fi

    echo "[$N] launching UDP agent on ${ip}:${PORT}  (quota=${CPU_QUOTA}, unit=${unit})"
    systemd-run --scope --quiet \
        -p "CPUQuota=${CPU_QUOTA}" \
        -u "$unit" \
        "${AGENT_CMD[@]}" > "$log" 2>&1 &
    echo $! >> "$PIDS_FILE"
    sleep 0.2
done

echo
echo "Started $N UDP agents on port $PORT, one per IP, CPU-capped at ${CPU_QUOTA}."
echo "  IPs:       $IP_LIST_FILE"
echo "  Logs:      ${LOG_DIR}/agent_<ip>.log"
echo "  PIDs:      $PIDS_FILE"
echo
echo "Quick test:"
echo "  echo 'test' | nc -u ${SECONDARY_IPS[0]} ${PORT}"
