#!/bin/bash
# setup_backends.sh — launch one Go agent per AWS secondary IP.
#
# AWS assigns multiple secondary private IPs to the instance's primary ENI.
# This script discovers them, writes them to a file, then launches one
# Go agent bound to each, isolated by a per-process systemd cgroup scope
# with a CPU quota (mirroring Docker --cpus 0.3 / your local netns+quota setup).
#
# Usage: sudo ./setup_backends.sh
#   REGISTER=1 CP_ADDR=<LB_BACKEND_IP>:9998 sudo ./setup_backends.sh
#
# Each agent listens on the same PORT, but on its own IP. The LB registers
# 10 backends as (IP, PORT) pairs.

set -euo pipefail

# ─── Config ───────────────────────────────────────────────
IFACE="${IFACE:-enp39s0}"                # ENI carrying the secondary IPs
PORT="${PORT:-50051}"                    # work port (same across all agents)
CPU_QUOTA="${CPU_QUOTA:-100%}"            # cgroup CPU cap per backend
PRIMARY_IP="${PRIMARY_IP:-}"             # optional: explicit primary IP to exclude
                                          # (auto-detected if empty)

# REGISTER selects which binary to use:
#   0 → tcp_no_regist (standalone, for LVS / nginx / HAProxy benchmarks)
#   1 → tcp_register  (registers with control plane, for your LB)
REGISTER="${REGISTER:-0}"
CP_ADDR="${CP_ADDR:-172.31.32.187:9998}"
PACKET_SIZE="${PACKET_SIZE:-1024}"

BIN_NO_REG="${BIN_NO_REG:-/home/ec2-user/benchmarks/tcp_no_regist}"
BIN_REG="${BIN_REG:-/home/ec2-user/benchmarks/tcp_register}"

LOG_DIR="${LOG_DIR:-/tmp/agents}"
IP_LIST_FILE="${IP_LIST_FILE:-${LOG_DIR}/backend_ips.txt}"
PIDS_FILE="${PIDS_FILE:-${LOG_DIR}/pids.txt}"

mkdir -p "$LOG_DIR"
: > "$PIDS_FILE"
: > "$IP_LIST_FILE"

# ─── Pick the binary based on REGISTER ────────────────────
if [ "$REGISTER" = "1" ]; then
    BIN="$BIN_REG"
    if [ -z "$CP_ADDR" ]; then
        echo "ERROR: REGISTER=1 requires CP_ADDR=<host:port> (the LB's backend-facing IP+port)" >&2
        exit 1
    fi
else
    BIN="$BIN_NO_REG"
fi

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary $BIN is missing or not executable" >&2
    exit 1
fi

# ─── Discover secondary IPs on the ENI ────────────────────
# `ip -4 -o addr show dev <IFACE>` prints one IP per line. Each line includes
# the address as "172.31.X.Y/PREFIX". We want all of them EXCEPT the primary
# (the one with `metric 512` / `dynamic`, i.e. the DHCP-assigned IP).
#
# Detection rule: a line that includes "dynamic" or "metric 512" is the
# primary; everything else is a secondary IP we care about.

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
    unit="backend-${N}.scope"
    log="${LOG_DIR}/agent_${ip}.log"

    # Build the agent command
    if [ "$REGISTER" = "1" ]; then
        AGENT_CMD=("$BIN" --port "$PORT" --cp "$CP_ADDR" --bind "$ip" --packet-size "$PACKET_SIZE")
    else
        AGENT_CMD=("$BIN" --port "$PORT" --bind "$ip" --packet-size "$PACKET_SIZE")
    fi
    # NOTE: --bind is the flag the agent needs to listen on a SPECIFIC IP
    # rather than all interfaces. If your binary doesn't support it yet, add
    # it (see notes after the script).

    echo "[$N] launching agent on ${ip}:${PORT}  (quota=${CPU_QUOTA}, unit=${unit})"
    systemd-run --scope --quiet \
        -p "CPUQuota=${CPU_QUOTA}" \
        -u "$unit" \
        "${AGENT_CMD[@]}" > "$log" 2>&1 &
    echo $! >> "$PIDS_FILE"
done

echo
echo "Started $N agents on port $PORT, one per IP, CPU-capped at ${CPU_QUOTA}."
echo "  IPs:       $IP_LIST_FILE"
echo "  Logs:      ${LOG_DIR}/agent_<ip>.log"
echo "  PIDs:      $PIDS_FILE"
echo
echo "Quick test:"
echo "  curl http://${SECONDARY_IPS[0]}:${PORT}/work"
