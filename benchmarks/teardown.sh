#!/bin/bash
# teardown.sh — tear down netns backends and LVS config.
#
# Usage: sudo ./teardown.sh

set -uo pipefail

N=20
CLIENT_IFACE="enp7s0"

echo "Clearing IPVS..."
ipvsadm -C 2>/dev/null || true


echo "Stopping backend agent processes..."
# Stop the systemd transient scopes (CPU-capped cgroups)
for i in $(seq 0 $((N-1))); do
    systemctl stop "backend-be${i}.scope" 2>/dev/null || true
done
# Belt-and-suspenders: kill any tracked PIDs
if [ -f /tmp/agents/pids.txt ]; then
    kill $(cat /tmp/agents/pids.txt) 2>/dev/null || true
    rm -f /tmp/agents/pids.txt
fi

echo "Deleting namespaces and veths..."
for i in $(seq 0 $((N-1))); do
    ip netns del "be$i" 2>/dev/null || true
    ip link del "veth$i" 2>/dev/null || true   # peer auto-removed with ns; this clears strays
done

echo "Teardown complete."
