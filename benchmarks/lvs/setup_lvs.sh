#!/bin/bash
# setup_lvs.sh — configure IPVS NAT load balancing to remote EC2 backends.
#
# Usage: sudo ./setup_lvs.sh

set -euo pipefail

VIP="172.31.41.174"        # VIP clients hit
VPORT=5555
BACKENDS_PORT=50051

CLIENT_IFACE="enp39s0"     # client-facing interface
BACKEND_IFACE="enp40s0"    # backend-facing interface
SCHEDULER="lc"             # least-connection

BACKENDS=(
    172.31.32.252
    172.31.34.16
    172.31.34.3
    172.31.34.89
    172.31.35.172
    172.31.36.67
    172.31.39.79
    172.31.40.35
    172.31.40.99
    172.31.42.20
    172.31.43.7
    172.31.44.117
    172.31.44.2
    172.31.46.222
    172.31.46.231
    172.31.47.99
)

# Adjustments for IPVS NAT
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w "net.ipv4.conf.${CLIENT_IFACE}.rp_filter=0" >/dev/null
sysctl -w "net.ipv4.conf.${BACKEND_IFACE}.rp_filter=0" >/dev/null

# Put the VIP on the client-facing interface
if ! ip addr show dev "$CLIENT_IFACE" | grep -q "${VIP}/"; then
    ip addr add "${VIP}/32" dev "$CLIENT_IFACE"
fi

# Configure IPVS
ipvsadm -C
ipvsadm -A -t "${VIP}:${VPORT}" -s "$SCHEDULER"

for rip in "${BACKENDS[@]}"; do
    # -m = NAT/masquerade mode
    ipvsadm -a -t "${VIP}:${VPORT}" -r "${rip}:${BACKENDS_PORT}" -m
done

echo "IPVS configured (scheduler=$SCHEDULER, ${#BACKENDS[@]} backends, NAT mode):"
ipvsadm -L -n

echo ""
echo "Live connection stats:  watch -n1 'sudo ipvsadm -L -n --stats'"
echo "Test:                   curl http://${VIP}:${VPORT}/work"