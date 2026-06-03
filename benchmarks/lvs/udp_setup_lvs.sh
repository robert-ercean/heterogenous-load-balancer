#!/bin/bash
# setup_lvs.sh — configure IPVS NAT load balancing to remote EC2 backends.
#
# Usage: sudo ./setup_lvs.sh

set -euo pipefail

VIP="172.31.42.58"        # VIP clients hit
VPORT=7777                # Updated for your UDP test
BACKENDS_PORT=50051

CLIENT_IFACE="ens5"     # client-facing interface
BACKEND_IFACE="ens6"    # backend-facing interface
SCHEDULER="lc"             # least-connection

BACKENDS=(
    172.31.32.7
    172.31.33.181
    172.31.33.27
    172.31.36.155
    172.31.36.35
    172.31.37.233
    172.31.39.178
    172.31.40.130
    172.31.43.150
    172.31.44.158
    172.31.33.156
    172.31.33.171
    172.31.35.104
    172.31.36.0
    172.31.36.5
    172.31.36.69
    172.31.37.131
    172.31.37.159
    172.31.37.43
    172.31.38.231
    172.31.38.58
    172.31.38.91
    172.31.39.157
    172.31.40.191
    172.31.41.38
    172.31.42.240
    172.31.43.48
    172.31.45.74
    172.31.46.164
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
# Notice the -u here for UDP
ipvsadm -A -u "${VIP}:${VPORT}" -s "$SCHEDULER"

for rip in "${BACKENDS[@]}"; do
    # -m = NAT/masquerade mode, and notice the -u here for UDP
    ipvsadm -a -u "${VIP}:${VPORT}" -r "${rip}:${BACKENDS_PORT}" -m
done

echo "IPVS configured (scheduler=$SCHEDULER, ${#BACKENDS[@]} backends, NAT mode):"
ipvsadm -L -n

echo ""
echo "Live connection stats:  watch -n1 'sudo ipvsadm -L -n --stats'"
echo "Test:                 echo 'test' | nc -u ${VIP} ${VPORT}"