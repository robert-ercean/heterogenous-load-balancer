#!/bin/bash
# setup_lvs.sh — configure IPVS NAT load balancing across the backends.
#
# Usage: sudo ./setup_lvs.sh

set -euo pipefail

#  Config (must match the backend setup) 
VIP="192.168.1.100"        # VIP clients hit (same one your LB uses, for consistency)
VPORT=5555
BACKEND_PORT=50051
N=20    # should change to be passed via args
IP_BASE_OCTET=11
SUBNET="172.16.0"
CLIENT_IFACE="enp7s0"      # client-facing interface to host the VIP
SCHEDULER="lc"             # least-connection (closest to P2C)

#  Kernel knobs required for IPVS NAT on one host 
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w "net.ipv4.conf.${CLIENT_IFACE}.rp_filter=0" >/dev/null
sysctl -w net.ipv4.conf.br0.rp_filter=0 >/dev/null

#  Put the VIP on the client-facing interface 
if ! ip addr show dev "$CLIENT_IFACE" | grep -q "${VIP}/"; then
    ip addr add "${VIP}/32" dev "$CLIENT_IFACE"
fi

#  Configure IPVS 
ipvsadm -C   # clear any existing config
ipvsadm -A -t "${VIP}:${VPORT}" -s "$SCHEDULER"

for i in $(seq 0 $((N-1))); do
    rip="${SUBNET}.$((IP_BASE_OCTET + i))"
    # -m = NAT (masq) mode: IPVS rewrites dst on the way in, src on the way out
    ipvsadm -a -t "${VIP}:${VPORT}" -r "${rip}:${BACKEND_PORT}" -m
done

echo "IPVS configured (scheduler=$SCHEDULER, $N backends, NAT mode):"
ipvsadm -L -n

echo ""
echo "Live connection stats:  watch -n1 'sudo ipvsadm -L -n --stats'"
echo "Test:                   curl http://${VIP}:${VPORT}/work"
