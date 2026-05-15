#!/usr/bin/env bash
set -euo pipefail

BR_NAME="br0"
BR_IP="172.16.0.1/24"

echo "Creating virtual bridge $BR_NAME..."

if ip link show "$BR_NAME" > /dev/null 2>&1; then
    echo "  bridge $BR_NAME already exists"
else
    sudo ip link add name "$BR_NAME" type bridge
    echo "  created bridge $BR_NAME"
fi

sudo ip link set dev "$BR_NAME" up

if ip addr show dev "$BR_NAME" | grep -q "172.16.0.1/24"; then
    echo "  IP already assigned"
else
    sudo ip addr add "$BR_IP" dev "$BR_NAME"
    echo "  assigned IP $BR_IP"
fi

sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

echo "$BR_NAME is up at $BR_IP"