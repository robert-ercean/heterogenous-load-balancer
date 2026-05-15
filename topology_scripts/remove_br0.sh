#!/bin/bash

BR_NAME="br0"
BR_IP="172.16.0.1/24"

if ip link show "$BR_NAME" > /dev/null 2>&1; then
    ip link set "$BR_NAME" down || true
    ip link delete "$BR_NAME" type bridge || true
    echo "  Removed bridge: $BR_NAME"
else
    echo "  Bridge $BR_NAME does not exist"
fi
