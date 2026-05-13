#!/bin/bash

set -e

echo "Removing virtual switch + backend Docker containers"

BR_NAME="br0"
DOCKER_NET="lb-backend"

CONTAINERS=(
  tcp-backend-1
  tcp-backend-2
  udp-backend-1
  udp-backend-2
)

echo "[1/4] Stopping and removing backend containers..."

for c in "${CONTAINERS[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
        echo "  Removing container: $c"
        docker rm -f "$c" > /dev/null
    else
        echo "  Container $c does not exist"
    fi
done

echo "[2/4] Removing Docker network..."

if docker network ls --format '{{.Name}}' | grep -q "^${DOCKER_NET}$"; then
    docker network rm "$DOCKER_NET" > /dev/null
    echo "  Removed Docker network: $DOCKER_NET"
else
    echo "  Docker network $DOCKER_NET does not exist"
fi

echo "[3/4] Removing bridge interface..."

if ip link show "$BR_NAME" > /dev/null 2>&1; then
    ip link set "$BR_NAME" down || true
    ip link delete "$BR_NAME" type bridge || true
    echo "  Removed bridge: $BR_NAME"
else
    echo "  Bridge $BR_NAME does not exist"
fi

echo ""
echo "=== Topology removed successfully ==="
echo ""