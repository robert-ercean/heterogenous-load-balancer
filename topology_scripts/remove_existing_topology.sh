#!/bin/bash

set -e

echo "Removing virtual switch + backend Docker containers"

BR_NAME="br0"
DOCKER_NET="lb-backends"


echo "[1/2] Stopping and removing backend containers..."

for i in $(seq 1 100); do
    docker rm -f "tcp-backend-$i" 2>/dev/null || true
done

echo "Dont forget to manually remove the UDP backends if they exist"

echo "[2/2] Removing Docker network..."

if docker network ls --format '{{.Name}}' | grep -q "^${DOCKER_NET}$"; then
    docker network rm "$DOCKER_NET" > /dev/null
    echo "  Removed Docker network: $DOCKER_NET"
else
    echo "  Docker network $DOCKER_NET does not exist"
fi

echo "WARNING: Removing bridge interface should be done separately in a different script"

echo ""
echo "=== Topology removed successfully ==="
echo ""