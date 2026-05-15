#!/bin/bash

set -e

echo "Removing virtual switch + backend Docker containers"

BR_NAME="br0"
DOCKER_NET="lb-backends"

CONTAINERS=(
  tcp-backend-1
  tcp-backend-2
  tcp-backend-3
  tcp-backend-4
  tcp-backend-5
  tcp-backend-6
  tcp-backend-7
  tcp-backend-8
  tcp-backend-9
  tcp-backend-10
  
  udp-backend-1
  udp-backend-2
  udp-backend-3
  udp-backend-4
  udp-backend-5
  udp-backend-6
  udp-backend-7
  udp-backend-8
  udp-backend-9
  udp-backend-10
)

echo "[1/2] Stopping and removing backend containers..."

for c in "${CONTAINERS[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
        echo "  Removing container: $c"
        docker rm -f "$c" > /dev/null
    else
        echo "  Container $c does not exist"
    fi
done

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