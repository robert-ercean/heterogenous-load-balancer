#!/bin/bash

set -e  # 

echo "Setting up virtual switch + backend Docker containers"

BR_NAME="br0"
BR_IP="172.16.0.1/24"
BR_IP_NO_MASK="172.16.0.1"


# Backend devices and their IPs
TCP_B1_IP="172.16.0.11"
TCP_B2_IP="172.16.0.12"
UDP_B1_IP="172.16.0.21"
UDP_B2_IP="172.16.0.22"

echo "[1/5] Creating virtual bridge $BR_NAME..."
ip link add name $BR_NAME type bridge 2> /dev/null || echo "Bridge $BR_NAME already exists"
ip link set $BR_NAME up 
ip addr add $BR_IP dev $BR_NAME
echo " Virtual interface br0 is up at $BR_IP"

echo "[2/5] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null

echo "[3/5] Creating Docker backend network..."
docker network create \
  --driver bridge \
  --subnet 172.16.0.0/24 \
  --gateway $BR_IP_NO_MASK \
  --opt com.docker.network.bridge.name=br0 \
  lb-backend 2> /dev/null || echo "Docker network lb-backend already created"

echo "Set up docker backend network on bridge $BR_NAME"

echo "[4/5] Creating TCP backends"

# We'll clean up any existing containers with the same names first to avoid conflicts
# Shouldn't be necessary if remove_existing_topology.sh is run before this, but just in case..
for existing_container in  tcp-backend-1 tcp-backend-2 udp-backend-1 udp-backend-2; do
    docker rm -f $existing_container 2> /dev/null || true
done

docker run -d \
  --name tcp-backend-1 \
  --network lb-backend \
  --ip $TCP_B1_IP \
  --cpus 1.0 \
  --memory 256m \
  alpine sleep infinity # keep the container running even if it isn't running any workload

docker run -d \
  --name tcp-backend-2 \
  --network lb-backend \
  --ip $TCP_B2_IP \
  --cpus 1.0 \
  --memory 256m \
  alpine sleep infinity

echo "[5/5] Creating UDP backends"
docker run -d \
  --name udp-backend-1 \
  --network lb-backend \
  --ip $UDP_B1_IP \
  --cpus 0.2 \
  --memory 64m \
  alpine sleep infinity

docker run -d \
  --name udp-backend-2 \
  --network lb-backend \
  --ip $UDP_B2_IP \
  --cpus 0.2 \
  --memory 64m \
  alpine sleep infinity

echo ""
echo "=== Topology ready ==="
echo ""
echo "  Bridge to LB (br0)  : 172.16.0.1"
echo "  TCP backend 1    : $TCP_B1_IP"
echo "  TCP backend 2    : $TCP_B2_IP"
echo "  UDP backend 1    : $UDP_B1_IP"
echo "  UDP backend 2    : $UDP_B2_IP"
echo ""