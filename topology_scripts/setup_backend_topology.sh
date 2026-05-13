#!/bin/bash
set -e

echo "Setting up virtual switch + backend Docker containers"

BR_NAME="br0"
BR_IP="172.16.0.1/24"
BR_IP_NO_MASK="172.16.0.1"

TCP_B1_IP="172.16.0.11"
TCP_B2_IP="172.16.0.12"
UDP_B1_IP="172.16.0.21"
UDP_B2_IP="172.16.0.22"

# Where the agent binaries live on the host
TCP_AGENT_BIN="/home/robert/Desktop/lb/backend_devices_scripts/tcp/tcp_register"
UDP_AGENT_BIN="/home/robert/Desktop/lb/backend_devices_scripts/udp/udp_register"

if [ ! -x "$TCP_AGENT_BIN" ]; then
    echo "ERROR: $TCP_AGENT_BIN not found or not executable"
    exit 1
fi
if [ ! -x "$UDP_AGENT_BIN" ]; then
    echo "ERROR: $UDP_AGENT_BIN not found or not executable"
    exit 1
fi

# Control plane addresses as seen from inside the containers
# (the bridge IP is the control plane's address since it runs on the host)
CP_HTTP_ADDR="${BR_IP_NO_MASK}:9998"
CP_UDP_ADDR="${BR_IP_NO_MASK}:9999"

# ─── Step 1: Bridge ────────────────────────────────────────────
echo "[1/5] Creating virtual bridge $BR_NAME..."
ip link add name $BR_NAME type bridge 2>/dev/null \
  || echo "      bridge already exists, skipping"
ip link set $BR_NAME up
ip addr add $BR_IP dev $BR_NAME 2>/dev/null \
  || echo "      IP already assigned, skipping"
echo "      br0 up at $BR_IP"

# ─── Step 2: IP forwarding ─────────────────────────────────────
echo "[2/5] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# ─── Step 3: Docker network ────────────────────────────────────
echo "[3/5] Creating Docker backend network..."
docker network create \
  --driver bridge \
  --subnet 172.16.0.0/24 \
  --gateway $BR_IP_NO_MASK \
  --opt com.docker.network.bridge.name=$BR_NAME \
  lb-backends 2>/dev/null \
  || echo "      docker network lb-backends already exists, skipping"

# Clean up any existing containers
for c in tcp-backend-1 tcp-backend-2 udp-backend-1 udp-backend-2; do
    docker rm -f $c 2>/dev/null || true
done

# ─── Step 4: TCP backends ──────────────────────────────────────
echo "[4/5] Creating TCP backends..."

docker run -d \
  --name tcp-backend-1 \
  --network lb-backends \
  --ip $TCP_B1_IP \
  --cpus 1.0 \
  --memory 256m \
  -v "$TCP_AGENT_BIN:/agent:ro" \
  alpine /agent --cp $CP_HTTP_ADDR --port 50051

docker run -d \
  --name tcp-backend-2 \
  --network lb-backends \
  --ip $TCP_B2_IP \
  --cpus 1.0 \
  --memory 256m \
  -v "$TCP_AGENT_BIN:/agent:ro" \
  alpine /agent --cp $CP_HTTP_ADDR --port 50051

# ─── Step 5: UDP backends ──────────────────────────────────────
echo "[5/5] Creating UDP backends..."

docker run -d \
  --name udp-backend-1 \
  --network lb-backends \
  --ip $UDP_B1_IP \
  --cpus 0.2 \
  --memory 256m \
  -v "$UDP_AGENT_BIN:/agent:ro" \
  alpine /agent --cp $CP_UDP_ADDR --port 9000

docker run -d \
  --name udp-backend-2 \
  --network lb-backends \
  --ip $UDP_B2_IP \
  --cpus 0.2 \
  --memory 256m \
  -v "$UDP_AGENT_BIN:/agent:ro" \
  alpine /agent --cp $CP_UDP_ADDR --port 9000

echo ""
echo "=== Topology ready ==="
echo "  Bridge (br0)    : $BR_IP_NO_MASK"
echo "  Control plane   : HTTP $CP_HTTP_ADDR, UDP $CP_UDP_ADDR"
echo "  TCP backend 1   : $TCP_B1_IP"
echo "  TCP backend 2   : $TCP_B2_IP"
echo "  UDP backend 1   : $UDP_B1_IP"
echo "  UDP backend 2   : $UDP_B2_IP"
echo ""
echo "  Check container logs to verify registration:"
echo "    docker logs tcp-backend-1"
echo "    docker logs udp-backend-1"