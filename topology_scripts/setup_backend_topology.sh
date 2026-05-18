#!/bin/bash
set -e

echo "Setting up virtual switch + backend Docker containers"

BR_NAME="br0"
BR_IP="172.16.0.1/24"
BR_IP_NO_MASK="172.16.0.1"

TCP_IPS=(
  "172.16.0.10"
  "172.16.0.11"
  "172.16.0.12"
  "172.16.0.13"
  "172.16.0.14"
  "172.16.0.15"
  "172.16.0.16"
  "172.16.0.17"
  "172.16.0.18"
  "172.16.0.19"
)

: '
UDP_IPS=(
  "172.16.0.21"
  "172.16.0.22"
  "172.16.0.23"
  "172.16.0.24"
  "172.16.0.25"
  "172.16.0.26"
  "172.16.0.27"
  "172.16.0.28"
  "172.16.0.29"
  "172.16.0.30"
)

'
TCP_WORKLOADS=(
  "idle"
  "idle"
  "idle"
  "idle"
  "idle"
  "idle"
  "idle"
  "idle"
  "idle"
  "idle"
)

# Where the agent binaries live on the host
TCP_AGENT_BIN="/home/robert/Desktop/lb/backend_devices_scripts/tcp/register/tcp_register"
UDP_AGENT_BIN="/home/robert/Desktop/lb/backend_devices_scripts/udp/udp_register"
TCP_CPU_WORK_BIN="/home/robert/Desktop/lb/backend_devices_scripts/tcp/cpu_work/tcp_cpu_work"
TCP_MEM_WORK_BIN="/home/robert/Desktop/lb/backend_devices_scripts/tcp/mem_work/tcp_mem_work"


if [ ! -x "$TCP_AGENT_BIN" ]; then
    echo "ERROR: $TCP_AGENT_BIN not found or not executable"
    exit 1
fi
if [ ! -x "$UDP_AGENT_BIN" ]; then
    echo "ERROR: $UDP_AGENT_BIN not found or not executable"
    exit 1
fi
if [ ! -x "$TCP_CPU_WORK_BIN" ]; then
    echo "ERROR: $TCP_CPU_WORK_BIN not found or not executable"
    exit 1
fi

# Control plane addresses as seen from inside the containers
# (the bridge IP is the control plane's address since it runs on the host)
CP_HTTP_ADDR="${BR_IP_NO_MASK}:9998"
CP_UDP_ADDR="${BR_IP_NO_MASK}:9999"

# ─── Step 1: Bridge ────────────────────────────────────────────
# check if interface already exists before trying to create it, to avoid exiting
if ip link show "$BR_NAME" > /dev/null 2>&1; then
    echo "  Bridge $BR_NAME already exists, skipping creation"
else
    echo "  Creating bridge: $BR_NAME"
    echo "[1/5] Creating virtual bridge $BR_NAME..."
    ip link add name $BR_NAME type bridge 2>/dev/null \
      || echo "      bridge already exists, skipping"
    ip link set $BR_NAME up
    ip addr add $BR_IP dev $BR_NAME 2>/dev/null \
      || echo "      IP already assigned, skipping"
    echo "      br0 up at $BR_IP"
fi

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
for i in $(seq 1 10); do
    docker rm -f "tcp-backend-$i" 2>/dev/null || true
    docker rm -f "udp-backend-$i" 2>/dev/null || true
done

# ─── Step 4: TCP backends ──────────────────────────────────────
echo "[4/5] Creating TCP backends..."


for i in "${!TCP_IPS[@]}"; do
  n=$((i + 1))
  ip="${TCP_IPS[$i]}"
  workload="${TCP_WORKLOADS[$i]}"

  case "$workload" in
    cpu)
      WORKER_CMD="/cpu_work --workers 1 --busy-percent 10 --period-ms 100"
      ;;
    idle)
      WORKER_CMD="tail -f /dev/null"
      ;;
    mem)
      WORKER_CMD="/mem_work --mb 160 --touch-interval-ms 1000"
      ;;
    *)
      echo "ERROR: unknown TCP workload: $workload"
      exit 1
      ;;
  esac

  echo "      tcp-backend-$n ip=$ip workload=$workload"

  docker run -d \
    --name "tcp-backend-$n" \
    --hostname "tcp-backend-$n" \
    --network lb-backends \
    --ip "$ip" \
    --cpus "0.6" \
    --memory "256m" \
    --memory-swap "256m" \
    -v "$TCP_AGENT_BIN:/agent:ro" \
    -v "$TCP_CPU_WORK_BIN:/cpu_work:ro" \
    -v "$TCP_MEM_WORK_BIN:/mem_work:ro" \
    alpine sh -c "/agent --cp '$CP_HTTP_ADDR' --port 50051 & exec $WORKER_CMD"
done

# ─── Step 5: UDP backends ──────────────────────────────────────
echo "[5/5] Creating UDP backends..."

for i in "${!UDP_IPS[@]}"; do
  n=$((i + 1))

  docker run -d \
    --name "udp-backend-$n" \
    --network lb-backends \
    --ip "${UDP_IPS[$i]}" \
    --cpus 0.1 \
    --memory 32m \
    -v "$UDP_AGENT_BIN:/agent:ro" \
    alpine /agent --cp "$CP_UDP_ADDR" --port 9000
done

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