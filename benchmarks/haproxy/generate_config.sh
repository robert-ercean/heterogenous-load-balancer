#!/bin/bash

# Set up HAProxy as a load balancer for a number of backend severs
cat <<EOF > haproxy.cfg
global
    maxconn 100000
    nbthread 4           # CPU cores used by haproxy

defaults
    mode tcp             # Use TCP mode
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend my_frontend
    bind *:5555          # The port hit by clients
    default_backend my_backends

backend my_backends
    balance random(2)  # P2C load balancing
EOF


# We're gonna use variables passed via args number of backends
SUBNET="172.16.0"
N="$2"
for i in $(seq 10 $((10 + N - 1))); do
    echo "    server backend_$i $SUBNET.$i:50051 check" >> haproxy.cfg
done

echo "haproxy.cfg generated successfully!"
