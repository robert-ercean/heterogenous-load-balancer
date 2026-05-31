#!/bin/bash

# Create the base config for NGINX Layer 4 TCP Load Balancing
cat <<EOF > nginx.conf
user  nginx;
worker_processes  auto;  # Use all available CPU cores

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;

events {
    worker_connections  100000; # Allow massive concurrency
    multi_accept on;
    use epoll;                  # use linux event loop
}

# Force NGINX into Layer 4 TCP mode
stream {
    upstream my_backends {
	# P2C with least conn load calculation
	random two least_conn;
EOF

N_BACKENDS=$1

# Append the backend IPs to the upstream block
for i in $(seq 10 $((10 + N_BACKENDS - 1))); do
    echo "        server 172.16.0.$i:50051;" >> nginx.conf
done

# Finish the config
cat <<EOF >> nginx.conf
    }

    server {
	listen 5555;
        proxy_pass my_backends;
        proxy_connect_timeout 5s;
    }
}
EOF

echo "nginx.conf generated successfully!"
