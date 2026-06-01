sudo docker run -d \
  --name haproxy \
  -p 5555:5555 \
  -v "$PWD/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
  haproxy:latest