sudo docker run -d \
  --name haproxy-benchmark \
  --net host \
  -v $(pwd)/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro \
  haproxy:latest
