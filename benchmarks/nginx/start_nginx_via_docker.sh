sudo docker run -d \
  --name nginx-benchmark \
  --net host \
  --ulimit nofile=100000:100000 \
  -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro \
  nginx:latest
