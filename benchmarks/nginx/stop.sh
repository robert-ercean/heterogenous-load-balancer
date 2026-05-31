#!/bin/bash

set -e

CONTAINER="nginx-benchmark"

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo "Stopping ${CONTAINER}..."
    sudo docker stop "${CONTAINER}"

    echo "Removing ${CONTAINER}..."
    sudo docker rm "${CONTAINER}"

    echo "Nginx container stopped and removed."
else
    echo "Container ${CONTAINER} does not exist."
fi