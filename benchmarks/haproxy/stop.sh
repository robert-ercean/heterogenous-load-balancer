#!/bin/bash

set -e

CONTAINER="haproxy"

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo "Stopping ${CONTAINER}..."
    sudo docker stop "${CONTAINER}"

    echo "Removing ${CONTAINER}..."
    sudo docker rm "${CONTAINER}"

    echo "HAProxy container stopped and removed."
else
    echo "Container ${CONTAINER} does not exist."
fi
