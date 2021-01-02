#!/bin/sh

DOCKER_USER=aparcar

docker build -t "$DOCKER_USER/buildmaster" -f docker/Dockerfile.master .
docker push "$DOCKER_USER/buildmaster"

docker build -t "$DOCKER_USER/buildworker" -f docker/Dockerfile.worker .
docker push "$DOCKER_USER/buildworker"

docker build -t "$DOCKER_USER/rsync" -f docker/Dockerfile.rsync .
docker push "$DOCKER_USER/rsync"
