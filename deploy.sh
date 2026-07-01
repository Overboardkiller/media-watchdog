#!/bin/bash
set -e
cd /mnt/user/appdata/media-watchdog

VERSION="latest"
PUSH=false

for arg in "$@"; do
  case $arg in
    --push) PUSH=true ;;
    *) VERSION="$arg" ;;
  esac
done

echo ">>> Stopping existing container..."
docker stop media-watchdog 2>/dev/null || true
docker rm media-watchdog 2>/dev/null || true

echo ">>> Building image..."
docker build -t media-watchdog .
docker tag media-watchdog overboardkiller/media-watchdog:${VERSION}
docker tag media-watchdog overboardkiller/media-watchdog:latest

echo ">>> Starting container..."
docker run -d \
  --name media-watchdog \
  --network bond0 \
  --ip 192.168.1.225 \
  -v /mnt/user/appdata/media-watchdog/data:/data \
  -v /mnt/user/appdata/EmbyServer:/emby-appdata:ro \
  -p 5000:5000 \
  --restart unless-stopped \
  media-watchdog

echo ">>> Container started at 192.168.1.225:5000"

# Push to Docker Hub if --push flag passed
if [[ "$PUSH" == "true" ]]; then
  echo ">>> Pushing to Docker Hub..."
  docker push overboardkiller/media-watchdog:${VERSION}
  docker push overboardkiller/media-watchdog:latest
  echo ">>> Pushed overboardkiller/media-watchdog:${VERSION}"
fi
