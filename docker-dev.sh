#!/usr/bin/env bash
#
# Launch EvilPikin inside an isolated Docker container on the operator's Mac.
# - Source is mounted from the host, so you keep editing on macOS as normal.
# - Ports are published ONLY on 127.0.0.1 (never 0.0.0.0) to preserve the
#   "dev mode stays on loopback" opsec rule.
# - The container runs as your host UID so .sandbox/ artifacts are owned by you,
#   not root.
#
# Usage:  ./docker-dev.sh [extra evilpikin flags...]
# e.g.    ./docker-dev.sh -domain ms.test
#
set -euo pipefail

IMAGE=evilpikin-dev
HOST_PORT_HTTP=9080
HOST_PORT_HTTPS=9443
HOST_PORT_API=8080

# Ensure the sandbox dir exists on the host so the mount is clean.
mkdir -p ".sandbox/certs"

# Build the image once (cached afterwards).
docker build -f Dockerfile.dev -t "$IMAGE" .

# Run with source mounted, loopback-only published ports.
exec docker run --rm -it \
  -v "$PWD":/app \
  -e HOME=/app \
  -e GOPATH=/app/.gopath \
  -e GOCACHE=/app/.gopath/cache \
  --user "$(id -u):$(id -g)" \
  -p "127.0.0.1:${HOST_PORT_HTTP}:${HOST_PORT_HTTP}" \
  -p "127.0.0.1:${HOST_PORT_HTTPS}:${HOST_PORT_HTTPS}" \
  -p "127.0.0.1:${HOST_PORT_API}:${HOST_PORT_API}" \
  -w /app \
  "$IMAGE" \
  -mode local \
  -http "127.0.0.1:${HOST_PORT_HTTP}" \
  -https "127.0.0.1:${HOST_PORT_HTTPS}" \
  -api-addr "127.0.0.1:${HOST_PORT_API}" \
  -domain ms.test \
  "$@"
