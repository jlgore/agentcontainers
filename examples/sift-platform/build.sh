#!/usr/bin/env bash
# Build the sift-gateway demo image from mainline AppliedIR/sift-mcp.
#
# Clones the upstream monorepo (no fork), drops in the Dockerfile + gateway
# config + entrypoint from this directory, and builds. The image hosts the
# whole SIFT platform behind one HTTP MCP endpoint on :4508.
#
# Usage:  ./build.sh
# Env:    IMAGE=sift-gateway:demo   SIFT_REF=main   VHIR_REF=main
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-sift-gateway:demo}"
SIFT_REF="${SIFT_REF:-main}"
VHIR_REF="${VHIR_REF:-main}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Cloning AppliedIR/sift-mcp@${SIFT_REF}"
git clone --depth 1 --branch "$SIFT_REF" \
  https://github.com/AppliedIR/sift-mcp.git "$WORK/sift-mcp"

cp "$HERE/Dockerfile" "$HERE/gateway.docker.yaml" "$HERE/entrypoint.sh" \
  "$WORK/sift-mcp/"

echo "==> Building $IMAGE (vhir ref: $VHIR_REF)"
docker build --build-arg "VHIR_REF=$VHIR_REF" -t "$IMAGE" "$WORK/sift-mcp"

echo "==> Built $IMAGE"
docker image inspect "$IMAGE" --format '    size: {{.Size}} bytes, id: {{.Id}}'
