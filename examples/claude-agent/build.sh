#!/usr/bin/env bash
# Build the claude-agent image.
#
# The build context is the repository root (not this directory) so the first
# stage can compile the agentcontainer binary from source — that binary provides
# `agentcontainer guard hook`, the in-container side of the guard.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
tag="${1:-claude-agent:demo}"

echo "Building $tag (context: $repo_root)..."
exec docker build -f "$here/Dockerfile" -t "$tag" "$repo_root"
