#!/usr/bin/env bash
# claude-agent entrypoint.
#
# HOME is /workspace (the only writable mount under the read-only rootfs), which
# always exists as the workspace bind-mount point, so Claude Code can create its
# config dir there. We ensure CLAUDE_CONFIG_DIR exists up front for a clean first
# run, then exec the requested command.
#
# Note: `agentcontainer run -d` overrides this entrypoint with `sleep infinity`
# to keep the container alive; in that mode this script does not run and Claude
# Code (started later via `agentcontainer exec`) creates the config dir itself.
set -euo pipefail

mkdir -p "${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

exec "$@"
