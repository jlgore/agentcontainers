#!/usr/bin/env bash
# claude-agent entrypoint.
#
# HOME, CLAUDE_CONFIG_DIR, and TMPDIR all live under /workspace — the only
# writable mount under the enforcer's read-only rootfs. /workspace always exists
# as the workspace bind-mount point, so we create the subdirs here for a clean
# first run, then exec the requested command.
#
# Note: `agentcontainer run -d` overrides this entrypoint with `sleep infinity`
# to keep the container alive; in that mode this script does not run, so the
# launcher (or `agentcontainer exec`) must ensure TMPDIR exists before invoking
# claude — the native claude binary exits silently if TMPDIR is not writable.
set -euo pipefail

mkdir -p "${CLAUDE_CONFIG_DIR:-$HOME/.claude}" "${TMPDIR:-/workspace/.tmp}"

exec "$@"
