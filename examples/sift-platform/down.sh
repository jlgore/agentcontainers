#!/usr/bin/env bash
# Tear down the SIFT platform demo brought up by up.sh.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
RUN_DIR="$HERE/.run"

echo "==> Tearing down SIFT demo"

if [ -f "$RUN_DIR/proxy.pid" ]; then
  kill "$(cat "$RUN_DIR/proxy.pid")" 2>/dev/null && echo "  stopped MCP proxy" || true
fi
pkill -f 'agentcontainer mcp start' 2>/dev/null || true

agentcontainer stop sift-agent >/dev/null 2>&1 && echo "  stopped agent" || true

# The proxy removes its backend container on shutdown; give it a moment, then
# sweep any orphans (proxy killed -9 / crashed) plus a legacy standalone gateway.
sleep 1
orphans="$(docker ps -aq --filter 'name=ac-mcp-sift-' 2>/dev/null)"
[ -n "$orphans" ] && docker rm -f $orphans >/dev/null 2>&1 && echo "  removed gateway backend container(s)" || true
if docker inspect sift-gateway >/dev/null 2>&1; then
  docker rm -f sift-gateway >/dev/null 2>&1 && echo "  removed legacy gateway" || true
fi

agentcontainer enforcer stop --force >/dev/null 2>&1 && echo "  stopped enforcer" || true

rm -rf "$RUN_DIR"
echo "Done."
