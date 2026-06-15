#!/usr/bin/env bash
# Tear down the forensic E2E brought up by up.sh.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
RUN_DIR="$HERE/.run"

echo "==> Tearing down forensic E2E"

if [ -f "$RUN_DIR/proxy.pid" ]; then
  kill "$(cat "$RUN_DIR/proxy.pid")" 2>/dev/null && echo "  stopped MCP proxy" || true
fi
pkill -f 'agentcontainer mcp start' 2>/dev/null || true

agentcontainer stop sift-forensic-agent >/dev/null 2>&1 && echo "  stopped agent" || true

# The proxy removes its backend container on shutdown; sweep any orphans.
sleep 1
orphans="$(docker ps -aq --filter 'name=ac-mcp-sift-' 2>/dev/null)"
[ -n "$orphans" ] && docker rm -f $orphans >/dev/null 2>&1 && echo "  removed gateway backend container(s)" || true

agentcontainer enforcer stop --force >/dev/null 2>&1 && echo "  stopped enforcer" || true

# Release any ewfmount FUSE raw mount(s) established by up.sh (<case>/.ewfraw).
# The mount source reports as /dev/fuse, so match on the .ewfraw mountpoint.
for m in $(mount 2>/dev/null | awk '$3 ~ /\/\.ewfraw$/ {print $3}'); do
  fusermount -u "$m" 2>/dev/null && echo "  released ewfmount $m" || true
done

rm -rf "$RUN_DIR"
echo "Done."
