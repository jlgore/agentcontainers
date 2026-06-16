#!/usr/bin/env bash
# Tear down the forensic E2E brought up by up.sh.
#
# By default this stops only the runtime (proxy, agent, enforcer, ewfmount) and
# LEAVES evidence immutable — the `chattr +i` set by up.sh is a property of the
# evidence, not the demo, and must survive teardown. Pass --release-evidence to
# also clear the immutable bit (e.g. to delete or re-acquire a case). That drops
# the kernel-level evidence guarantee, so it is opt-in and never the default.
#
# Env: CASE_DIR=/cases/e2e-demo
set -uo pipefail

RELEASE_EVIDENCE=0
for arg in "$@"; do
  case "$arg" in
    --release-evidence) RELEASE_EVIDENCE=1 ;;
    *) echo "unknown flag: $arg (supported: --release-evidence)" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
RUN_DIR="$HERE/.run"
CASE_DIR="${CASE_DIR:-/cases/e2e-demo}"
CASES_DIR="$(dirname "$CASE_DIR")"

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

# Opt-in: clear the immutable bit up.sh set on evidence. Only with the explicit
# flag — this removes the kernel-level guarantee that the acquired evidence
# cannot be altered or deleted. Mirrors up.sh's evidence glob.
if [ "$RELEASE_EVIDENCE" = "1" ]; then
  echo "  !! --release-evidence: clearing chattr +i (evidence becomes mutable)" >&2
  shopt -s nullglob
  released=0
  # Unlock the evidence directory first (so its entries can be removed again),
  # then the files. Mirrors up.sh's lock set (files + dir).
  if [ -d "$CASE_DIR/evidence" ]; then
    sudo chattr -i "$CASE_DIR/evidence" 2>/dev/null && released=$((released + 1)) || echo "  could not chattr -i $CASE_DIR/evidence" >&2
  fi
  for f in "$CASE_DIR"/evidence/* "$CASES_DIR"/*.zip "$CASES_DIR"/*.E01 "$CASES_DIR"/*.dd "$CASES_DIR"/*.raw; do
    [ -f "$f" ] || continue
    if sudo chattr -i "$f" 2>/dev/null; then released=$((released + 1)); else echo "  could not chattr -i $f" >&2; fi
  done
  shopt -u nullglob
  echo "  released immutable bit on $released evidence path(s) (files + dir)"
fi

rm -rf "$RUN_DIR"
echo "Done."
