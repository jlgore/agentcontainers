#!/usr/bin/env bash
# Bring up the forensic E2E under agentcontainers enforcement, the PROXY way.
#
# Unlike the legacy ~/e2e-up.sh standalone-gateway arrangement (where the agent
# talks to sift-gw directly on a host port and bypasses the proxy), this drives
# the gateway as a kernel-enforced container backend BEHIND the MCP proxy. Every
# forensic tool call then flows through policy evaluation, the approval broker,
# correlation IDs, and the proxy + enforcer audit chains — the property the
# project exists to provide.
#
# Evidence is mounted read-only (see agentcontainer.json); case outputs are
# writable. Reproducible from the repo: point CASE_DIR at a SIFT/Valhuntir case
# laid out as <case>/evidence/*.E01 plus the usual findings/timeline/audit dirs.
#
# Assumes scripts/bootstrap.sh has prepared the host (Docker, the agentcontainer
# CLI built from THIS source, the enforcer image, BPF LSM).
#
# Env: IMAGE=sift-gateway:e2e  PROXY_PORT=4510  CASE_DIR=/cases/e2e-demo
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

IMAGE="${IMAGE:-ghcr.io/jlgore/sift-gateway:e2e}"
PROXY_PORT="${PROXY_PORT:-4510}"
CASE_DIR="${CASE_DIR:-/cases/e2e-demo}"
RUN_DIR="$HERE/.run"

if [ -t 1 ]; then B='\033[1;34m'; G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; Z='\033[0m'
else B=''; G=''; Y=''; R=''; Z=''; fi
log()  { printf "${B}==>${Z} %s\n" "$*"; }
ok()   { printf "  ${G}OK${Z} %s\n" "$*"; }
warn() { printf "  ${Y}!!${Z} %s\n" "$*" >&2; }
die()  { printf "${R}xx %s${Z}\n" "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found — run scripts/bootstrap.sh first"
command -v agentcontainer >/dev/null 2>&1 || die "agentcontainer CLI not found — build from this source"
[ -d "$CASE_DIR/evidence" ] || die "no evidence dir at $CASE_DIR/evidence (set CASE_DIR)"

mkdir -p "$RUN_DIR"

# The checked-in config references /cases/e2e-demo. If CASE_DIR differs, render a
# copy with the case paths substituted so the run stays reproducible.
CFG="$HERE/agentcontainer.json"
if [ "$CASE_DIR" != "/cases/e2e-demo" ]; then
  CASE_NAME="$(basename "$CASE_DIR")"
  CFG="$RUN_DIR/agentcontainer.json"
  sed -e "s#/cases/e2e-demo#$CASE_DIR#g" -e "s#\"e2e-demo\"#\"$CASE_NAME\"#g" \
    "$HERE/agentcontainer.json" > "$CFG"
fi

# 1. Gateway image — pull the vendored image (a judge pulls, doesn't build).
log "Gateway image: $IMAGE"
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  ok "present"
elif docker pull "$IMAGE" >/dev/null 2>&1; then
  ok "pulled"
else
  die "image $IMAGE not present and pull failed — build via examples/sift-platform/build.sh"
fi

# 2. Agent under enforcement (the enforcer auto-starts; the proxy needs it for
#    the container backend).
log "Starting agent under enforcement"
( cd "$(dirname "$CFG")" && agentcontainer run -d 2>&1 | grep -avE 'lockfile not found' || true )

# 3. MCP proxy launches the gateway as an enforced container backend, mounts the
#    case (evidence read-only), and fronts the SIFT tools through audit/approval.
log "Starting MCP proxy on :$PROXY_PORT (launches the enforced gateway backend)"
if [ -f "$RUN_DIR/proxy.pid" ] && kill -0 "$(cat "$RUN_DIR/proxy.pid")" 2>/dev/null; then
  ok "proxy already running (pid $(cat "$RUN_DIR/proxy.pid"))"
else
  ( cd "$(dirname "$CFG")" && nohup agentcontainer mcp start --port "$PROXY_PORT" \
      > "$RUN_DIR/proxy.log" 2>&1 & echo $! > "$RUN_DIR/proxy.pid" )
  for _ in $(seq 1 60); do
    grep -aqE 'Backends:' "$RUN_DIR/proxy.log" && break
    kill -0 "$(cat "$RUN_DIR/proxy.pid")" 2>/dev/null || break
    sleep 1
  done
  grep -aqE 'Backends:' "$RUN_DIR/proxy.log" \
    && ok "$(grep -aE 'Backends:' "$RUN_DIR/proxy.log" | head -1)" \
    || { warn "proxy not confirmed; last log lines:"; tail -8 "$RUN_DIR/proxy.log" >&2; }
fi

cat <<EOT

${G}Forensic E2E is up under enforcement (proxy path).${Z}
  case:      $CASE_DIR  (evidence read-only, outputs writable)
  gateway:   kernel-enforced container backend, fronted by the proxy
  MCP proxy: http://localhost:${PROXY_PORT}/   (policy / approval / correlation / audit)

Verify the enforced path:
  # evidence is read-only inside the gateway
  agentcontainer exec sift-forensic-agent -- sh -c 'touch $CASE_DIR/evidence/x' 2>&1 | grep -i 'read-only' && echo OK:evidence-RO
  # tool calls are recorded with correlation IDs + a continuous audit chain
  agentcontainer audit verify
EOT
