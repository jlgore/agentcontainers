#!/usr/bin/env bash
# Bring up the SIFT platform demo under agentcontainers enforcement.
#
# Idempotent. Builds the gateway image if missing, runs the agent under
# enforcement, and starts the MCP proxy. The proxy launches the sift-gateway
# itself as a kernel-enforced container backend (type: container + http) and
# fronts the 49 SIFT tools — no standalone gateway container to manage.
#
# Assumes scripts/bootstrap.sh has already prepared the host (Docker, the
# agentcontainer CLI, the enforcer image, BPF LSM).
#
# Env: IMAGE=sift-gateway:demo  PROXY_PORT=4510
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

IMAGE="${IMAGE:-ghcr.io/jlgore/sift-gateway:demo}"
PROXY_PORT="${PROXY_PORT:-4510}"
RUN_DIR="$HERE/.run"

if [ -t 1 ]; then B='\033[1;34m'; G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; Z='\033[0m'
else B=''; G=''; Y=''; R=''; Z=''; fi
log()  { printf "${B}==>${Z} %s\n" "$*"; }
ok()   { printf "  ${G}OK${Z} %s\n" "$*"; }
warn() { printf "  ${Y}!!${Z} %s\n" "$*" >&2; }
die()  { printf "${R}xx %s${Z}\n" "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found — run scripts/bootstrap.sh first"
command -v agentcontainer >/dev/null 2>&1 || die "agentcontainer CLI not found — run scripts/bootstrap.sh first"

mkdir -p "$RUN_DIR"

# 1. Gateway image — pull the vendored image (a judge pulls, doesn't build).
log "Gateway image: $IMAGE"
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  ok "present"
elif docker pull "$IMAGE" >/dev/null 2>&1; then
  ok "pulled"
else
  warn "pull failed — building locally (clones upstream; a few minutes)"
  IMAGE="$IMAGE" "$HERE/build.sh"
fi

# 2. Agent under enforcement (enforcer auto-starts — the proxy needs it for the
#    container backend).
log "Starting agent under enforcement"
agentcontainer run -d 2>&1 | grep -avE 'lockfile not found' || true

# 3. MCP proxy. It launches the sift-gateway as a kernel-enforced container
#    backend (type: container + http), registers its cgroup with the enforcer,
#    and fronts the 49 SIFT tools. First start pulls/boots the gateway, so allow
#    a longer settle than a remote backend.
#
# The proxy is a separate process and authenticates to the mTLS enforcer with
# the client creds the managed enforcer wrote to ~/.ac/enforcer-creds. Recent
# CLI versions discover that path automatically; export it explicitly too so the
# demo also works with a CLI that predates the auto-discovery, and so it's
# obvious where the creds come from.
ENFORCER_CREDS="${ENFORCER_CREDS:-$HOME/.ac/enforcer-creds}"
if [ -f "$ENFORCER_CREDS/client.crt" ]; then
  export AC_ENFORCER_ADDR="${AC_ENFORCER_ADDR:-127.0.0.1:50051}"
  export AC_ENFORCER_TLS_CA="$ENFORCER_CREDS/client-ca.crt"
  export AC_ENFORCER_TLS_CERT="$ENFORCER_CREDS/client.crt"
  export AC_ENFORCER_TLS_KEY="$ENFORCER_CREDS/client.key"
fi
log "Starting MCP proxy on :$PROXY_PORT (launches the gateway backend)"
if [ -f "$RUN_DIR/proxy.pid" ] && kill -0 "$(cat "$RUN_DIR/proxy.pid")" 2>/dev/null; then
  ok "proxy already running (pid $(cat "$RUN_DIR/proxy.pid"))"
else
  nohup agentcontainer mcp start --port "$PROXY_PORT" > "$RUN_DIR/proxy.log" 2>&1 &
  echo $! > "$RUN_DIR/proxy.pid"
  for _ in $(seq 1 30); do
    grep -aqE 'Backends:' "$RUN_DIR/proxy.log" && break
    kill -0 "$(cat "$RUN_DIR/proxy.pid")" 2>/dev/null || break
    sleep 1
  done
  if grep -aqE 'Backends:' "$RUN_DIR/proxy.log"; then
    ok "$(grep -aE 'Backends:' "$RUN_DIR/proxy.log" | head -1)"
  else
    warn "proxy not confirmed; last log lines:"; tail -5 "$RUN_DIR/proxy.log" >&2
  fi
fi

cat <<EOT

${G}SIFT platform is up under enforcement.${Z}
  gateway:   kernel-enforced container backend (ac-mcp-sift-*), 49 tools
  MCP proxy: http://localhost:${PROXY_PORT}/                (policy / approval / audit)
  agent:     agentcontainer ps   ·   agentcontainer exec sift-agent -- <cmd>
  enforcer:  agentcontainer enforcer status

Tear down with: ${HERE}/down.sh
EOT
