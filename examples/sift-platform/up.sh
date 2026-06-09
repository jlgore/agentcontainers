#!/usr/bin/env bash
# Bring up the SIFT platform demo under agentcontainers enforcement.
#
# Idempotent. Builds the gateway image if missing, resolves the agent base
# image's amd64 manifest digest (so org-policy extraction doesn't 404 on the
# multi-arch tag), starts the hardened gateway, runs the agent under
# enforcement, and starts the MCP proxy fronting the 49 SIFT tools.
#
# Assumes scripts/bootstrap.sh has already prepared the host (Docker, the
# agentcontainer CLI, the enforcer image, BPF LSM).
#
# Env: IMAGE=sift-gateway:demo  GATEWAY_PORT=4508  PROXY_PORT=4510
#      BASE_IMAGE=mcr.microsoft.com/devcontainers/base:ubuntu
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

IMAGE="${IMAGE:-sift-gateway:demo}"
GATEWAY_PORT="${GATEWAY_PORT:-4508}"
PROXY_PORT="${PROXY_PORT:-4510}"
BASE_IMAGE="${BASE_IMAGE:-mcr.microsoft.com/devcontainers/base:ubuntu}"
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

# 1. Gateway image.
log "Gateway image: $IMAGE"
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  ok "present"
else
  warn "not found — building (clones upstream; a few minutes)"
  "$HERE/build.sh"
fi

# 2. Resolve the agent base image's amd64 manifest digest. Fall back to the
#    committed pin if crane is unavailable or the lookup fails.
RUN_CONFIG="$RUN_DIR/agentcontainer.json"
if command -v crane >/dev/null 2>&1; then
  log "Resolving $BASE_IMAGE linux/amd64 digest"
  DIGEST="$(crane digest --platform linux/amd64 "$BASE_IMAGE" 2>/dev/null || true)"
  if [ -n "$DIGEST" ]; then
    ok "$DIGEST"
    sed -E "s#\"image\": \"[^\"]*\"#\"image\": \"${BASE_IMAGE}@${DIGEST}\"#" \
      "$HERE/agentcontainer.json" > "$RUN_CONFIG"
  else
    warn "crane could not resolve digest; using committed config pin"
    cp "$HERE/agentcontainer.json" "$RUN_CONFIG"
  fi
else
  warn "crane not found; using committed config pin"
  cp "$HERE/agentcontainer.json" "$RUN_CONFIG"
fi

# 3. Gateway container (hardened, mirrors the MCP-sidecar profile).
log "Starting gateway on :$GATEWAY_PORT"
docker rm -f sift-gateway >/dev/null 2>&1 || true
docker run -d --name sift-gateway \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /run/secrets:rw,exec -p "${GATEWAY_PORT}:4508" "$IMAGE" >/dev/null
for _ in $(seq 1 20); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${GATEWAY_PORT}/health" 2>/dev/null)" = "200" ] && break
  sleep 1
done
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${GATEWAY_PORT}/health" 2>/dev/null)" = "200" ] \
  && ok "gateway healthy" || die "gateway did not become healthy (docker logs sift-gateway)"

# 4. Agent under enforcement (enforcer auto-starts). Workspace stays this dir;
#    -c just points at the digest-pinned config.
log "Starting agent under enforcement"
agentcontainer run -c "$RUN_CONFIG" -d 2>&1 | grep -avE 'lockfile not found' || true

# 5. MCP proxy fronting the SIFT platform (committed config from cwd; the remote
#    backend's URL is what matters here, not the agent image digest).
log "Starting MCP proxy on :$PROXY_PORT"
if [ -f "$RUN_DIR/proxy.pid" ] && kill -0 "$(cat "$RUN_DIR/proxy.pid")" 2>/dev/null; then
  ok "proxy already running (pid $(cat "$RUN_DIR/proxy.pid"))"
else
  nohup agentcontainer mcp start --port "$PROXY_PORT" > "$RUN_DIR/proxy.log" 2>&1 &
  echo $! > "$RUN_DIR/proxy.pid"
  sleep 6
  if grep -aqE 'Backends:' "$RUN_DIR/proxy.log"; then
    ok "$(grep -aE 'Backends:' "$RUN_DIR/proxy.log" | head -1)"
  else
    warn "proxy not confirmed; last log lines:"; tail -3 "$RUN_DIR/proxy.log" >&2
  fi
fi

cat <<EOT

${G}SIFT platform is up under enforcement.${Z}
  gateway:   http://localhost:${GATEWAY_PORT}/health        (49 tools)
  MCP proxy: http://localhost:${PROXY_PORT}/                (policy / approval / audit)
  agent:     agentcontainer ps   ·   agentcontainer exec sift-agent -- <cmd>
  enforcer:  agentcontainer enforcer status

Tear down with: ${HERE}/down.sh
EOT
