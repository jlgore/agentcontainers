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

# Present EWF/E01 evidence as a raw device for the gateway. The gateway image's
# bundled sleuthkit (Debian TSK 4.12.1 + libewf2) segfaults on any libewf read,
# so the container cannot open the .E01 directly. ewfmount on the HOST decodes
# the EWF and exposes a flat raw image at <case>/.ewfraw/ewf1; the gateway binds
# that read-only (see agentcontainer.json) and TSK reads it natively. allow_root
# lets the Docker daemon (root) traverse the FUSE mount when it sets up the bind.
RAW_MNT="$CASE_DIR/.ewfraw"
mkdir -p "$RAW_MNT"
E01="$(ls "$CASE_DIR"/evidence/*.E01 2>/dev/null | head -1 || true)"
if [ -n "$E01" ]; then
  if mount | grep -q " on $RAW_MNT "; then
    ok "evidence already presented raw at $RAW_MNT/ewf1 (ewfmount)"
  else
    command -v ewfmount >/dev/null 2>&1 || die "ewfmount not found — install ewf-tools/libewf-tools"
    if ! grep -q '^user_allow_other' /etc/fuse.conf 2>/dev/null; then
      warn "enabling user_allow_other in /etc/fuse.conf (one-time, needs sudo)"
      echo user_allow_other | sudo tee -a /etc/fuse.conf >/dev/null
    fi
    if ewfmount -X allow_root "$E01" "$RAW_MNT" >/dev/null 2>&1; then
      ok "ewfmount: $(basename "$E01") -> $RAW_MNT/ewf1 (raw, read-only)"
    else
      die "ewfmount failed for $E01 — check ewf-tools and /etc/fuse.conf"
    fi
  fi
else
  warn "no .E01 in $CASE_DIR/evidence — assuming raw/dd evidence (skipping ewfmount)"
fi

# Evidence immutability. The gateway runs as the owner uid (1000) on a
# read-write /cases (needed so case_init can create new cases), so neither the
# mount nor DAC stops it from deleting/altering acquired evidence. Mark every
# evidence file immutable: the gateway is launched CapDrop:["ALL"] → no
# CAP_LINUX_IMMUTABLE → it cannot modify, delete, rename, or clear +i, even as
# owner. This is the kernel-level evidence guarantee the proxy path relies on.
# Idempotent (chattr +i on an already-immutable file is a no-op); needs sudo.
CASES_DIR="$(dirname "$CASE_DIR")"
shopt -s nullglob
locked=0
for f in "$CASE_DIR"/evidence/* "$CASES_DIR"/*.zip "$CASES_DIR"/*.E01 "$CASES_DIR"/*.dd "$CASES_DIR"/*.raw; do
  [ -f "$f" ] || continue
  if sudo chattr +i "$f" 2>/dev/null; then locked=$((locked + 1)); else warn "could not chattr +i $f (evidence not immutable!)"; fi
done
shopt -u nullglob
ok "evidence marked immutable (chattr +i): $locked file(s) — capless gateway cannot clear it"
# NOTE: removing a case later needs `sudo chattr -i <evidence>` first (by design).

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

# Ensure the proxy port is free. On the demo VM another container may already
# publish :4510 (the default); rather than fail to bind, bump to the next free
# port so a fresh judge run never collides. Override with PROXY_PORT=.
port_busy() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; } || return 1
  fi
}
if port_busy "$PROXY_PORT"; then
  orig="$PROXY_PORT"
  for cand in $(seq "$PROXY_PORT" $((PROXY_PORT + 20))); do
    port_busy "$cand" || { PROXY_PORT="$cand"; break; }
  done
  [ "$PROXY_PORT" = "$orig" ] && die "no free port found near $orig (set PROXY_PORT)"
  warn "port $orig is in use — using free port $PROXY_PORT instead"
fi

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
