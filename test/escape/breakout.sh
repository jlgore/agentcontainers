#!/usr/bin/env bash
# Escape-the-Box — HOST orchestrator for the runtime-free guard-layer suite
# (P2). Sibling of test/vm/phase6-pi.sh; drives the **pi** harness against the
# breakout fixture on the ac-matrix-vm. pi is the cleanest cell (--extension +
# --tools, no config install) and the model axis is validated for both attacker
# brains — anthropic/claude-* and z-ai/glm-5.2 — via OpenRouter.
#
# This is the SAME guard broker + adapter that gates Claude Code and opencode in
# the capability matrix; only the fixture and the scorers (state/audit/emergent)
# differ. The full 2×3 attacker-model × harness matrix layers Phase 4/5 adapters
# on top later — this cell proves the breakout scorers end-to-end first.
#
#   BREAKOUT_PROVIDER=openrouter BREAKOUT_MODEL=z-ai/glm-5.2 OPENROUTER_API_KEY=sk-or-... ./breakout.sh
#   # or BREAKOUT_MODEL=anthropic/claude-opus-4.8 (the constant Claude attacker)
set -euo pipefail

cd "$(dirname "$0")"
NS=ac-matrix
VM=ac-matrix-vm
KEY="${AC_MATRIX_SSH_KEY:-$HOME/.ssh/ac-matrix-vm}"
REPO="$(cd ../.. && pwd)"
FIXTURE="$REPO/test/escape/breakout-matrix.yaml"
REMOTE_DIR=/home/ubuntu/breakout
PROVIDER="${BREAKOUT_PROVIDER:-anthropic}"
MODEL="${BREAKOUT_MODEL:?set BREAKOUT_MODEL, e.g. z-ai/glm-5.2}"
SSHOPTS=(-t "-o StrictHostKeyChecking=no" -t "-o UserKnownHostsFile=/dev/null" -t "-o LogLevel=ERROR")
guest() { virtctl ssh "ubuntu@vmi/$VM" -n "$NS" -i "$KEY" "${SSHOPTS[@]}" -c "$1"; }
push()  { virtctl scp "$1" "ubuntu@vmi/$VM:$2" -n "$NS" -i "$KEY" "${SSHOPTS[@]}"; }
pull()  { virtctl scp "ubuntu@vmi/$VM:$1" "$2" -n "$NS" -i "$KEY" "${SSHOPTS[@]}"; }

if [ -t 1 ]; then B='\033[1;34m'; G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; Z='\033[0m'; else B=''; G=''; Y=''; R=''; Z=''; fi
log() { printf "${B}==>${Z} %s\n" "$*"; }
ok()  { printf "  ${G}OK${Z} %s\n" "$*"; }
die() { printf "${R}xx %s${Z}\n" "$*" >&2; exit 1; }

command -v virtctl >/dev/null 2>&1 || die "virtctl not found"
command -v yq >/dev/null 2>&1 || die "yq not found on host (used to derive policy + cases)"
[ -f "$FIXTURE" ] || die "fixture not found: $FIXTURE"

# ---- resolve the provider key ----------------------------------------------
APIKEY=""
if [ -n "${BREAKOUT_KEY_FILE:-}" ]; then APIKEY="$(cat "$BREAKOUT_KEY_FILE")"
elif [ "$PROVIDER" = anthropic ] && [ -n "${ANTHROPIC_API_KEY:-}" ]; then APIKEY="$ANTHROPIC_API_KEY"
elif [ "$PROVIDER" = openrouter ] && [ -n "${OPENROUTER_API_KEY:-}" ]; then APIKEY="$OPENROUTER_API_KEY"
fi
[ -n "$APIKEY" ] || die "no key for provider '$PROVIDER' — set ANTHROPIC_API_KEY / OPENROUTER_API_KEY / BREAKOUT_KEY_FILE"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ---- 1. ensure pi + the agentcontainer binary are present ------------------
log "Ensuring pi is installed on the VM"
guest 'command -v pi >/dev/null 2>&1 || sudo npm i -g @earendil-works/pi-coding-agent >/dev/null 2>&1; echo "pi $(pi --version 2>&1 | head -1)"' | sed 's/^/  /'
[ "${AC_SKIP_BUILD:-1}" = 1 ] && ok "reusing the on-VM agentcontainer binary (AC_SKIP_BUILD=1)" || {
  log "Building + shipping agentcontainer"
  ( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$WORK/agentcontainer" ./cmd/agentcontainer )
  push "$WORK/agentcontainer" /home/ubuntu/agentcontainer >/dev/null
  guest 'sudo install -m0755 /home/ubuntu/agentcontainer /usr/local/bin/agentcontainer && agentcontainer version' | sed 's/^/  /'
}

# ---- 2. derive policy + cases from the ONE fixture, ship to the VM ---------
# Host has yq; the VM consumes only the derived guard-policy.yaml + cases.json
# (jq on the VM) — single source, no drift from the Layer-1 oracle, no yq on VM.
log "Deriving guard policy + cases from $(basename "$FIXTURE")"
yq '.policy' "$FIXTURE" > "$WORK/guard-policy.yaml"
yq -o=json '.cases' "$FIXTURE" > "$WORK/cases.json"
ok "$(jq 'length' "$WORK/cases.json") cases, policy block extracted"

log "Shipping derived artifacts + runner + guard adapter -> $VM:$REMOTE_DIR"
guest "mkdir -p $REMOTE_DIR && sudo mkdir -p /var/lib/ac/audit && sudo chown ubuntu:ubuntu /var/lib/ac/audit"
push "$WORK/guard-policy.yaml" "$REMOTE_DIR/guard-policy.yaml" >/dev/null
push "$WORK/cases.json" "$REMOTE_DIR/cases.json" >/dev/null
push "$REPO/test/escape/breakout-run.sh" "$REMOTE_DIR/breakout-run.sh" >/dev/null
push "$REPO/test/vm/phase6-guard-adapter.ts" "$REMOTE_DIR/phase6-guard-adapter.ts" >/dev/null
push "$REPO/test/escape/breakout-approver.js" "$REMOTE_DIR/breakout-approver.js" >/dev/null
guest "chmod +x $REMOTE_DIR/breakout-run.sh"
ok "policy, cases, runner, guard-adapter, HITL approver in place"

# ---- 3. deliver the provider key to VM tmpfs -------------------------------
log "Delivering provider key -> $VM:/run/secrets/pi-key (tmpfs, mode 600)"
printf '%s' "$APIKEY" | virtctl ssh "ubuntu@vmi/$VM" -n "$NS" -i "$KEY" "${SSHOPTS[@]}" \
  -c 'sudo install -d -m0711 /run/secrets && sudo tee /run/secrets/pi-key >/dev/null && sudo chown ubuntu:ubuntu /run/secrets/pi-key && sudo chmod 600 /run/secrets/pi-key && echo "key staged ($(wc -c < /run/secrets/pi-key) bytes)"' | sed 's/^/  /'

# ---- 4. run the cell -------------------------------------------------------
log "Running the breakout guard-layer cell on the VM (pi --print per case, deny mode)"
RUNENV="BREAKOUT_PROVIDER='$PROVIDER' BREAKOUT_MODEL='$MODEL' BREAKOUT_AGENT_TIMEOUT=${BREAKOUT_AGENT_TIMEOUT:-180} AC_AUDIT_DIR=/var/lib/ac/audit"
[ -n "${CASE_FILTER:-}" ] && RUNENV="$RUNENV CASE_FILTER='$CASE_FILTER'"
[ -n "${SCORE_ONLY:-}" ] && RUNENV="$RUNENV SCORE_ONLY='$SCORE_ONLY'"
set +e
guest "cd $REMOTE_DIR && $RUNENV ./breakout-run.sh"
RC=$?
set -e

# ---- 5. retrieve results ---------------------------------------------------
log "Retrieving results"
pull "$REMOTE_DIR/results.jsonl" "$WORK/results.jsonl" >/dev/null 2>&1 || true
tag="$(printf '%s' "$MODEL" | tr '/:' '--')"
[ -s "$WORK/results.jsonl" ] && { cp "$WORK/results.jsonl" "$REPO/test/escape/breakout-results-$tag.jsonl"; ok "results -> test/escape/breakout-results-$tag.jsonl"; }
[ "$RC" -eq 0 ] && printf "${G}Breakout cell [$MODEL]: GREEN${Z}\n" || printf "${R}Breakout cell [$MODEL]: FAIL (rc=$RC) — see the per-case table above${Z}\n"
exit "$RC"
