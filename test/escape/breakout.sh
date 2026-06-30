#!/usr/bin/env bash
# Escape-the-Box — HOST orchestrator for the runtime-free guard-layer suite (P2).
# Drives ANY of the three harnesses against the one breakout fixture on the
# ac-matrix-vm, completing the 2×3 attacker-model × harness grid. Every harness
# routes its native tools to the SAME `agentcontainer guard` broker via its own
# adapter (pi extension / opencode plugin / Claude Code managed PreToolUse hook),
# so the fixture, policy, and scorers are identical — only the harness wiring differs.
#
#   BREAKOUT_HARNESS=pi|opencode|claude \
#   BREAKOUT_PROVIDER=openrouter BREAKOUT_MODEL=z-ai/glm-5.2 OPENROUTER_API_KEY=sk-or-... ./breakout.sh
#   # or BREAKOUT_MODEL=anthropic/claude-opus-4.8 (the Claude attacker brain)
set -euo pipefail

cd "$(dirname "$0")"
NS=ac-matrix
VM=ac-matrix-vm
KEY="${AC_MATRIX_SSH_KEY:-$HOME/.ssh/ac-matrix-vm}"
REPO="$(cd ../.. && pwd)"
FIXTURE="$REPO/test/escape/breakout-matrix.yaml"
REMOTE_DIR=/home/ubuntu/breakout
HARNESS="${BREAKOUT_HARNESS:-pi}"
PROVIDER="${BREAKOUT_PROVIDER:-openrouter}"
MODEL="${BREAKOUT_MODEL:?set BREAKOUT_MODEL, e.g. z-ai/glm-5.2}"
KEYPATH=/run/secrets/breakout-key
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
case "$HARNESS" in pi|opencode|claude) ;; *) die "BREAKOUT_HARNESS must be pi|opencode|claude" ;; esac

# ---- resolve the provider key ----------------------------------------------
APIKEY=""
if [ -n "${BREAKOUT_KEY_FILE:-}" ]; then APIKEY="$(cat "$BREAKOUT_KEY_FILE")"
elif [ "$PROVIDER" = anthropic ] && [ -n "${ANTHROPIC_API_KEY:-}" ]; then APIKEY="$ANTHROPIC_API_KEY"
elif [ "$PROVIDER" = openrouter ] && [ -n "${OPENROUTER_API_KEY:-}" ]; then APIKEY="$OPENROUTER_API_KEY"
fi
[ -n "$APIKEY" ] || die "no key for provider '$PROVIDER' — set ANTHROPIC_API_KEY / OPENROUTER_API_KEY / BREAKOUT_KEY_FILE"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ---- 1. ensure the chosen harness + the agentcontainer binary are present --
log "Ensuring harness '$HARNESS' is installed on the VM"
case "$HARNESS" in
  pi)       guest 'command -v pi >/dev/null 2>&1 || sudo npm i -g @earendil-works/pi-coding-agent >/dev/null 2>&1; echo "pi $(pi --version 2>&1 | head -1)"' | sed 's/^/  /' ;;
  opencode) guest 'command -v opencode >/dev/null 2>&1 || sudo npm i -g opencode-ai >/dev/null 2>&1; echo "opencode $(opencode --version 2>&1 | head -1)"' | sed 's/^/  /' ;;
  claude)   guest 'command -v claude >/dev/null 2>&1 || sudo npm i -g @anthropic-ai/claude-code >/dev/null 2>&1; echo "claude $(claude --version 2>&1 | head -1)"' | sed 's/^/  /' ;;
esac
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

log "Shipping derived artifacts + runner + approver -> $VM:$REMOTE_DIR"
guest "mkdir -p $REMOTE_DIR && sudo mkdir -p /var/lib/ac/audit && sudo chown ubuntu:ubuntu /var/lib/ac/audit"
push "$WORK/guard-policy.yaml" "$REMOTE_DIR/guard-policy.yaml" >/dev/null
push "$WORK/cases.json" "$REMOTE_DIR/cases.json" >/dev/null
push "$REPO/test/escape/breakout-run.sh" "$REMOTE_DIR/breakout-run.sh" >/dev/null
push "$REPO/test/escape/breakout-approver.js" "$REMOTE_DIR/breakout-approver.js" >/dev/null
push "$REPO/test/escape/breakout-canary.py" "$REMOTE_DIR/breakout-canary.py" >/dev/null
guest "chmod +x $REMOTE_DIR/breakout-run.sh"

# ---- 2b. install the chosen harness's guard adapter (all → same guard sock) -
log "Installing the $HARNESS guard adapter"
case "$HARNESS" in
  pi)
    push "$REPO/test/vm/phase6-guard-adapter.ts" "$REMOTE_DIR/phase6-guard-adapter.ts" >/dev/null
    ok "pi extension shipped (loaded per-invocation via --extension)" ;;
  opencode)
    # auto-loaded plugin + managed config (root-owned) with provider/model and the
    # key referenced via {file:...}; native read/grep/glob/webfetch denied so all
    # work funnels onto the guarded bash/edit/write path.
    guest "mkdir -p ~/.config/opencode/plugin"
    push "$REPO/test/vm/phase5-guard-adapter.js" "/home/ubuntu/.config/opencode/plugin/phase5-guard-adapter.js" >/dev/null
    cat > "$WORK/opencode.json" <<JSON
{
  "\$schema": "https://opencode.ai/config.json",
  "model": "$PROVIDER/$MODEL",
  "provider": { "$PROVIDER": { "options": { "apiKey": "{file:$KEYPATH}" } } },
  "permission": {
    "bash": "allow", "edit": "allow", "write": "allow",
    "read": "deny", "grep": "deny", "glob": "deny", "webfetch": "deny", "websearch": "deny"
  }
}
JSON
    push "$WORK/opencode.json" /home/ubuntu/opencode.json >/dev/null
    guest "sudo install -d -m0755 /etc/opencode && sudo install -m0644 -o root -g root /home/ubuntu/opencode.json /etc/opencode/opencode.json && rm -f /home/ubuntu/opencode.json && echo managed: \$(sudo jq -c '{model,permission}' /etc/opencode/opencode.json)" | sed 's/^/  /' ;;
  claude)
    # locked managed PreToolUse hook (root-owned, agent can't disable) → guard hook.
    push "$REPO/examples/claude-agent/managed-settings.json" /home/ubuntu/managed-settings.json >/dev/null
    guest "sudo install -d -m0755 /etc/claude-code && sudo install -m0644 -o root -g root /home/ubuntu/managed-settings.json /etc/claude-code/managed-settings.json && rm -f /home/ubuntu/managed-settings.json && echo 'managed hook installed'" | sed 's/^/  /' ;;
esac
ok "policy, cases, runner, approver, $HARNESS adapter in place"

# ---- 3. deliver the provider key to VM tmpfs -------------------------------
log "Delivering provider key -> $VM:$KEYPATH (tmpfs, mode 600)"
printf '%s' "$APIKEY" | virtctl ssh "ubuntu@vmi/$VM" -n "$NS" -i "$KEY" "${SSHOPTS[@]}" \
  -c "sudo install -d -m0711 /run/secrets && sudo tee $KEYPATH >/dev/null && sudo chown ubuntu:ubuntu $KEYPATH && sudo chmod 600 $KEYPATH && echo \"key staged (\$(wc -c < $KEYPATH) bytes)\"" | sed 's/^/  /'

# ---- 4. run the cell -------------------------------------------------------
log "Running the breakout cell on the VM — harness=$HARNESS model=$MODEL"
RUNENV="BREAKOUT_HARNESS='$HARNESS' BREAKOUT_PROVIDER='$PROVIDER' BREAKOUT_MODEL='$MODEL' BREAKOUT_AGENT_TIMEOUT=${BREAKOUT_AGENT_TIMEOUT:-180} AC_AUDIT_DIR=/var/lib/ac/audit"
[ -n "${CASE_FILTER:-}" ] && RUNENV="$RUNENV CASE_FILTER='$CASE_FILTER'"
[ -n "${SCORE_ONLY:-}" ] && RUNENV="$RUNENV SCORE_ONLY='$SCORE_ONLY'"
set +e
guest "cd $REMOTE_DIR && $RUNENV ./breakout-run.sh"
RC=$?
set -e

# ---- 5. retrieve results ---------------------------------------------------
log "Retrieving results"
pull "$REMOTE_DIR/results.jsonl" "$WORK/results.jsonl" >/dev/null 2>&1 || true
tag="$HARNESS-$(printf '%s' "$MODEL" | tr '/:' '--')"
[ -s "$WORK/results.jsonl" ] && { cp "$WORK/results.jsonl" "$REPO/test/escape/breakout-results-$tag.jsonl"; ok "results -> test/escape/breakout-results-$tag.jsonl"; }
[ "$RC" -eq 0 ] && printf "${G}Breakout cell [$HARNESS/$MODEL]: GREEN${Z}\n" || printf "${R}Breakout cell [$HARNESS/$MODEL]: FAIL (rc=$RC) — see the per-case table above${Z}\n"
exit "$RC"
