#!/usr/bin/env bash
# One idempotent command for the bare forensic-e2e harness: guard + enforcer +
# gateway + proxy + the native Claude Code wiring — so you don't juggle a stack
# of terminals. Wraps up.sh/down.sh and adds the host-side guard + harness config.
#
#   ./demo.sh up        # bring everything up (idempotent), print the `claude` command
#   ./demo.sh status     # what's running / healthy
#   ./demo.sh down       # tear it all down (stack + guard)
#
# Env: PROXY_PORT=4510  CASE_DIR=/cases/e2e-demo  ESCALATION=inline
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
PROXY_PORT="${PROXY_PORT:-4510}"
ESCALATION="${ESCALATION:-inline}"     # inline = approvals in Claude's TUI; prompt = out-of-band guard terminal
GUARD_SOCK="$HOME/.ac/guard.sock"
GUARD_PID="$HOME/.ac/demo-guard.pid"   # stable (down.sh wipes .run/)
GUARD_LOG="$HOME/.ac/demo-guard.log"
MCP_JSON="$HOME/sift-proxy-mcp.json"
SETTINGS="$HOME/.claude/settings.json"

if [ -t 1 ]; then B='\033[1;34m'; G='\033[1;32m'; Y='\033[1;33m'; Z='\033[0m'; else B=''; G=''; Y=''; Z=''; fi
log()  { printf "${B}==>${Z} %s\n" "$*"; }
ok()   { printf "  ${G}OK${Z} %s\n" "$*"; }
warn() { printf "  ${Y}!!${Z} %s\n" "$*" >&2; }

guard_running() { [ -f "$GUARD_PID" ] && kill -0 "$(cat "$GUARD_PID" 2>/dev/null)" 2>/dev/null; }

wire_harness() {
  mkdir -p "$HOME/.claude"
  cat > "$MCP_JSON" <<JSON
{ "mcpServers": { "sift": { "type": "http", "url": "http://localhost:${PROXY_PORT}/" } } }
JSON
  ok "mcp config -> $MCP_JSON (proxy :$PROXY_PORT)"

  if [ -f "$SETTINGS" ] && ! grep -q 'agentcontainer guard hook' "$SETTINGS"; then
    warn "$SETTINGS exists without the guard hook — leaving it untouched (add the hook manually; see RUNBOOK.md)"
    return
  fi
  cat > "$SETTINGS" <<JSON
{
  "hooks": {
    "PreToolUse":  [ { "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
      "hooks": [ { "type": "command", "command": "/usr/local/bin/agentcontainer guard hook --socket $GUARD_SOCK" } ] } ],
    "PostToolUse": [ { "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
      "hooks": [ { "type": "command", "command": "/usr/local/bin/agentcontainer guard hook --socket $GUARD_SOCK" } ] } ],
    "PostToolUseFailure": [ { "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
      "hooks": [ { "type": "command", "command": "/usr/local/bin/agentcontainer guard hook --socket $GUARD_SOCK" } ] } ]
  }
}
JSON
  ok "guard hook wired -> $SETTINGS"
}

start_guard() {
  if guard_running; then ok "guard already running (pid $(cat "$GUARD_PID"))"; return; fi
  mkdir -p "$HOME/.ac"
  if [ "$ESCALATION" = "prompt" ]; then
    warn "ESCALATION=prompt needs an interactive terminal; run 'agentcontainer guard serve' yourself and re-run with ESCALATION=inline to auto-manage it"
    return 1
  fi
  # inline escalation needs no TTY (approvals surface in Claude's own TUI).
  nohup agentcontainer guard serve --escalation inline >"$GUARD_LOG" 2>&1 &
  echo $! > "$GUARD_PID"
  for _ in $(seq 1 20); do [ -S "$GUARD_SOCK" ] && break; sleep 0.5; done
  [ -S "$GUARD_SOCK" ] && ok "guard serve (inline) pid $(cat "$GUARD_PID"), socket $GUARD_SOCK" \
    || { warn "guard socket not up; see $GUARD_LOG"; return 1; }
}

case "${1:-}" in
  up)
    log "Guard (OPA + HITL for Claude's own tools)"
    start_guard || exit 1
    log "Enforced stack (enforcer + gateway behind the proxy)"
    PROXY_PORT="$PROXY_PORT" ./up.sh
    log "Native Claude Code harness wiring"
    wire_harness
    cat <<EOT

${G}Forensic E2E (bare) is up.${Z} Run Claude against the audited proxy:

  claude --mcp-config $MCP_JSON --strict-mcp-config

  /mcp should show: sift · connected · 49 tools
  Claude's own Bash/Write -> guard (OPA, approvals inline); forensic tools -> proxy (OPA + audit).
  ./demo.sh status | down
EOT
    ;;
  status)
    log "Guard";     guard_running && ok "running (pid $(cat "$GUARD_PID")), socket $([ -S "$GUARD_SOCK" ] && echo up || echo MISSING)" || warn "not running"
    log "Enforcer";  agentcontainer enforcer status 2>&1 | sed 's/^/  /' | head -6
    log "Containers"; docker ps --format '{{.Names}}  {{.Status}}' | grep -iE 'sift|forensic|enforcer|ac-mcp' | sed 's/^/  /' || echo "  none"
    log "Proxy port :$PROXY_PORT"; (ss -ltnH 2>/dev/null | grep -q "[:.]$PROXY_PORT\$" && ok "listening") || warn "not listening"
    ;;
  down)
    log "Stack"; ./down.sh
    log "Guard"
    if guard_running; then kill "$(cat "$GUARD_PID")" 2>/dev/null && ok "stopped guard"; fi
    rm -f "$GUARD_PID"
    ok "down (harness config left in place: $MCP_JSON, $SETTINGS)"
    ;;
  *)
    echo "usage: $0 {up|status|down}" >&2; exit 2 ;;
esac
