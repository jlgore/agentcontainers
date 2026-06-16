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
PROTOCOL_SIFT_DIR="$HOME/protocol-sift"
SIFT_MCP_DIR="${SIFT_MCP_DIR:-$HOME/git/sift-mcp}"

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

wire_skills() {
  if [ -d "$PROTOCOL_SIFT_DIR" ]; then
    ok "protocol-sift already present -> $PROTOCOL_SIFT_DIR"
  else
    log "Cloning protocol-sift skills"
    if git clone --depth 1 https://github.com/teamdfir/protocol-sift.git "$PROTOCOL_SIFT_DIR"; then
      ok "protocol-sift cloned -> $PROTOCOL_SIFT_DIR"
    else
      warn "could not clone protocol-sift; DFIR skills were not wired"
      return 1
    fi
  fi

  local skills_src="$PROTOCOL_SIFT_DIR/skills"
  local skills_dst="$HERE/.claude/skills"
  mkdir -p "$skills_dst"
  local linked=0
  local existing=0
  local skipped=0
  local skill_dir skill_name link_target current_target
  for skill_dir in "$skills_src"/*/; do
    [ -d "$skill_dir" ] || continue
    skill_dir="${skill_dir%/}"
    skill_name="$(basename "$skill_dir")"
    link_target="$skills_dst/$skill_name"
    if [ -L "$link_target" ]; then
      current_target="$(readlink "$link_target")"
      if [ "$current_target" = "$skill_dir" ]; then
        existing=$((existing + 1))
      else
        warn "skill target exists with different symlink: $link_target -> $current_target"
        skipped=$((skipped + 1))
      fi
    elif [ -e "$link_target" ]; then
      warn "skill target exists and is not a symlink: $link_target"
      skipped=$((skipped + 1))
    elif ln -s "$skill_dir" "$link_target"; then
      linked=$((linked + 1))
    else
      warn "failed to link skill: $skill_name"
      skipped=$((skipped + 1))
    fi
  done
  if [ "$linked" -eq 0 ] && [ "$existing" -eq 0 ]; then
    warn "no skill directories found under $skills_src"
  else
    ok "skills wired -> $skills_dst ($linked linked, $existing existing, $skipped skipped)"
  fi

  local agents_dst="$HERE/.claude/agents"
  local critic_src="$SIFT_MCP_DIR/.claude/agents/forensic-critic.md"
  local critic_dst="$agents_dst/forensic-critic.md"
  mkdir -p "$agents_dst"
  if [ -e "$critic_dst" ]; then
    ok "forensic-critic already present -> $critic_dst"
  elif [ -f "$critic_src" ]; then
    if cp "$critic_src" "$critic_dst"; then
      ok "forensic-critic copied -> $critic_dst"
    else
      warn "could not copy forensic-critic from $critic_src"
    fi
  else
    warn "forensic-critic source not found at $critic_src; place it in $agents_dst manually if needed"
  fi

  if [ -f "$HERE/CLAUDE.md" ]; then
    ok "Claude investigation context -> $HERE/CLAUDE.md"
  else
    warn "$HERE/CLAUDE.md is missing; Claude will start without the forensic investigation context"
  fi
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
    log "DFIR skills and critic wiring"
    wire_skills || exit 1
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
