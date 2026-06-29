// opencode → agentcontainer guard adapter  (Phase 5, Layer-2 capability matrix)
//
// Routes opencode's NATIVE tool calls (bash/write/edit) through the exact same
// `agentcontainer guard` broker that gates Claude Code — proving the guard is
// harness-agnostic. opencode has no Claude-Code-style hook protocol, so this
// ~40-line `tool.execute.before` plugin IS the adapter: it synthesizes the
// guard's PreToolUse payload (the 6 snake_case fields the guard.Request struct
// unmarshals) and shells out to the dumb-pipe `guard hook` client, which dials
// the unix socket, gets one Verdict, and prints the decision. Deny ⇒ throw,
// which is how an opencode plugin blocks a tool call.
//
// The guard writes its hash-chained `exec` audit record server-side regardless
// of which harness connected, so the Phase 4 deterministic audit scoring works
// here unchanged. Fails CLOSED: any unparsable/again decision blocks the tool.
//
// Install at ~/.config/opencode/plugins/ (global) so it loads for every
// `opencode run`. Socket via $AC_GUARD_SOCKET (default /run/ac/guard.sock).
import { spawnSync } from "node:child_process"

const SOCK = process.env.AC_GUARD_SOCKET || "/run/ac/guard.sock"

// opencode tool name → [guard tool literal, tool_input payload]. Only Bash and
// the file mutators are policy-evaluated by the guard; everything else passes
// through (the guard would allow it anyway, and the eBPF floor still applies).
const MAP = {
  bash:  (a) => ["Bash",  { command: a.command }],
  write: (a) => ["Write", { file_path: a.filePath }],
  edit:  (a) => ["Edit",  { file_path: a.filePath }],
}

export const GuardAdapter = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    const m = MAP[input.tool]
    if (!m) return
    const args = output.args || {}
    const [tool_name, tool_input] = m(args)
    if (!tool_input.command && !tool_input.file_path) return

    const payload = JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name,
      tool_input,
      cwd: directory || process.cwd(),
      session_id: "opencode-" + (input.sessionID || "session"),
      tool_use_id: "opencode-" + (input.callID || `${Date.now()}`),
    })

    const r = spawnSync("agentcontainer", ["guard", "hook", "--socket", SOCK], {
      input: payload, encoding: "utf8", timeout: 360000,
    })

    let decision = "deny"
    let reason = "guard adapter: no decision from guard hook (fail-closed)"
    try {
      const out = JSON.parse(r.stdout).hookSpecificOutput
      decision = out.permissionDecision
      reason = out.permissionDecisionReason
    } catch (e) {
      reason = "guard adapter: unparsable guard decision (fail-closed): " +
        (r.stderr || r.error || e)
    }
    // deny (and inline-mode "ask") both mean not-allowed.
    if (decision !== "allow") {
      throw new Error("blocked by agentcontainer guard: " + reason)
    }
  },
})
