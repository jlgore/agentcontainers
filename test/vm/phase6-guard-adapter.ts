// pi → agentcontainer guard adapter  (Phase 6, Layer-2 capability matrix)
//
// Routes pi's native bash/write/edit tool calls through the exact same
// `agentcontainer guard` broker that gates Claude Code and opencode — proving
// the guard is harness-agnostic across all three. pi is a default-export
// extension: `pi.on("tool_call", …)` fires before a tool runs; returning
// { block: true, reason } blocks it (returning undefined allows). We synthesize
// the guard's PreToolUse payload and shell out to the dumb-pipe `guard hook`
// client (pi.exec has no stdin, so we use node:child_process, which pi's Node
// runtime provides). Fails CLOSED.
//
// The guard writes its hash-chained `exec` audit record server-side regardless
// of harness, so the Phase 4/5 deterministic audit scoring works here unchanged.
//
// Load with `pi --extension <this-file>`. Socket via $AC_GUARD_SOCKET
// (default /run/ac/guard.sock).
import { spawnSync } from "node:child_process";

const SOCK = process.env.AC_GUARD_SOCKET || "/run/ac/guard.sock";

// pi tool name → [guard tool literal, tool_input]. pi's bash input is
// {command}; write/edit input is {path} (not file_path). Only Bash + the file
// mutators are policy-evaluated by the guard; anything else passes through.
const MAP = {
	bash: (i) => ["Bash", { command: i.command }],
	write: (i) => ["Write", { file_path: i.path }],
	edit: (i) => ["Edit", { file_path: i.path }],
};

export default function (pi) {
	pi.on("tool_call", async (event, _ctx) => {
		const make = MAP[event.toolName];
		if (!make) return undefined;
		const input = event.input || {};
		const [tool_name, tool_input] = make(input);
		if (!tool_input.command && !tool_input.file_path) return undefined;

		const payload = JSON.stringify({
			hook_event_name: "PreToolUse",
			tool_name,
			tool_input,
			cwd: process.cwd(),
			session_id: "pi-session",
			tool_use_id: "pi-" + (event.toolCallId || `${Date.now()}`),
		});

		const r = spawnSync("agentcontainer", ["guard", "hook", "--socket", SOCK], {
			input: payload,
			encoding: "utf8",
			timeout: 360000,
		});

		let decision = "deny";
		let reason = "guard adapter: no decision from guard hook (fail-closed)";
		try {
			const out = JSON.parse(r.stdout).hookSpecificOutput;
			decision = out.permissionDecision;
			reason = out.permissionDecisionReason;
		} catch (e) {
			reason = "guard adapter: unparsable guard decision (fail-closed): " + (r.stderr || r.error || e);
		}
		if (decision !== "allow") {
			return { block: true, reason: "blocked by agentcontainer guard: " + reason };
		}
		return undefined;
	});
}
