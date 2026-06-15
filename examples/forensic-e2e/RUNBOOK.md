# Forensic E2E — Operator Runbook

End-to-end runbook for the **proxy-path** forensic demo: the SIFT gateway runs as a
kernel-enforced container backend *behind* the MCP proxy, every forensic tool call is
policy-evaluated (OPA), approval-gated, correlation-tagged, and recorded in the
`<session>-proxy` audit hash chain. Acquired evidence is mounted **read-only**.

Two ways to drive it with a Claude Code harness:

- **Bare** — Claude runs on the host, pointed at the proxy. Still fully **OPA-governed**:
  Claude's own Bash/Write go through the guard hook (OPA + HITL), forensic tools go
  through the proxy (OPA + audit). Lacks only the eBPF kernel boundary around Claude
  itself.
- **Containerized** — Claude runs *inside* the enforced `claude-agent` container; adds
  the eBPF kernel boundary (egress / file_open / exec) + fail-closed on top. See
  `examples/claude-agent/E2E-FORENSIC-DEMO.md`.

> **One command:** `./demo.sh up` brings up guard + enforcer + gateway + proxy and wires
> the bare harness idempotently, then prints the `claude …` command. `./demo.sh status`
> and `./demo.sh down` manage it. The step-by-step below is what that automates.

---

## 0. Prerequisites (host)

- `scripts/bootstrap.sh` has run: Docker, the `agentcontainer` CLI, the enforcer image,
  and **BPF LSM active** (`agentcontainer enforcer diagnose` → BPF LSM `[PASS]`).
- The CLI is **≥ v0.1.9** and the enforcer image is **≥ ac-enforcer-v0.1.6** — earlier
  builds hit three kernel-primary bugs fixed in this repo:
  - `get_stats` empty-container_id (kernel-primary gate aborted `run`) — `ac-enforcer-v0.1.5`
  - exec-allowlist denied the gateway's sub-servers (0 tools) — `ac-enforcer-v0.1.6`
  - proxy panicked on Claude's numeric `progressToken` (every tool call crashed it) — CLI v0.1.9
- `ewf-tools` installed and `user_allow_other` in `/etc/fuse.conf` (up.sh sets the latter).
- A case laid out as `<case>/evidence/*.E01` (see §1).

---

## 1. Build the case

The demo uses one acquired disk image. Stage just the `.E01` into a fresh case:

```bash
mkdir -p /cases/e2e-demo/{evidence,findings,timeline,audit,extractions}
unzip -j -o /cases/<image>.zip '*/<image>-c-drive.E01' -d /cases/e2e-demo/evidence/
ls -lh /cases/e2e-demo/evidence/     # expect the .E01
```

You only need ONE image. Multiple evidence archives are *separate victim hosts*, not
parts of one case.

---

## 2. Bring up the enforced stack

```bash
cd examples/forensic-e2e
./up.sh            # ewfmount + gateway image + agent under enforcement + MCP proxy
```

Success signals (the green banner prints unconditionally — look for these instead):

- `kernel-primary enforcement verified: BPF LSM hooks active, cgroupns=host`
- `OK Backends: sift` (not `proxy not confirmed`)
- gateway log → `Tool map built: 49 tools across 4 backends`:
  ```bash
  gw=$(docker ps --filter ancestor=ghcr.io/jlgore/sift-gateway:e2e --format '{{.ID}}' | head -1)
  docker logs "$gw" 2>&1 | grep -i "Tool map built"
  ```

> **Evidence paths — important.** `up.sh` runs `ewfmount` on the **host** to expose the
> E01 as a raw device:
> - **Host path:** `/cases/e2e-demo/.ewfraw/ewf1` (use this for bare host Sleuth Kit).
> - **In-gateway path:** `/cases/e2e-demo/evidence-raw/ewf1` (the `.ewfraw:…/evidence-raw:ro`
>   mount — this is what the **audited** `run_command` tool sees; it does **not** exist on
>   the host). The original `.E01` stays read-only at `evidence/`.
> Analyze a *logical NTFS volume*: use `fsstat`/`fls`, not `mmls`.

---

## 3a. Bare harness (Claude on the host)

```bash
# install Claude Code (native, no Node)
curl -fsSL https://claude.ai/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"        # add to ~/.bashrc too
claude        # then /login   (or: export CLAUDE_CODE_OAUTH_TOKEN=…)
```

Wire the guard hook for the native install — `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse":  [ { "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
      "hooks": [ { "type": "command", "command": "/usr/local/bin/agentcontainer guard hook --socket $HOME/.ac/guard.sock" } ] } ],
    "PostToolUse": [ { "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
      "hooks": [ { "type": "command", "command": "/usr/local/bin/agentcontainer guard hook --socket $HOME/.ac/guard.sock" } ] } ],
    "PostToolUseFailure": [ { "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
      "hooks": [ { "type": "command", "command": "/usr/local/bin/agentcontainer guard hook --socket $HOME/.ac/guard.sock" } ] } ]
  }
}
```
(Use an **absolute** socket path — hooks don't expand `~` reliably.)

Proxy MCP config — `~/sift-proxy-mcp.json`:
```json
{ "mcpServers": { "sift": { "type": "http", "url": "http://localhost:4510/" } } }
```

Start the guard, then Claude:
```bash
agentcontainer guard serve --escalation inline    # inline = approvals prompt in Claude's TUI; can background
claude --mcp-config ~/sift-proxy-mcp.json --strict-mcp-config
```

In-session: `/mcp` should list `sift` with `mcp__sift__*` (49 tools). Claude's own
Bash/Write hit the guard (OPA → allow/ask/deny inline); forensic tools hit the proxy
(OPA + audit). `--escalation prompt` instead routes approvals to a separate
`guard serve` terminal (out-of-band — the production default).

---

## 3b. Containerized harness (Claude inside the enforced container)

Adds the eBPF kernel boundary around Claude. Full runbook:
`examples/claude-agent/E2E-FORENSIC-DEMO.md`. Same proxy/OPA/audit story as bare,
plus cgroup egress / file_open / exec enforcement and fail-closed on Claude itself.

---

## 4. Verify the enforced path

```bash
# read-only evidence — via the gateway's audited run_command tool (NOT host exec):
#   run_command(["dd","if=/dev/null","of=/cases/e2e-demo/evidence/x"])  -> "Read-only file system"
agentcontainer audit list                       # find the <session-id>
agentcontainer audit show  <session-id>-proxy   # tool_call entries + verdicts
agentcontainer audit verify <session-id>-proxy  # -> OK: N entries, chain intact
```

> `agentcontainer exec sift-forensic-agent -- sh -c '…'` is **not** the read-only test:
> the guard denies `sh -c`, every exec is approval-gated, and the agent doesn't even mount
> `/cases`. The real RO proof is a write attempt through the gateway's `run_command`.

---

## 5. Teardown

```bash
./demo.sh down      # guard + stack
# or just the stack:
./down.sh
```

---

## Gotchas seen in the field

| Symptom | Cause / fix |
|---|---|
| `enforcer status` → `Health: UNHEALTHY` | Cosmetic on CLI < v0.1.7: the bundled `grpc_health_probe` is plaintext vs the mTLS server. Enforcement is fine — check `enforcer diagnose` (BPF LSM `[PASS]`). Fixed in CLI status to probe with mTLS. |
| `run: kernel-primary enforcement unavailable … container not registered` | Enforcer image predates `ac-enforcer-v0.1.5`. Pull the current `ghcr.io/jlgore/agentcontainer-enforcer:latest`. |
| Gateway up but `Tool map built: 0 tools` (`Permission denied: /app/venv/bin/python`) | Enforcer image predates `ac-enforcer-v0.1.6` (exec-allowlist denied the gateway's sub-servers). Pull current `:latest`. |
| `/mcp` shows 49 tools but every call → "socket closed" | Proxy panicked on Claude's numeric `progressToken`. Needs CLI ≥ v0.1.9. |
| `no route to host` to the gateway on `up.sh` | Transient gateway-startup/timing blip; re-run. |
| `evidence-raw/ewf1` empty on the host | Expected — that path only exists *inside the gateway*. Host raw image is `.ewfraw/ewf1`. |
