# claude-agent — Claude Code under zero-trust enforcement

Run Claude Code itself inside an agentcontainers-enforced container, with its
**own** tool calls gated by the same OPA policy and human-in-the-loop approval
that gate the MCP forensic tools.

Three layers wrap the agent:

| Layer | Mechanism | Stops |
|-------|-----------|-------|
| **Tool policy** | PreToolUse hook → host `guard serve` → OPA + HITL | `curl`, `bash -c`, `rm -rf /`, blocked dirs — with a human-readable reason and an approval escalation |
| **Network** | eBPF egress allowlist (kernel) | any connection except `api.anthropic.com:443` |
| **Secrets** | API key in `/run/secrets` (tmpfs), read via `apiKeyHelper` | key never appears in the agent's environment |

The decision authority is **out-of-band**: `guard serve` runs on the host. The
in-container hook only carries a request over a bind-mounted unix socket and
renders the verdict — it cannot allow what the host denies, and the agent cannot
edit the hook (it lives in root-owned `/etc/claude-code/managed-settings.json`,
Claude Code's highest-precedence settings source).

## Prerequisites

- Docker, and the agentcontainers enforcer image available locally.
- The `agentcontainer` binary on the host (this branch's build — `guard` subcommand).
- An `ANTHROPIC_API_KEY` for the final, key-dependent step.
- The host user running `guard serve` should have **uid 1000** — the image runs
  as uid 1000, and the guard socket is `0600`. If your uid differs, see
  *uid alignment* below.

## Build

```sh
examples/claude-agent/build.sh           # builds claude-agent:demo
```

## Run

From the workspace you want the agent to operate in (it is bind-mounted at
`/workspace`, which is also the agent's writable `HOME`):

```sh
# 1. Host-side decision authority. Leave it running; denials prompt here
#    (or approve from another terminal with `agentcontainer approve`).
sudo mkdir -p /run/ac && sudo chown "$(id -u):$(id -g)" /run/ac
agentcontainer guard serve \
  --socket /run/ac/guard.sock \
  --security-yaml examples/sift-platform/guard.security.yaml &

# 2. Start the enforced agent container (detached).
export ANTHROPIC_API_KEY=sk-ant-...        # read into /run/secrets, not the env
cd /path/to/your/workspace
agentcontainer run -d -c /path/to/examples/claude-agent/agentcontainer.json
```

### Two ways to drive it

**Interactive — "Claude Code as normal":**

```sh
agentcontainer exec -it claude-agent -- claude
```

A TTY-attached Claude session. You drive it; every Bash command it proposes is
checked by the guard first. Because the exec'd process joins the container's
cgroup, the egress allowlist and the PreToolUse hook apply exactly as they do to
the main process.

**Auto investigation — headless:**

```sh
agentcontainer exec claude-agent -- claude -p "Triage the artifacts in /workspace and summarize."
```

Same enforcement, no human at the keyboard for the run itself — but a denied
command still escalates to whoever is watching `guard serve`.

## Verifying the guard

Inside a session, ask Claude to run `curl https://example.com`. The hook denies
it with *"binary 'curl' is blocked by security policy and cannot be overridden"*,
and the attempt is recorded in the host audit chain
(`~/.ac/audit/<session>.jsonl`, hash-linked). A benign `ls` passes straight
through.

## uid alignment

The guard socket is created `0600`, owned by the host user running `guard serve`.
The container runs as uid 1000 (the node base image's `node` user). When those
uids match, the socket is accessible across the bind mount. If your host uid is
not 1000, either run `guard serve` as a uid-1000 user, or relax the socket's
permissions for the demo. (Making the socket mode/group configurable on the
`Listener` is tracked as a follow-up.)

## Notes

- `HOME=/workspace` because the enforcer mounts the rootfs read-only; Claude's
  config and session history live in `/workspace/.claude`, co-located with the
  work (handy for a forensic case directory).
- `agentcontainer run -d` overrides the image entrypoint with `sleep infinity`
  to hold the container open for `exec`; Claude is started on demand.
