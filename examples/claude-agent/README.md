# claude-agent — Claude Code under zero-trust enforcement

Run Claude Code itself inside an agentcontainers-enforced container, with its
**own** tool calls gated by the same OPA policy and human-in-the-loop approval
that gate the MCP forensic tools.

Three layers wrap the agent:

| Layer | Mechanism | Stops |
|-------|-----------|-------|
| **Tool policy** | PreToolUse hook → host `guard serve` → OPA + HITL | `curl`, `bash -c`, `rm -rf /`, shell metacharacters, blocked dirs — with a human-readable reason and an approval escalation |
| **Network** | eBPF egress allowlist (kernel) | any connection except `api.anthropic.com:443` |
| **Auth** | OAuth token, or API key injected into `/run/secrets` | credentials kept out of the image and (for the API key) out of the agent's environment |

The decision authority is **out-of-band**: `guard serve` runs on the host. The
in-container hook only carries a request over a bind-mounted unix socket and
renders the verdict — it cannot allow what the host denies, and the agent cannot
edit the hook (it lives in root-owned `/etc/claude-code/managed-settings.json`,
Claude Code's highest-precedence settings source). The managed settings carry
**only** the hook; auth is supplied per deployment so it stays flexible.

This directory builds **one image** and offers **two auth examples**:

- [`oauth/`](oauth/) — authenticate with an OAuth token (`claude setup-token`)
- [`apikey/`](apikey/) — authenticate with a regular API key via the native
  `/run/secrets` secret mechanism

## Prerequisites

- Docker, and the agentcontainers enforcer image available locally.
- The `agentcontainer` binary on the host (with the `guard` subcommand, and the
  enforcer build that injects secrets — see *Enforcer requirements* below).
- The host user running `guard serve` should have **uid 1000** (the image runs
  as uid 1000; see *uid alignment*).

## Build & publish the image

```sh
examples/claude-agent/build.sh ghcr.io/<you>/claude-agent:demo
docker push ghcr.io/<you>/claude-agent:demo     # make the package public
```

`agentcontainer run` extracts the image's org-policy layer over HTTPS from a
registry, so the image must be pushed (a local-only image is rejected). Point the
`image` field in each example's `agentcontainer.json` at your reference.

## Start the host guard (both examples)

```sh
sudo mkdir -p /run/ac && sudo chown "$(id -u):$(id -g)" /run/ac
agentcontainer guard serve \
  --socket /run/ac/guard.sock \
  --security-yaml examples/sift-platform/guard.security.yaml &
```

Leave it running; denials prompt here (or approve from another terminal with
`agentcontainer approve`).

---

## OAuth example

Generate a long-lived token, then run the agent and supply the token at exec
time (it never touches the image, the config, or `/run/secrets`):

```sh
claude setup-token                       # → sk-ant-oat01-...

cd /path/to/your/workspace
agentcontainer run -d -c /path/to/examples/claude-agent/oauth/agentcontainer.json

agentcontainer exec -it \
  -e CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-... \
  -e TMPDIR=/workspace/.tmp \
  claude-agent-oauth -- claude
```

`-e` resolves secret URIs host-side, so you can keep the token in a manager:
`-e CLAUDE_CODE_OAUTH_TOKEN=op://vault/claude/token`.

> The image's managed settings deliberately do **not** set `apiKeyHelper` — a
> managed `apiKeyHelper` takes precedence over `CLAUDE_CODE_OAUTH_TOKEN` and
> would silently break OAuth.

## API-key example

The key is injected into `/run/secrets` by the enforcer (chowned to the agent's
uid) and read via `apiKeyHelper`. Drop the provided settings into your workspace
so Claude knows to call the helper:

```sh
cd /path/to/your/workspace
mkdir -p .claude && cp /path/to/examples/claude-agent/apikey/claude-settings.json .claude/settings.json

export ANTHROPIC_API_KEY=sk-ant-api03-...      # read into /run/secrets, not the agent env
agentcontainer run -d -c /path/to/examples/claude-agent/apikey/agentcontainer.json

agentcontainer exec -it -e TMPDIR=/workspace/.tmp claude-agent-apikey -- claude
```

Swap the secret `provider` in `apikey/agentcontainer.json` for
`vault`/`op`/`infisical`/`oidc` in production — the agent never sees the key in
its environment either way.

---

## Two ways to drive either example

**Interactive** — `agentcontainer exec -it … -- claude` (a TTY session you drive).

**Headless** — `agentcontainer exec -i … -- claude -p "…" < /dev/null` (an
auto-investigation; redirect stdin or `claude -p` waits on it).

Either way, because the exec'd process joins the container cgroup, the egress
allowlist and the PreToolUse hook gate it exactly as they gate the main process.

## Verifying the guard

Ask Claude to run `curl https://example.com`. The hook denies it
(*"binary 'curl' is blocked by security policy and cannot be overridden"*) and
Claude reports the block; the attempt is recorded in the host audit chain
(`~/.ac/audit/<session>.jsonl`, hash-linked). A benign `ls` passes through.

## Enforcer requirements

The API-key example needs an enforcer build that:

- carries **`CAP_SYS_PTRACE`** — required to inject secrets through the agent's
  `/proc/<pid>/root` under the yama LSM (`ptrace_scope>=1`);
- **chowns** injected secrets to the agent's uid, so the non-root agent can read
  them.

Both are in the enforcer as of this example; rebuild and publish the enforcer
image (`enforcer/Dockerfile`) if you run an older one.

## uid alignment

The guard socket is created `0600`, owned by the host user running `guard serve`,
and injected secrets are chowned to the agent's uid. The container runs as uid
1000 (the node base image's `node` user). When the host `guard serve` user is
also uid 1000, the socket is accessible across the bind mount. If your host uid
differs, run `guard serve` as a uid-1000 user (or relax the socket permissions
for the demo).

## Notes

- `HOME`, `CLAUDE_CONFIG_DIR`, and `TMPDIR` all live under `/workspace` because
  the enforcer mounts the rootfs read-only; the native `claude` binary exits
  silently if `TMPDIR` is not writable, hence the explicit `-e TMPDIR=…`.
- `agentcontainer run -d` overrides the image entrypoint with `sleep infinity`
  to hold the container open for `exec`; Claude is started on demand.
