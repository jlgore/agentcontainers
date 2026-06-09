# SIFT forensic platform under agentcontainers enforcement

Runs an agent under agentcontainers enforcement with the mainline
[AppliedIR/sift-mcp](https://github.com/AppliedIR/sift-mcp) forensic platform
(49 tools across `forensic-mcp`, `sift-mcp`, `case-mcp`, `report-mcp`) attached
through the agentcontainers MCP proxy.

## Architecture

`sift-gateway` is the upstream HTTP gateway that aggregates the SIFT-local MCP
servers behind one endpoint. This example packages it into a container image and
attaches it to the agent:

```
            agentcontainers MCP proxy (policy / approval / audit)
                       │  type: remote (Streamable HTTP)
                       ▼
   sift-gateway:demo  ──┬─▶ forensic-mcp   (stdio subprocess)
   (HTTP :4508)         ├─▶ sift-mcp
                        ├─▶ case-mcp
                        └─▶ report-mcp        49 tools total

   agent container ── registered with the eBPF enforcer (cgroup connect4/6,
                      file_open LSM, process) ── network egress allowlist applied
```

## Hosting model: why `remote`, not `container`

The gateway is wired as a **`type: remote`** MCP backend, not `container`. Two
constraints on a plain Docker **Engine** host (no Docker Desktop) force this:

1. The in-`run` container-MCP path is only wired by the **sandbox** runtime,
   which needs Docker Desktop's `sandboxd` (a microVM backend). On Docker Engine
   `--runtime sandbox` fails with `dial unix .../sandboxd.sock: no such file`.
2. The MCP proxy can host container backends only over **stdio** — it explicitly
   rejects `container` + `http` (*"transport http is not yet implemented (use
   type remote for HTTP endpoints)"*, `internal/mcpproxy/transport.go`). The
   gateway is HTTP.

So the gateway runs as a standalone container and the proxy connects to its HTTP
endpoint as a remote backend. (For a kernel-enforced *container* MCP tool on
Engine, host an individual **stdio** server as `type: container` instead — the
proxy `docker run`s it and registers its cgroup with the enforcer.)

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Builds `sift-gateway:demo` from mainline sift-mcp + vhir-cli |
| `gateway.docker.yaml` | Gateway config: core local backends, auth disabled (single-user) |
| `entrypoint.sh` | Creates writable dirs under `/run/secrets` and launches the gateway |
| `build.sh` | Clones upstream and builds the image |
| `agentcontainer.json` | The agent + the `sift` remote MCP tool + egress/filesystem policy |

The image still runs cleanly under the hardened MCP-sidecar profile (read-only
rootfs, all caps dropped, only `/run/secrets` writable) — every mutable path is
funneled to `/run/secrets` and `.pyc` writes are disabled.

## Build

```bash
./build.sh                 # -> sift-gateway:demo  (~128 MB)
```

## Run

```bash
# 1. Start the gateway (hardened, host port 4508).
docker run -d --name sift-gateway \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /run/secrets:rw,exec -p 4508:4508 sift-gateway:demo

# 2. Start the agent under enforcement (Docker runtime; enforcer auto-starts).
agentcontainer run -d

# 3. Front the SIFT platform through the agentcontainers proxy (different port;
#    the gateway already uses 4508).
agentcontainer mcp start --port 4510
#    -> "Backends: sift", and the 49 SIFT tools are proxied with policy/audit.

agentcontainer stop sift-agent
docker rm -f sift-gateway
```

## What this demonstrates (validated on Ubuntu 24.04 / Docker Engine)

- The mainline SIFT platform runs containerized under the hardened sidecar
  profile and serves **49 tools** across 4 backends.
- The agentcontainers MCP proxy aggregates it (`Backends: sift`) with a hash-
  chained audit log.
- The agent runs under live BPF enforcement: the enforcer registers the agent's
  cgroup and applies the egress allowlist (`hosts=["api.github.com"]`), blocks
  the cloud-metadata IP (`169.254.169.254/32`), and applies filesystem/process
  policy to BPF maps. With only `api.github.com:443` allowed, DNS egress is
  itself denied (instant connection refusal, not a timeout).
- The approval broker denies ungranted shell commands and rejects interpreter
  escapes (`bash -c`).

## Notes

- Forensic tool *execution* (the real SIFT binaries) is not installed — servers
  start with deferred tools and report availability; this demonstrates the
  platform and enforcement, not full tool execution.
- Disabled upstream backends: `forensic-rag` (heavy ML), `windows-triage`,
  `opencti`, and remote HTTP backends (need external services/credentials).
  Re-enable in `gateway.docker.yaml` (and install the packages in the
  `Dockerfile`).
