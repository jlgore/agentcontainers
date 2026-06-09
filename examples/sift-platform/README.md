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

This example wires the gateway as a **`type: remote`** MCP backend for
simplicity, but `container` + `http` is also supported by the MCP proxy and
gives the gateway kernel enforcement — see the alternative below.

One thing to know about a plain Docker **Engine** host (no Docker Desktop): the
in-`run` container-MCP path is only wired by the **sandbox** runtime, which
needs Docker Desktop's `sandboxd` (a microVM backend); on Docker Engine
`--runtime sandbox` fails with `dial unix .../sandboxd.sock: no such file`. The
MCP proxy (`agentcontainer mcp start`) does not need the sandbox runtime — it
launches container backends directly via the Docker API.

**Remote (this example):** the gateway runs as a standalone container and the
proxy connects to its HTTP endpoint as a remote backend. Simple, but the gateway
itself is not registered with the enforcer.

**Container + http (kernel-enforced):** point the tool at the image instead of a
URL and the proxy launches the gateway container, registers its cgroup with the
eBPF enforcer (network/file/process policy on BPF maps), and connects over HTTP
on the per-session bridge network:

```jsonc
"sift": {
  "type": "container",
  "image": "sift-gateway:demo",
  "transport": "http",
  "port": 4508,
  "path": "/mcp"
}
```

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

The whole lifecycle is scripted (idempotent). `up.sh` builds the image if
needed, starts the hardened gateway, runs the agent under enforcement, and
starts the MCP proxy:

```bash
./up.sh       # build (if needed) + gateway + agent + proxy
./down.sh     # tear it all down
```

`up.sh` prints the endpoints and how to `agentcontainer exec sift-agent`. From a
freshly bootstrapped host you can also do it in one shot:

```bash
sudo ./scripts/bootstrap.sh --with-sift-demo   # host setup, then up.sh
```

<details><summary>The equivalent manual steps</summary>

```bash
docker run -d --name sift-gateway \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /run/secrets:rw,exec -p 4508:4508 sift-gateway:demo
agentcontainer run -d                  # agent under enforcement
agentcontainer mcp start --port 4510   # proxy: "Backends: sift", 49 tools
```
</details>

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
