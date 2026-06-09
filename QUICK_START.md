# Quick Start

Get `agentcontainers` running on a fresh Linux host and bring up a real agent —
plus the SIFT forensic platform — under eBPF + human-in-the-loop enforcement.

Two layers, kept separate:

1. **`scripts/bootstrap.sh`** — makes a bare host ready (Docker, Go + the CLI,
   signing tools, the enforcer image, and the BPF LSM).
2. **`examples/sift-platform/up.sh` / `down.sh`** — builds and runs the demo
   (the SIFT forensic MCP platform behind one endpoint, under enforcement).

---

## Prerequisites

A fresh **Ubuntu 22.04 / 24.04** host (amd64), with:

- a sudo-capable user
- `cgroup v2` (default on 22.04+)
- a kernel built with `CONFIG_BPF_LSM=y` (Ubuntu's stock kernels are) — the
  bootstrap turns it on
- outbound network to `ghcr.io`, `mcr.microsoft.com`, Docker Hub, and `go.dev`

Everything else (Docker, Go, cosign/crane) is installed by the bootstrap if
missing. Validated on Ubuntu 24.04 / Docker Engine 29.

> **Architecture:** amd64 only for now. The enforcer image and the demo are
> built for `linux/amd64`; arm64 needs the cross toolchain re-enabled (see
> *Maintainer notes*).

---

## TL;DR — one command

```bash
git clone https://github.com/jlgore/agentcontainers.git
cd agentcontainers
sudo ./scripts/bootstrap.sh --with-sift-demo
#   ... configures the BPF LSM, then asks you to reboot ...
sudo reboot
# after reboot:
cd agentcontainers
sudo ./scripts/bootstrap.sh --with-sift-demo
```

The second run finishes setup and brings the SIFT platform up under enforcement.
That's it — skip to [Verify enforcement](#verify-enforcement).

---

## Step by step

### 1. Bootstrap the host

```bash
sudo ./scripts/bootstrap.sh
```

It is **idempotent and reboot-aware**. Phases:

| Phase | What it does |
|-------|--------------|
| Preflight | asserts OS / arch / cgroup-v2 / connectivity |
| Base utils | `curl`, `ca-certificates`, `jq`, `tar` |
| Docker | installs Engine if absent; adds your user to the `docker` group |
| Go + CLI | installs the Go version from `go.mod`, builds `agentcontainer` → `/usr/local/bin` |
| Signing tools | `cosign` + `crane` (optional — for `sign`/`verify`/`attest`) |
| BPF LSM | appends `bpf` to the kernel `lsm=` list via GRUB, then **stops for reboot** |
| Enforcer image | pulls the enforcer image and re-tags it to the reference the CLI expects |
| Smoke test | starts the enforcer, health-checks it, stops it |

Useful flags:

```bash
sudo ./scripts/bootstrap.sh \
  --enforcer-image ghcr.io/<you>/agentcontainer-enforcer:latest \  # override the image
  --with-sift-demo \        # also run examples/sift-platform/up.sh when ready
  --skip-lsm \              # network+DNS enforcement only; no GRUB change / reboot
  --skip-enforcer-image \   # don't pull/tag the enforcer (e.g. not published yet)
  --skip-signing-tools \    # don't install cosign/crane
  --skip-smoke              # don't run the enforcer smoke test
```

Env: `ENFORCER_IMAGE`, and `GHCR_TOKEN` (+`GHCR_USER`) if the enforcer package is
private.

### 2. Reboot to activate the BPF LSM

The first run edits `/etc/default/grub` (backup saved alongside) so the kernel
boots with `lsm=...,bpf`. Reboot, then **re-run the same command** — it detects
`bpf` is now active and continues past the GRUB phase.

```bash
sudo reboot
```

Without this, `file_open` / `bprm_check` credential gating self-skips and you get
network + DNS enforcement only. (Use `--skip-lsm` if that's all you want.)

### 3. Bring up the SIFT platform demo

If you didn't pass `--with-sift-demo`, run it directly:

```bash
cd examples/sift-platform
./up.sh        # build (if needed) + gateway + agent + proxy
./down.sh      # tear it all down
```

`up.sh` is idempotent. It builds `sift-gateway:demo` from mainline
[`AppliedIR/sift-mcp`](https://github.com/AppliedIR/sift-mcp) (the first build
clones upstream + `vhir-cli` and takes a few minutes), starts the hardened
gateway, runs the agent under enforcement, and starts the MCP proxy aggregating
the **49 SIFT tools** with policy / approval / audit.

---

## Verify enforcement

```bash
agentcontainer ps                 # the agent + enforcer containers
agentcontainer enforcer status    # SERVING at 127.0.0.1:50051
```

The enforcer log shows the agent's cgroup registered and policy applied to BPF
maps:

```
registering cgroup for BPF enforcement ... cgroup_id=...
applying network policy ... hosts=["api.github.com"]
added CIDR to BLOCKED_CIDRS_V4 cidr=169.254.169.254/32   # cloud-metadata SSRF block
applying filesystem policy to BPF maps ...
```

Three enforcement layers you can observe:

- **Kernel network egress** — the agent's allowlist is `api.github.com:443`, so
  DNS (port 53) is itself denied; outbound connects fail *instantly* (EPERM,
  not a timeout).
- **Approval broker** — ungranted shell commands prompt and deny; `bash -c` is
  rejected as an interpreter escape:
  ```
  agentcontainer exec sift-agent -- curl https://example.com   # -> Capability Request -> denied
  ```
- **Enforcer sidecar** — fail-closed: no healthy enforcer, no container start.

---

## Two ways to host the SIFT platform

The gateway is an **HTTP** MCP server. The proxy (`agentcontainer mcp start`) can
attach it two ways:

| Mode | Config | Enforcement | Use when |
|------|--------|-------------|----------|
| **remote** (default in the example) | `type: remote`, `url: http://localhost:4508/mcp` | proxy policy/approval/audit only | simplest; gateway runs as a plain container you manage |
| **container + http** | `type: container`, `image`, `transport: http`, `port`, `path` | **+ kernel netpolicy on the gateway's own cgroup** | you want the gateway itself eBPF-enforced |

Container + http example:

```jsonc
"sift": {
  "type": "container",
  "image": "sift-gateway:demo",
  "transport": "http",
  "port": 4508,
  "path": "/mcp"
}
```

Here the proxy launches the container, **registers its cgroup with the
enforcer**, applies network policy to BPF maps, and connects over HTTP on the
per-session bridge network. `mcp start` requires the enforcer for container
backends (or set `agent.enforcer.required: false`).

> **Note:** the in-`run` container-MCP path needs the **sandbox** runtime
> (Docker Desktop `sandboxd`); on plain Docker **Engine**, use the MCP proxy
> (`mcp start`) — it launches container backends directly via the Docker API.

---

## How it's wired

```
            agentcontainer mcp start  (proxy: policy / approval / audit)
                       │  remote URL  OR  container+http (kernel-enforced)
                       ▼
   sift-gateway  ──┬─▶ forensic-mcp   (stdio subprocess)
   (HTTP :4508)    ├─▶ sift-mcp
                   ├─▶ case-mcp
                   └─▶ report-mcp        49 tools total

   agent container ── registered with the eBPF enforcer
                      (cgroup connect4/6, file_open LSM, process)
```

The gateway image funnels all writes to `/run/secrets` so it runs cleanly under
the hardened MCP-sidecar profile (read-only rootfs, all caps dropped).

---

## Common commands

```bash
agentcontainer init                       # scaffold an agentcontainer.json
agentcontainer run -d                     # start an agent (enforcer auto-starts)
agentcontainer exec <name> -- <cmd>       # run inside, gated by the approval broker
agentcontainer ps | logs | stop <name>    # lifecycle
agentcontainer enforcer start|status|diagnose|stop
agentcontainer mcp start --port 4510      # MCP proxy fronting configured servers
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `enforcer image unavailable` during bootstrap | the fork package isn't published/public yet — see *Maintainer notes*, or `--skip-enforcer-image` to defer |
| `docker: permission denied` | log out/in (or `newgrp docker`) so the `docker` group takes effect |
| BPF LSM still inactive after reboot | `cat /sys/kernel/security/lsm` should include `bpf`; check `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, re-run `sudo update-grub`, reboot |
| `--runtime sandbox` → `sandboxd.sock: no such file` | expected on Docker Engine; use the MCP proxy path instead |
| agent can't resolve any host | working as intended — DNS egress is blocked unless the resolver/port is in the allowlist |
| first `up.sh` build is slow | it clones upstream + builds the Rust-free Python image once; subsequent runs reuse it |

---

## Maintainer notes

### Publishing the enforcer image (fork)

The enforcer is a Rust + Aya eBPF sidecar built and pushed by CI:

- `.github/workflows/docker.yml` publishes to
  `ghcr.io/${{ github.repository_owner }}/agentcontainer-enforcer` on pushes
  touching `enforcer/**` or the workflow itself.
- It builds **amd64-only** (the arm64 cross-build needs `gcc-aarch64-linux-gnu`
  + a target `CC` in `enforcer/Dockerfile`).
- After the first publish, make the GHCR package **public** so hosts pull
  anonymously — otherwise set `GHCR_TOKEN` when bootstrapping.

The bootstrap pulls the fork image and re-tags it to the upstream default
reference the stock CLI looks for, so no code change is needed to use a fork.

### Fixes carried in this fork

- **`fix(oci)`** — `fetchManifest` resolves multi-arch image indexes (advertises
  the index media types, follows the host-platform entry). Without it,
  org-policy extraction 404s on any multi-arch base-image tag.
- **`feat(mcpproxy)`** — `container` + `http` backends: the proxy launches an
  HTTP MCP server as a kernel-enforced container (`dialHTTPContainer`), not just
  `type: remote`.

Both are self-contained on the `bug/fetchManifest` and `bug/container-http`
branches if you want to rework them into upstream PRs.
