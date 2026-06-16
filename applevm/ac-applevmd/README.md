# ac-applevmd

A helper daemon that boots Linux microVMs via Apple's open-source
[containerization](https://github.com/apple/containerization) library and runs a
private Docker daemon inside each one, exposing its socket back to the host.

It is the open-source counterpart to Docker Desktop's proprietary **sandboxd**.
`ac-applevmd` deliberately speaks the **same HTTP-over-unix-socket contract as
sandboxd**, so the Go `agentcontainers` CLI drives it through the existing
sandbox runtime — see `internal/container/applevm.go` and `internal/applevm` in
this repo. From the CLI's point of view, `--runtime=applevm` and
`--runtime=sandbox` are identical except for which daemon socket they dial.

```
agentcontainer run --runtime=applevm
        │  unix:///~/.agentcontainers/applevm/applevmd.sock
        ▼
   ac-applevmd  ──(Apple containerization)──►  Linux microVM
        │                                          └─ dockerd (docker:dind)
        │  per-VM host unix socket  ◄── TCP proxy ──┘   (TCP :2375 on vmnet IP)
        ▼
   moby Docker client  ──►  agent container created inside the VM
```

## Requirements

- Apple silicon Mac
- **macOS 26** or later, **Xcode 26** (Apple containerization requirement)
- A Linux kernel image for the microVMs (see Configuration)

## Build

```bash
cd applevm/ac-applevmd
swift build -c release
# binary at .build/release/ac-applevmd
```

### Code signing (required)

Any process that uses Virtualization.framework must carry the
`com.apple.security.virtualization` entitlement. Ad-hoc signing is fine for
local development:

```bash
codesign --force --sign - --timestamp=none \
  --entitlements signing/vz.entitlements .build/release/ac-applevmd
```

Re-sign after every rebuild.

## Runtime prerequisites (one-time)

1. **Kernel.** A Linux kernel image for the microVMs. Use the BPF-LSM + BTF
   kernel this repo builds in CI — it's what lets the in-VM enforcer attach its
   eBPF/BPF-LSM hooks (the stock containerization kernel and the Kata kernel both
   lack `CONFIG_BPF_LSM`/BTF, so enforcement degrades to audit-only on them). It
   is attached to each GitHub Release as `vmlinux` (and produced by the
   `applevm-kernel` workflow — see `applevm/kernel/`):

   ```bash
   mkdir -p ~/.agentcontainers/applevm
   gh release download -R jlgore/agentcontainers --pattern vmlinux \
     -O ~/.agentcontainers/applevm/kernel
   ```

   Verify after first boot: `zcat /proc/config.gz | grep -E 'BPF_LSM|DEBUG_INFO_BTF'`
   should show `=y`, and `/sys/kernel/btf/vmlinux` should exist.

   <details><summary>Fallback: the Kata kernel (no BPF-LSM enforcement)</summary>

   ```bash
   curl -SsL -o /tmp/kata.tar.xz \
     https://github.com/kata-containers/kata-containers/releases/download/3.17.0/kata-static-3.17.0-arm64.tar.xz
   tar -xf /tmp/kata.tar.xz -C /tmp
   cp -L /tmp/opt/kata/share/kata-containers/vmlinux.container ~/.agentcontainers/applevm/kernel
   ```
   The VM boots, but the enforcer's BPF programs cannot load (no BTF), so run
   `--runtime=applevm` audit-only.
   </details>

2. **vminit initfs.** Build `vminit:latest` into the local image store from a
   checkout of apple/containerization at the **same revision** this package
   pins (so the guest init matches the host library). This cross-compiles
   `vminitd` via the Swift static Linux SDK — use `swiftly` to get a toolchain
   that matches the SDK version (Xcode's Swift may be a point release ahead and
   fail with a module-version mismatch):

   ```bash
   git clone https://github.com/apple/containerization.git && cd containerization
   git checkout <pinned-revision>           # see Package.resolved
   make -C vminitd cross-prep               # installs swiftly + Swift 6.3.0 + static SDK
   make init                                # builds vminit:latest into the image store
   ```

   Because `ac-applevmd` runs as root (for vmnet, below), load `vminit:latest`
   into **root's** image store — run `make init` (or the `cctl rootfs create`
   step it invokes) under `sudo`.

## Run

`vmnet` networking and Virtualization.framework both require privilege, so run
the daemon as root:

```bash
sudo ./.build/release/ac-applevmd
```

> **Verified end-to-end** on macOS 26.5.1 / Apple M4 / Swift 6.3.2: `POST /vm`
> boots a `docker.io/library/docker:dind` microVM and the bridged socket serves
> a live Docker Engine (29.5.3, linux/arm64, overlayfs).

Configuration (all optional, via environment):

| Variable                | Default                                            | Purpose |
|-------------------------|----------------------------------------------------|---------|
| `AC_APPLEVM_API`        | `~/.agentcontainers/applevm/applevmd.sock`         | Control socket path (must match the Go client). |
| `AC_APPLEVM_KERNEL`     | `~/.agentcontainers/applevm/kernel`                | Linux kernel image for the microVMs. |
| `AC_APPLEVM_DIND_IMAGE` | `docker:dind`                                      | Docker-in-docker workload image run inside each VM. |
| `AC_APPLEVM_STATE`      | `~/.agentcontainers/applevm/vms`                   | Directory for per-VM host sockets. |

Once running, point the CLI at it:

```bash
agentcontainer run    --runtime=applevm
agentcontainer ps     --runtime=applevm
agentcontainer exec   --runtime=applevm -- echo hi
agentcontainer logs   --runtime=applevm
agentcontainer stop   --runtime=applevm
agentcontainer gc     --runtime=applevm
```

## API (sandboxd-shaped)

| Method | Path                      | Purpose |
|--------|---------------------------|---------|
| GET    | `/health`                 | Daemon status. |
| POST   | `/vm`                     | Boot a microVM + dockerd, return its host socket path. |
| GET    | `/vm`                     | List VMs. |
| GET    | `/vm/{name}`              | Inspect a VM (incl. `ip_addresses`). |
| POST   | `/vm/{name}/stop`         | Stop a VM. |
| DELETE | `/vm/{name}`              | Delete a VM. |
| POST   | `/vm/{name}/keepalive`    | Reset idle timeout (no-op in MVP). |
| POST   | `/network/proxyconfig`    | Egress policy (no-op in MVP — see below). |

Request/response JSON shapes match `internal/sandbox/types.go`.

## Status / known limitations (MVP)

This is an initial spike. Parity gaps versus sandboxd, all documented rather than
silently worked around:

1. **No eBPF/BPF-LSM enforcement on the stock kernel.** The kernel shipped with
   containerization (`kernel/config-arm64`) has no `CONFIG_SECURITY`, no
   `CONFIG_BPF_LSM`, and no BTF, so the agentcontainers enforcer cannot attach.
   Run `applevm` at audit/off enforcement for now. Full parity requires a custom
   kernel (`CONFIG_SECURITY=y`, `CONFIG_BPF_LSM=y`, `CONFIG_LSM="...,bpf"`,
   `CONFIG_DEBUG_INFO_BTF=y`) supplied via `AC_APPLEVM_KERNEL` — a follow-up.
2. **No MITM egress proxy.** `/network/proxyconfig` is accepted but is a no-op,
   and `ca_cert_data` is returned empty (the Go side then skips CA injection).
   Network egress policy is a follow-up.
3. **Credential / service-auth injection** fields on `POST /vm` are accepted but
   not yet enforced.
4. **Docker exposure.** dockerd is reached over TCP `:2375` on the VM's vmnet
   interface and bridged to a host unix socket. A more locked-down design keeps
   dockerd on a vsock port and bridges via `LinuxContainer.dialVsock(port:)`;
   left as a follow-up.

## Source layout

| File              | Responsibility |
|-------------------|----------------|
| `main.swift`      | Entry point, env configuration. |
| `HTTPServer.swift`| SwiftNIO HTTP/1 server over the unix socket. |
| `Router.swift`    | Method+path → `VMManager` dispatch, JSON encoding. |
| `VMManager.swift` | microVM lifecycle via containerization; the host-socket bridges. |
| `SocketBridge.swift` | host unix socket → in-VM dockerd TCP proxy. |
| `Models.swift`    | Codable wire models (mirror `internal/sandbox/types.go`). |

> **Note for implementers:** lines marked `// VERIFY:` in `VMManager.swift` use
> containerization API surface (kernel/manager construction, interface IP
> resolution, container stop) whose exact signatures shift between library
> releases. Check them against the installed version when you first
> `swift build` on a Mac.
