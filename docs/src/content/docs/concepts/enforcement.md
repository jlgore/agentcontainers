---
title: Enforcement
description: Defense-in-depth security model with BPF LSM hooks, network enforcement, and credential gating.
---

agentcontainers uses a defense-in-depth approach with multiple enforcement layers. Even if one layer is bypassed, the others catch the violation.

## Enforcement layers

### Layer 1: Container isolation

Standard OCI container hardening:
- Dropped Linux capabilities (only declared caps retained)
- seccomp syscall filtering
- Read-only root filesystem
- No access to host credential stores

### Layer 2: Network enforcement

BPF cgroup hooks gate all network egress at the kernel level:

| Hook | Protocol | Purpose |
|---|---|---|
| `connect4` | TCP (IPv4) | Gate outbound TCP connections |
| `connect6` | TCP (IPv6) | Gate outbound TCP connections |
| `sendmsg4` | UDP (IPv4) | Gate UDP datagram sends |
| `sendmsg6` | UDP (IPv6) | Gate UDP datagram sends |

All protocols are enforced. Unlike Docker's proxy-based enforcement (gVisor netstack), BPF hooks cannot be bypassed via unbound UDP exfiltration.

Allowed endpoints are declared in `agent.capabilities.network`:

```jsonc
{
  "agent": {
    "capabilities": {
      "network": {
        "allow": [
          "api.github.com:443",
          "registry.npmjs.org:443"
        ]
      }
    }
  }
}
```

### Layer 3: Filesystem enforcement

The BPF LSM `file_open` hook enforces inode-level access control:

- **DENIED_INODES**: Explicitly blocked files (e.g., host credential stores)
- **ALLOWED_INODES**: Explicitly permitted files
- **Default deny**: Anything not in the allow list is blocked

Filesystem capabilities are declared in `agent.capabilities.filesystem`:

```jsonc
{
  "agent": {
    "capabilities": {
      "filesystem": {
        "read": ["/workspace/**", "/usr/**"],
        "write": ["/workspace/**", "/tmp/**"],
        "deny": ["/etc/shadow", "/root/.ssh/**"]
      }
    }
  }
}
```

### Layer 4: Process enforcement

The BPF LSM `bprm_check_security` hook authorizes every binary execution in an
enforced cgroup against an allowlist of **executable identities**:

```jsonc
{
  "agent": {
    "capabilities": {
      "shell": {
        "allow": ["git", "npm", "node", "python3"],
        "deny": ["curl", "wget", "sudo", "su"]
      }
    }
  }
}
```

The enforcer resolves each allowed command to its container-namespace
`(device, inode)` before the container is unpaused:

- **Bare command names** (`git`) are resolved against the container's `PATH`
  (falling back to a documented default PATH), matching `execvp` semantics.
- **Absolute paths** (`/usr/bin/git`) are resolved directly.
- **Shebang scripts** also allowlist their interpreter, since the kernel execs
  the interpreter.
- An executable that cannot be resolved to a real file **aborts startup** — it
  is never silently skipped, since that would leave it un-runnable with no signal.

`bprm_check` is **default-deny and fail-closed**: an execution is permitted only
when its `(device, inode, cgroup)` is in the allowlist. Anything else — an
unlisted binary, an inode that replaced an allowed path, or any failure to read
the executable's identity for an enforced process — is denied (`-EACCES`). An
**empty allowlist therefore denies all new executions**, so process enforcement
requires the shell capability to enumerate every binary the container runs. Both
allowed and denied attempts are audited to `PROC_EVENTS`.

This layer authorizes **executable identity** — *which binary* may run. It does
not inspect command arguments; argument-level policy (e.g. blocking
`python3 -c '...'` interpreter injection) is the [guard layer's](/concepts/architecture/)
responsibility.

### Layer 5: Credential enforcement (CREDLSM)

The BPF LSM `file_open` hook includes a `SECRET_ACLS` map that gates per-cgroup access to secret files:

- Each secret file's inode is registered with `(inode, device, cgroup_id)` as the key
- The ACL value includes TTL expiry (`expires_at_ns`) and permission flags
- If a cgroup has no ACL entry for a secret file, access is denied
- If the TTL has expired, access is denied
- Write access to secrets is always denied unless explicitly permitted

Block reasons are tracked:
- **No ACL entry**: The cgroup is not authorized for this secret
- **TTL expired**: The credential has expired and needs rotation
- **Write denied**: Write access to credential files is blocked

Credential events are emitted to a dedicated `CRED_EVENTS` ring buffer for audit logging.

#### Atomic, fail-closed secret bootstrap

Secrets are injected and gated while the container is **paused**, so it never
runs for a single instruction with an injected-but-ungated secret. The Docker
runtime bootstraps in strict order:

```
start → pause → register + base policy → inject secrets → install credential ACLs → unpause
```

Each secret is injected to `/run/secrets/<name>` and its ACL keys off that
container path (never the provider lookup path). Because the ACL is installed
only after the file exists, the enforcer can resolve the secret's inode; a path
that cannot be resolved is a **fatal** error, never a silent skip. Any
failure — pause, inject, ACL install, or unpause — tears the container down
without ever unpausing it, so a partially-enforced container is never left
running.

#### Per-tool secret restrictions

A secret may be scoped to specific MCP tools via `allowedTools`:

- **Empty `allowedTools`** — container-wide: any code in the cgroup may read the
  secret (subject to TTL and write rules).
- **Non-empty `allowedTools`** — restricted: the secret is readable **only while
  one of its allowed tools has an active tool-call window**.

The kernel enforces this through two maps: `SECRET_TOOL_ACLS` records which tool
identities may read each restricted secret, and `ACTIVE_TOOL` records the tool
identity currently executing in each cgroup. `PrepareToolCall` writes the active
tool and `CompleteToolCall` clears it (including on tool error or cancellation).
The `file_open` hook denies a restricted secret when there is no active window,
or when the active tool is not in the secret's allow-set.

Restricted MCP servers are **serialized**: only one tool call may be active at a
time, so the active-tool identity is unambiguous. `PrepareToolCall` rejects an
overlapping call, and a configuration that pairs a restricted secret with
`maxConcurrentTools > 1` is rejected at startup.

**Limitation — same-process attribution.** The active-tool window is per-cgroup,
not per-thread. Any code running in the MCP server's container during an allowed
tool's window can read the secret, including other code in the same server
process. Restriction is at the granularity of the tool-call window, not the
individual call stack.

### Layer 6: Approval broker

The approval broker wraps the container runtime (decorator pattern) and intercepts capability changes. When an agent requests a capability not declared in the original config, the broker:

1. Pauses the request
2. Shows the user a diff of what changed
3. Waits for explicit approval
4. Only then applies the capability change

This is the human-in-the-loop layer for runtime escalation.

## Enforcement strategy

The enforcer uses a **gRPC sidecar** architecture:

```
agentcontainer runtime ──gRPC──► agentcontainer-enforcer sidecar ──BPF──► kernel
```

- The Go runtime sends policy via gRPC to the Rust enforcer sidecar
- The enforcer attaches Aya BPF programs to the container's cgroup
- All enforcement happens at the kernel level (no userspace bypass)
- The enforcer is fail-closed: if it cannot start, the session fails

There is no in-process BPF and no iptables/nftables. The sidecar model ensures:
- The BPF programs run with the minimum required privileges
- The agent container has no access to the enforcement mechanism
- Policy updates are applied atomically via gRPC `Apply` calls

### Control-plane security

The gRPC channel between the runtime and the enforcer is the control plane: it
carries policy and secret material, so it is authenticated and confined by
default.

- **Loopback only.** A managed sidecar publishes its gRPC port on `127.0.0.1`,
  never on `0.0.0.0`, so it is not reachable from off-host.
- **Ephemeral mutual TLS.** At startup the enforcer generates a self-signed CA
  and a server/client certificate pair (`--creds-dir`). The runtime retrieves
  the client certificate over the Docker API and presents it on every RPC,
  including health probes. Credentials live only for the session.
- **Explicit profiles.** The endpoint and its certificates are threaded
  directly into each client (runtime, MCP proxy, health probe) rather than
  through `AC_ENFORCER_*` process-global environment variables.
- **No silent downgrade.** TLS is required for any non-loopback endpoint.
  Plaintext is permitted only for loopback, or for a non-loopback endpoint when
  the operator sets the development-only `enforcer.insecureDev` opt-in (which
  logs a prominent warning). A credentialed profile is never downgraded to
  plaintext.

This applies to both the host Docker runtime and the per-VM enforcer in
[Sandbox mode](#enforcement-in-sandbox-mode); the Sandbox retrieves the in-VM
enforcer's credentials the same way, over its private Docker socket.

## Stats and audit

The enforcer tracks per-cgroup statistics:

| Counter | Description |
|---|---|
| `network_allowed` | Network connections permitted |
| `network_blocked` | Network connections denied |
| `filesystem_allowed` | File opens permitted |
| `filesystem_blocked` | File opens denied |
| `process_allowed` | Process executions permitted |
| `process_blocked` | Process executions denied |
| `credential_allowed` | Secret file reads permitted |
| `credential_blocked` | Secret file reads denied |

Events are emitted to per-domain ring buffers (`NET_EVENTS`, `FS_EVENTS`, `PROC_EVENTS`, `CRED_EVENTS`) for real-time audit logging.

View enforcement stats:

```bash
agentcontainer enforcer status
agentcontainer enforcer diagnose
agentcontainer audit events
agentcontainer audit summary
```

## Enforcement in Sandbox mode

When using Docker Sandbox (microVM), **both** enforcement layers are active:

1. **Docker's proxy enforcement** (gVisor netstack `ProxyEnforcingDialer`) provides coarse-grained network control
2. **BPF enforcer inside the VM** provides precise, kernel-level enforcement with no bypasses

The BPF enforcer runs inside the Sandbox VM, not on the host. This provides defense-in-depth: the proxy catches most violations, and the BPF hooks catch anything that slips through (including unbound UDP exfiltration).
