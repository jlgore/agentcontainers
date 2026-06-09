# agentcontainers fork — MCP-Aware Enforcement Runtime (v4)

**Status:** Spec (not built yet)
**Author:** Jared Gore
**Base:** Fork of [kubedoll-heavy-industries/agentcontainers](https://github.com/kubedoll-heavy-industries/agentcontainers) v0.1.0-alpha.3
**License:** Apache-2.0 (inherited)
**Revision:** v6 — Phase 1 as-built amendments: official `modelcontextprotocol/go-sdk`
for MCP transport (replaces hand-rolled note); resources + prompts passthrough in
Phase 1 scope; audit dir stays `~/.ac/audit` with `AC_AUDIT_DIR` override; tool-name
collisions are a startup error; container-`http` transport deferred to Phase 3;
audit entries carry a hash-scheme version field for legacy-log compat. (v5: `type:
"remote"`, per-type field allowlists; PoC framing: upstream changes carried as
fork-local patches, PRs deferred until concept proven)

---

## 1. What This Fork Adds

One new component — an **MCP reverse proxy** — and targeted extensions to
the existing agentcontainer runtime so its per-container enforcement
(approval broker, eBPF enforcer, OCI verifier) applies to MCP server
containers with tool-call-level granularity.

The proxy intercepts `tools/call` JSON-RPC messages, evaluates policy on
the host (in the TCB), and either forwards to the backend or returns a
structured denial. Each backend MCP server runs in its own OCI container
with its own cgroup. The eBPF enforcer already registers containers and
returns cgroup IDs; this fork rekeys the global network and filesystem
maps to per-cgroup scope and adds two new RPCs (`PrepareToolCall` /
`CompleteToolCall`) for tool-call correlation.

Audit events are appended to JSONL files with hash chains (reusing the
upstream `internal/audit/` format). DuckDB reads them at query time for
correlation. No daemon, no database, no schema to manage.

---

## 2. Trust Model

```
TRUSTED (host)
├── agentcontainer CLI
├── MCP proxy (policy evaluation, approval broker)
├── agentcontainer-enforcer sidecar (Rust + Aya eBPF)
└── Audit JSONL files (written by CLI-side stream consumer)

UNTRUSTED (containers)
├── MCP Server A (e.g. sift-mcp) — own cgroup, own BPF maps
├── MCP Server B (e.g. wintools-mcp) — own cgroup, own BPF maps
├── WASM Component tools — hosted in enforcer sandbox
└── Agent process (if containerized)

REMOTE (no container lifecycle, proxy-only enforcement)
├── type: "remote" MCP servers accessed via URL (e.g. wintools-mcp on Windows)
```

Policy evaluation runs on the host. A compromised MCP server cannot
tamper with its own policy. The CLI-side process writes all three audit
files — one trust domain, one writer, no volume-mounting audit
directories into sidecars. Remote servers get proxy-level policy
enforcement but no kernel-level eBPF (no cgroup to attach to).

---

## 3. Components

### 3.1 MCP Proxy

**What:** A Go process that speaks MCP Streamable HTTP on the client side
and connects to backend MCP servers via stdio (attached containers),
HTTP (Compose services or remote servers), or gRPC (WASM components via
the enforcer). One proxy, N backends.

**Where:** `internal/mcpproxy/`

**Responsibilities:**

1. Accept MCP Streamable HTTP connections from LLM clients on a
   configurable port (default `:4508`).
2. Start backend servers based on transport mode:
   - `transport: "stdio"` — launch container directly via Docker API
     with attached stdin/stdout streams, joined to the
     `ac-mcp-<session>` network for secrets/isolation. NOT managed by
     Compose (Compose services are detached; you can't cleanly hold
     stdin pipes on a Compose-managed container). Use
     `MCPServiceConfig` from `mcp_isolation.go` for the
     network/secrets/policy spec, but diverge on container lifecycle.
     The container's cgroup does not exist until it starts, so the
     proxy freezes it (`ContainerPause`) the instant after start,
     registers + applies kernel policy while frozen, then unfreezes
     before the MCP handshake — enforcement is in place before the
     server handles anything. Docker has no atomic start-frozen, so
     the brief Start→Pause interval runs unenforced (best-effort; if
     the freezer is unavailable the pause is skipped with a warning).
   - `transport: "http"` with `image` — launch as a Compose service
     via the existing `GenerateMCPServices` path. Proxy connects via
     HTTP over the `ac-mcp-<session>` bridge network.
   - `type: "remote"` — no container lifecycle. Proxy connects
     directly to the declared `url`. Proxy-only enforcement.
   - `type: "component"` — WASM tools hosted by the enforcer. Proxy
     routes `tools/call` to the enforcer's existing `CallTool` gRPC
     endpoint.

   Transport/lifecycle selection is a `switch` on `type` (+ `transport`
   for containers) — no inference from which optional fields are set.
3. On `tools/call`: extract tool name + arguments, build a policy input
   document, evaluate against the compiled policy for that server. If
   denied, return an MCP `tools/call` result with `isError: true` and
   structured reasons. If allowed, call `PrepareToolCall` on the
   enforcer (for container servers), forward to the backend, relay the
   response, then call `CompleteToolCall`.
4. On `tools/list`: aggregate tool lists from all backends (container
   servers, remote servers, AND WASM components via enforcer
   `ListTools`), filtered by each server's `allowedTools` policy.
   Re-fetch on `notifications/tools/list_changed` from any backend.
5. **Bidirectional relay:** pass through all server→client messages
   (notifications, progress, sampling requests, elicitation) unmodified.
   Only `tools/call` is policy-gated.
6. **Serialization:** serialize `tools/call` per server by default
   (`maxConcurrentTools: 1`). Configurable per server via
   `policy.maxConcurrentTools`. This avoids kernel-level correlation
   ambiguity (§3.3) and matches forensic workflow patterns.
7. Emit JSONL audit events for every tool call.
8. Call `PrepareToolCall` before forwarding, `CompleteToolCall` after
   relaying the response. This bounds the correlation window exactly.

**MCP SDK note (v6, as built):** The proxy uses the official
`github.com/modelcontextprotocol/go-sdk` (v1.x). Backends connect via SDK
client sessions (`IOTransport` over Docker-attached stdio with stdcopy
demux; `StreamableClientTransport` for HTTP/remote); the client-facing
side is an SDK `Server` behind `NewStreamableHTTPHandler`. The non-generic
`Server.AddTool` handler receives raw `json.RawMessage` arguments —
verbatim forwarding, no re-typing.

**Resources and prompts passthrough (v6):** in addition to tools, the
proxy aggregates and relays `resources/*` (list, read, templates,
subscribe/unsubscribe, `updated` notifications) and `prompts/*` (list,
get). These are pure passthrough — the policy boundary is `tools/call`
only. Anything the SDK does not model (custom/experimental methods,
`completion/*`) does not relay; documented gap.

**Tool identity (v6):** aggregation flattens N backends into one tool
list. A tool name exposed by two backends is a **startup error** (never
silently shadowed — this is a forensic audit boundary). Rename or
restrict via `policy.allowedTools`. During a running session
(`list_changed` re-aggregation) collisions are skipped with a warning
instead, so a misbehaving backend cannot crash the session.

### 3.2 Policy Engine (embedded)

**What:** OPA evaluation compiled into the proxy as a Go library.

**Where:** `internal/mcpproxy/policy.go`, `internal/mcpproxy/compiler.go`

At startup, compile `securityYaml` (if declared) and
`agentcontainer.json` capabilities into Rego + data per server. Evaluate
in-process via `github.com/open-policy-agent/opa/v1/rego` — the OPA 1.0
`/v1` path (Rego v1 syntax by default; the old un-versioned path is the
deprecated v0-syntax shim).

### 3.3 eBPF Enforcer Extensions

**What:** Rekey existing global BPF maps to per-cgroup scope, and add
tool-call correlation with bounded windows.

**Where:** `enforcer/agentcontainer-ebpf/src/` (Rust/Aya)

**Existing maps that need per-cgroup rekeying:**

| Map | Current key | Change |
|-----|------------|--------|
| `ALLOWED_V4` | LPM trie (prefix/addr) | Prefix key with 64-bit cgroup_id, offset prefix_len by 64 |
| `ALLOWED_V6` | LPM trie (prefix/addr) | Same LPM prefix trick |
| `BLOCKED_CIDRS_V4` | LPM trie | Same |
| `BLOCKED_CIDRS_V6` | LPM trie | Same |
| `ALLOWED_PORTS` | port-based | Add cgroup_id to key |
| `ALLOWED_INODES` | `FsInodeKey` (no cgroup_id) | Add cgroup_id to `FsInodeKey` |
| `DENIED_INODES` | `FsInodeKey` (no cgroup_id) | Same |
| `ALLOWED_EXECS` | `FsInodeKey` (no cgroup_id) | Same |
| `TRACKED_DOMAINS` | SipHash-based (global) | **Retired** — in-kernel hashing over a variable-length name never cleared the verifier; the kernel now copies the raw question name and userspace owns per-cgroup identification (Phase 3, step 7) |

**Already per-cgroup (no change):** `SECRET_ACLS` (`SecretAclKey`
includes `cgroup_id`).

**LPM trie rekeying:** `key = (cgroup_id_u64 ++ original_key)` with
`prefix_len += 64`. This is plain bitwise longest-prefix matching —
valid on **every** kernel with `BPF_MAP_TYPE_LPM_TRIE` (4.11+), no
version gate needed. Constraints: key data ≤ 256 bytes (we need 24 max
for cgroup_id + IPv6), `max_prefixlen` a multiple of 8, map created
with `BPF_F_NO_PREALLOC`. Aya's `LpmTrie` takes arbitrary `Pod` key
structs via `Key::new(64 + cidr_len, data)`. Entries must never be
inserted with `prefix_len < 64` (that would match across cgroups).
`ENFORCED_CGROUPS` caps at 256 — fine at this scale; document the limit.

**Server registration:** Use the existing `RegisterContainer` →
`ApplyNetworkPolicy` / `ApplyProcessPolicy` / `ApplyCredentialPolicy` /
`InjectSecrets` RPCs. Stays inside the `LoadPolicyBundle` content-trust
flow. `RegisterContainer` carries the container's init PID; filesystem,
exec, and credential policy paths are container-namespace paths and are
resolved to inodes through `/proc/<init_pid>/root` (the container's mount
namespace, same mechanism as `InjectSecrets`) — resolving them in the
enforcer's own namespace would pin host files, which on overlayfs are
different inodes than the ones the container's LSM hooks observe.

**New gRPC endpoints (two RPCs):**

```protobuf
message PrepareToolCallRequest {
  string correlationId = 1;
  string containerId = 2;
  string toolName = 3;
}
message PrepareToolCallResponse {}

message CompleteToolCallRequest {
  string correlationId = 1;
  string containerId = 2;
}
message CompleteToolCallResponse {}
```

`CompleteToolCall` clears the active correlation ID for a container.
With `maxConcurrentTools: 1` (the default), the window is exact:
`PrepareToolCall` → tool executes → `CompleteToolCall`. Kernel events
between Prepare and Complete carry the correlation ID; events outside
that window carry none. Without this, background container activity
(GC, watchdog timers, lazy writes) would be misattributed to the last
tool call — worse than no attribution in a forensic audit.

**Window assignment uses kernel timestamps, not read time.** Ring
buffer events are consumed asynchronously — an event generated during
call N can be *read* by userspace after `CompleteToolCall(N)`. The
enforcer records `[prepare_ktime, complete_ktime]` per window and
assigns the correlation ID by comparing the event's kernel timestamp
(`bpf_ktime_get_ns` captured at emit time) against the window, not by
when the userspace reader happens to drain the buffer.

The Prepare side has the mirror-image race: an event can be drained in
the instant between `PrepareToolCall` capturing its window-start
timestamp and inserting the window, where immediate assignment would
find no window. Drained events are therefore parked ~100 ms before
assignment — longer than any plausible insert latency — so the
in-flight Prepare lands first. Late assignment is safe for exactly the
reason above: matching is by the event's kernel timestamp, not by when
assignment runs. Parked events are flushed (assigned and published) on
reader shutdown, never dropped.

**Extend `EnforcementEvent`:** Add `correlationId` (string) to the
existing message (`proto:163-171`). The enforcer sets this on events
emitted while a `PrepareToolCall` window is active for the container.

**argv capture:** Stretch work for Phase 3. Initial events carry binary
path and `comm`. Full argv (reading user memory at execve) has verifier
complexity and truncation limits — list as explicit work item, not
assumed.

### 3.4 Audit Trail (JSONL)

**What:** Append-only JSONL files. Three independent hash chains, one
per file, each its own `audit.Logger` instance.

**Where:** Configurable via `AC_AUDIT_DIR` env var. Default:
`~/.ac/audit/` (v6: keeps the upstream default so the existing
`agentcontainer audit` CLI keeps working on one directory; the env var is
the override, centralized in `audit.DefaultDir()`).

**Writer:** CLI-side process writes all three files. Enforcer kernel
events arrive via `StreamEvents` gRPC and are written by the CLI-side
consumer.

**Files and chain independence:**

| File | Logger name | Chain starts at |
|------|-------------|-----------------|
| `<sessionId>-proxy.jsonl` | `<sessionId>-proxy` | sequence: 0, prev_hash: zero |
| `<sessionId>-enforcer.jsonl` | `<sessionId>-enforcer` | sequence: 0, prev_hash: zero |
| `<sessionId>-approval.jsonl` | `<sessionId>-approval` | sequence: 0, prev_hash: zero |

Each file has its own independent hash chain. `ValidateChain` is called
per file. Cross-file correlation is by `correlationId` — a DuckDB JOIN,
not a hash chain link.

**Metadata typing and hash coverage — one bundled upstream PR:**

Two upstream limitations block this design as-is, and one PR fixes both:

1. `Entry.Metadata` is `map[string]string` (`entry.go:43`). It cannot
   hold the typed values this spec needs: `reasons` ([]string),
   `policiesEvaluated` ([]string), `pid` (int), `latencyMs` (int),
   `approvalRequired` (bool). Change to `map[string]any`.
2. `computeHash` (`log.go:163-176`) hashes only
   `prevHash|timestamp|sessionId|sequence|eventType|actor|verdict|command`.
   `Metadata` and `Detail` are **not** covered — extended fields would
   not be tamper-evident. Extend `computeHash` to hash the full
   canonicalized entry (deterministic key-ordered JSON of all fields).

**PoC stance:** the fork carries both changes as a single fork-local
patch to `internal/audit/` (typed metadata + full canonical hash),
applied in Phase 1 since everything downstream depends on it. An
upstream PR is deferred until the concept is proven — the patch is
written to be PR-able as-is (no fork-specific coupling in the audit
package). Until upstreamed, this is a deliberate divergence point to
track on rebases.

**Hash-scheme versioning (v6, as built):** `Entry` gains `Version int`
(JSON `"v"`, omitted when 0). New entries are written at version 1 and
hashed over the full canonicalized entry (deterministic key-ordered JSON
of all fields except `entryHash`, via a marshal→generic→marshal round
trip so int/float representation differences cannot break verification).
Entries without a version field validate against the legacy chain-fields
hash, so `agentcontainer audit verify` stays green on pre-fork logs with
no migration.

**Field naming:** All JSONL fields use **camelCase** to match the
upstream `entry.go:33-46` serialization (`sessionId`, `prevHash`,
`entryHash`, `eventType`). DuckDB queries in §8 use camelCase
accordingly.

---

## 4. Schema: agentcontainer.json Extensions

Extend `MCPToolConfig` (`internal/config/config.go:168`).

```go
type MCPToolConfig struct {
    // --- Existing fields ---
    // Type gains one fork value: "container" (default) | "component"
    // | "remote". Remote = URL endpoint, no container lifecycle,
    // proxy-only enforcement.
    Type         string           `json:"type,omitempty"`
    Image        string           `json:"image,omitempty"`     // now omitempty (unused for remote)
    Capabilities []string         `json:"capabilities,omitempty"`
    Secrets      []string         `json:"secrets,omitempty"`
    Mounts       []string         `json:"mounts,omitempty"`
    Limits       *ComponentLimits `json:"limits,omitempty"`

    // --- New fields ---

    // Transport: "stdio" (default) or "http". Container type only.
    Transport string `json:"transport,omitempty"`

    // Port: container port for HTTP transport. Required when
    // transport: "http". Container type only.
    Port int `json:"port,omitempty"`

    // URL: endpoint for a type: "remote" server. Remote type only.
    URL string `json:"url,omitempty"`

    // Command: override container entrypoint. Container type only.
    Command []string `json:"command,omitempty"`

    // Env: environment variables. Container type only.
    Env map[string]string `json:"env,omitempty"`

    // Policy: per-server enforcement rules. Valid on all types;
    // which sub-fields are valid depends on type (see allowlists).
    Policy *MCPServerPolicy `json:"policy,omitempty"`
}

type MCPServerPolicy struct {
    AllowedTools        []string        `json:"allowedTools,omitempty"`
    RequireApproval     []string        `json:"requireApproval,omitempty"`
    MaxConcurrentTools  int             `json:"maxConcurrentTools,omitempty"`
    Network             *NetworkCaps    `json:"network,omitempty"`
    Filesystem          *FilesystemCaps `json:"filesystem,omitempty"`
    Shell               *ShellCaps      `json:"shell,omitempty"`
    SecurityYAML        string          `json:"securityYaml,omitempty"`
}
```

Example:

```jsonc
{
  "agent": {
    "tools": {
      "mcp": {
        "sift-gateway": {
          "type": "container",
          "image": "ghcr.io/appliedr/sift-gateway:latest",
          "transport": "stdio",
          "command": ["python", "-m", "sift_gateway"],
          "mounts": [
            "/opt/zimmerman:/opt/zimmerman:ro",
            "/opt/volatility3:/opt/volatility3:ro",
            "/opt/hayabusa:/opt/hayabusa:ro"
          ],
          "env": {"SIFT_CASE_DIR": "/cases/active"},
          "policy": {
            "maxConcurrentTools": 1,
            "allowedTools": ["run_command", "run_hayabusa",
                             "get_finding", "create_finding"],
            "requireApproval": ["run_privileged_command"],
            "network": {
              "egress": [],
              "deny": ["0.0.0.0/0"]
            },
            "filesystem": {
              "read": ["/evidence", "/opt", "/usr"],
              "write": ["/cases/*/extractions", "/tmp"],
              "deny": ["/etc/shadow", "/proc/*/mem"]
            },
            "shell": {
              "commands": [
                "fls", "mmls", "icat", "vol3", "grep", "strings",
                {"binary": "find", "denyArgs": ["-exec", "-delete"]},
                {"binary": "sed", "denyArgs": ["-i", "--in-place"]}
              ]
            },
            "securityYaml": "security.yaml"
          },
          "secrets": ["GITHUB_TOKEN"]
        },

        "wintools-mcp": {
          "type": "remote",
          "url": "http://192.168.1.20:4624/mcp",
          // Remote: only proxy-enforceable policy fields are valid.
          // network/filesystem/shell/securityYaml are REJECTED at
          // validation — there is no container or eBPF to enforce
          // them, and the spec never claims unenforceable policy.
          "policy": {
            "allowedTools": ["run_zimmerman", "run_hayabusa"],
            "requireApproval": ["run_zimmerman_write"],
            "maxConcurrentTools": 1
          }
        },

        "sigma-lookup": {
          "type": "component",
          "image": "ghcr.io/appliedr/sigma-lookup:latest",
          "capabilities": ["fs:read"],
          "limits": {"memory_mb": 64, "timeout_ms": 5000},
          "policy": {
            "allowedTools": ["search_sigma", "get_rule"]
          }
        }
      }
    },

    "secrets": {
      "GITHUB_TOKEN": {
        "provider": "infisical://infisical.corp/secret/github#token",
        "allowedTools": ["git"],
        "ttl": "1h"
      }
    },

    "policy": {
      "escalation": "prompt",
      "auditLog": true,
      "sessionTimeout": "8h",
      "maxConcurrentTools": 3,
      "onCapabilityViolation": "deny"
    },

    "provenance": {
      "require": {
        "signatures": true,
        "sbom": true,
        "slsaLevel": 2,
        "trustedRegistries": ["ghcr.io/appliedr"]
      }
    },

    "enforcer": {"required": true}
  }
}
```

### Validation Rules — per-type field allowlists

Validation is type-driven: each type has an allowlist of valid fields.
This extends the pattern upstream already uses for container-vs-component
(`config.go:385-399`).

| Field | `container` | `component` | `remote` |
|-------|:-----------:|:-----------:|:--------:|
| `image` | required | required | rejected |
| `url` | rejected | rejected | required |
| `transport`, `port` | ✓ (`http` requires `port > 0`) | rejected | rejected |
| `command`, `env`, `mounts` | ✓ | rejected | rejected |
| `secrets` | ✓ | ✓ | rejected (nothing to inject into) |
| `limits` | rejected | ✓ | rejected |
| `policy.allowedTools`, `requireApproval`, `maxConcurrentTools` | ✓ | ✓ | ✓ |
| `policy.network`, `filesystem`, `shell`, `securityYaml` | ✓ | rejected | rejected |

- Remote servers must not declare enforcement the runtime cannot
  deliver: there is no container and no eBPF, so kernel-class policy
  fields are validation errors, not silent no-ops.
- `policy.maxConcurrentTools` defaults to 1. Shadows the agent-level
  `agent.policy.maxConcurrentTools` (config.go:224) — per-server
  overrides the agent default.
- `policy.securityYaml` resolved relative to config file directory.
- `policy.shell.commands` uses existing `ShellCommand.UnmarshalJSON`.

---

## 5. Policy Input Document

Unchanged from v2. Built by the proxy for every `tools/call`.

```json
{
  "server":  "sift-gateway",
  "tool":    "run_command",
  "args":    {"binary": "find", "extra_args": ["/evidence/disk1", "-name", "*.evtx"]},
  "parsed":  {"binary": "find", "flags": ["-name"], "paths": ["/evidence/disk1"],
              "output_paths": [], "device_paths": []},
  "context": {"case_dir": "/home/analyst/cases/INC-2026-0042", "examiner": "jgore",
              "correlationId": "0192b3a4-5e6f-7890-abcd-ef1234567890",
              "timestamp": "2026-06-04T15:30:00Z"}
}
```

---

## 6. Policy Decision Document

```json
{
  "allowed": false,
  "reasons": [
    "sift.tool_blocked_flags: flag '-exec' is not permitted on 'find'",
    "sift.shell_metacharacters: shell metacharacter ';' detected"
  ],
  "policiesEvaluated": [
    "sift.denied_binaries", "sift.dangerous_flags",
    "sift.tool_blocked_flags", "sift.shell_metacharacters",
    "sift.path_policy", "sift.rm_protection"
  ]
}
```

Denials return an in-band `tools/call` result with `isError: true`:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "content": [{"type": "text",
      "text": "Policy denial: flag '-exec' is not permitted on 'find'; shell metacharacter ';' detected"}],
    "isError": true
  }
}
```

---

## 7. JSONL Schemas

All entries use the upstream `Entry` struct verbatim (`entry.go:33-46`):
camelCase fields, and `actor` is an **object** `{"type", "name"}` — not
a string — because `computeHash` covers `Actor.Type` and `Actor.Name`.
Actor types follow upstream conventions: `"tool"` for MCP server
activity, `"user"` for approval decisions.

Three independent hash chains — each file starts at sequence 0 with
the zero hash. Cross-file correlation is by `correlationId` (DuckDB
JOIN), not by chain linkage.

Metadata values below assume the fork-local audit patch (§3.4): typed
`map[string]any` metadata covered by the full-entry hash.

### 7.1 proxy.jsonl

```json
{
  "timestamp":         "2026-06-04T15:30:00.123Z",
  "sessionId":         "ses-abc123",
  "sequence":          0,
  "prevHash":          "0000000000000000000000000000000000000000000000000000000000000000",
  "entryHash":         "a1b2c3d4...",
  "eventType":         "tool_call",
  "actor":             {"type": "tool", "name": "sift-gateway"},
  "verdict":           "allow",
  "command":           "run_command: find /evidence/disk1 -name *.evtx",
  "metadata": {
    "correlationId":   "0192b3a4-5e6f-7890-abcd-ef1234567890",
    "containerId":     "ac-mcp-sift-gateway-7f3a",
    "tool":            "run_command",
    "argsSummary":     "find /evidence/disk1 -name *.evtx",
    "reasons":         [],
    "policiesEvaluated": ["sift.denied_binaries", "sift.dangerous_flags",
                          "sift.tool_blocked_flags", "sift.shell_metacharacters",
                          "sift.path_policy", "sift.rm_protection"],
    "approvalRequired": false,
    "latencyMs":       3
  }
}
```

Denied:

```json
{
  "timestamp":         "2026-06-04T15:31:00.456Z",
  "sessionId":         "ses-abc123",
  "sequence":          1,
  "prevHash":          "a1b2c3d4...",
  "entryHash":         "d4e5f6g7...",
  "eventType":         "tool_call",
  "actor":             {"type": "tool", "name": "sift-gateway"},
  "verdict":           "deny",
  "command":           "run_command: find /evidence -exec rm {} ;",
  "metadata": {
    "correlationId":   "0192b3a4-5e6f-7890-abcd-ef1234567891",
    "containerId":     "ac-mcp-sift-gateway-7f3a",
    "tool":            "run_command",
    "argsSummary":     "find /evidence -exec rm {} ;",
    "reasons":         [
      "sift.tool_blocked_flags: flag '-exec' is not permitted on 'find'",
      "sift.shell_metacharacters: shell metacharacter ';' detected"
    ],
    "policiesEvaluated": ["sift.denied_binaries", "sift.dangerous_flags",
                          "sift.tool_blocked_flags", "sift.shell_metacharacters",
                          "sift.path_policy", "sift.rm_protection"],
    "approvalRequired": false,
    "latencyMs":       2
  }
}
```

Tool-call entries carry an optional `metadata.enforcement` marker when
the enforcement posture is anything other than full kernel+proxy:
`"proxy-only"` for remote backends (no cgroup to attach eBPF to), and
`"fs-allowlists:proxy-only"` for container backends that declare
`policy.filesystem.read`/`write` allowlists (kernel LSM runs deny-list
mode; allowlist confinement is at the proxy's filesystem.rego layer —
see §14).

### 7.2 enforcer.jsonl

Written by CLI-side `StreamEvents` consumer. Independent chain.

```json
{
  "timestamp":     "2026-06-04T15:30:00.125Z",
  "sessionId":     "ses-abc123",
  "sequence":      0,
  "prevHash":      "0000000000000000000000000000000000000000000000000000000000000000",
  "entryHash":     "h8i9j0...",
  "eventType":     "kernel_execve",
  "actor":         {"type": "tool", "name": "sift-gateway"},
  "verdict":       "allow",
  "command":       "/usr/bin/find",
  "metadata": {
    "correlationId": "0192b3a4-5e6f-7890-abcd-ef1234567890",
    "containerId":   "ac-mcp-sift-gateway-7f3a",
    "pid":           48291,
    "comm":          "find"
  }
}
```

Network denial:

```json
{
  "timestamp":     "2026-06-04T15:30:00.130Z",
  "sessionId":     "ses-abc123",
  "sequence":      1,
  "prevHash":      "h8i9j0...",
  "entryHash":     "k1l2m3...",
  "eventType":     "kernel_connect4",
  "actor":         {"type": "tool", "name": "sift-gateway"},
  "verdict":       "deny",
  "command":       "connect 169.254.169.254:80/tcp",
  "metadata": {
    "correlationId": "0192b3a4-5e6f-7890-abcd-ef1234567890",
    "containerId":   "ac-mcp-sift-gateway-7f3a",
    "pid":           48291,
    "dstAddr":       "169.254.169.254",
    "dstPort":       80,
    "protocol":      "tcp"
  }
}
```

**Note:** Initial events carry binary path and `comm`, not full argv.
Full argv capture is Phase 3 stretch work.

### 7.3 approval.jsonl (authoritative for approval decisions)

Independent chain. This file is authoritative — proxy.jsonl's
`approvalRequired` field is a summary; approval.jsonl is the record.

```json
{
  "timestamp":         "2026-06-04T15:32:00.000Z",
  "sessionId":         "ses-abc123",
  "sequence":          0,
  "prevHash":          "0000000000000000000000000000000000000000000000000000000000000000",
  "entryHash":         "n4o5p6...",
  "eventType":         "approval_decision",
  "actor":             {"type": "user", "name": "jgore"},
  "verdict":           "deny",
  "command":           "run_privileged_command: vol3 --write ...",
  "metadata": {
    "correlationId":     "0192b3a4-5e6f-7890-abcd-ef1234567892",
    "server":            "sift-gateway",
    "tool":              "run_privileged_command",
    "argsSummary":       "vol3 --write ...",
    "reason":            "writes to evidence not permitted for this case",
    "promptDurationMs":  12400
  }
}
```

---

## 8. DuckDB Correlation Queries

No setup. DuckDB reads the JSONL files directly. Note camelCase, and
**bracket notation** for struct field access (`metadata['correlationId']`)
— dot notation on JSON-derived structs has a regression history in
DuckDB; bracket form is the reliable syntax. `actor` is a struct, so
the server name is `actor.name`.

### Intent vs. reality drift

```sql
SELECT
  p.timestamp, p.command,
  p.metadata['correlationId'] as cid,
  e.eventType, e.command as kernelCmd, e.verdict
FROM read_json_auto('audit/*-proxy.jsonl') p
JOIN read_json_auto('audit/*-enforcer.jsonl') e
  ON p.metadata['correlationId'] = e.metadata['correlationId']
WHERE p.verdict = 'allow' AND e.verdict = 'deny';
```

### Full tool call trace

```sql
SELECT * FROM (
  SELECT timestamp, 'proxy' as source, command,
         verdict, metadata['correlationId'] as cid
  FROM read_json_auto('audit/*-proxy.jsonl')
  WHERE metadata['correlationId'] = ?
  UNION ALL
  SELECT timestamp, 'kernel', command, verdict,
         metadata['correlationId']
  FROM read_json_auto('audit/*-enforcer.jsonl')
  WHERE metadata['correlationId'] = ?
  UNION ALL
  SELECT timestamp, 'approval', command, verdict,
         metadata['correlationId']
  FROM read_json_auto('audit/*-approval.jsonl')
  WHERE metadata['correlationId'] = ?
) ORDER BY timestamp;
```

### Per-file hash chain smoke check

```sql
-- Quick linkage check (per-file only).
-- Authoritative verification: the EXISTING `agentcontainer audit verify`
-- command (internal/cli/audit_log.go:150, calls audit.ValidateChain)
WITH ordered AS (
  SELECT *, LAG(entryHash) OVER (ORDER BY sequence) as expectedPrev
  FROM read_json_auto('audit/*-proxy.jsonl')
)
SELECT sequence, timestamp, command, prevHash, expectedPrev
FROM ordered
WHERE prevHash != expectedPrev AND sequence > 0;
```

### Per-server enforcement summary

```sql
SELECT
  e.actor.name as server, e.eventType, count(*) as denyCount
FROM read_json_auto('audit/*-enforcer.jsonl') e
WHERE e.verdict = 'deny'
GROUP BY e.actor.name, e.eventType
ORDER BY denyCount DESC;
```

### Policy denial hot spots

```sql
SELECT unnest(metadata['reasons']) as reason, count(*) as n
FROM read_json_auto('audit/*-proxy.jsonl')
WHERE verdict = 'deny'
GROUP BY reason ORDER BY n DESC;
```

---

## 9. Implementation Sequence

### Phase 1: MCP proxy skeleton (Go, no policy yet)

**Goal:** LLM client → proxy → MCP server works end-to-end.

1. Extend `MCPToolConfig` in `internal/config/config.go` with
   `Transport`, `Port`, `URL`, `Command`, `Env`, `Policy`, and the
   `"remote"` type value. Extend `Validate()` with the per-type field
   allowlists (§4).
2. Create `internal/mcpproxy/proxy.go`: Streamable HTTP listener,
   JSON-RPC relay, `tools/list` aggregation, bidirectional message
   relay (notifications, progress, sampling, `list_changed`).
3. Create `internal/mcpproxy/transport.go`:
   - **stdio client:** launch container via Docker API with attached
     streams (`-i`), joined to `ac-mcp-<session>` network. Use
     `MCPServiceConfig` from `mcp_isolation.go` for network/secrets
     spec but manage container lifecycle directly (not via Compose).
   - **HTTP client:** for `url` (remote), connect directly via
     `StreamableClientTransport`. (v6: container `transport: "http"` —
     the `GenerateMCPServices` Compose path — is **deferred to Phase 3**;
     validation accepts it, `mcp start` returns not-implemented. The
     remote path exercises the same HTTP client code.)
   - **WASM client:** route to enforcer `ListTools`/`CallTool` gRPC.
4. Create `internal/cli/mcp.go`: `agentcontainer mcp start|stop|ps|logs`.
5. **Apply the fork-local audit patch** (§3.4): `Entry.Metadata` →
   `map[string]any` + `computeHash` over the full canonicalized entry.
   Everything downstream depends on it. Written PR-clean; upstream
   submission deferred until the PoC proves out.
6. Emit `proxy.jsonl` with hash chain on every `tools/call`
   (pass-through, `verdict: "allow"` for everything). Correlation IDs
   via `uuid.NewV7()` — `github.com/google/uuid v1.6.0` is already in
   go.mod and v7 is monotonic within a millisecond.
7. Test: Claude Code → proxy → sift-mcp stdio → tool output returns.
   Also test: remote HTTP transport, WASM component routing,
   server→client notification relay, resources/prompts passthrough.

**New dependencies:** `github.com/modelcontextprotocol/go-sdk` (MIT;
v6 — replaces the hand-rolled transport). `google/uuid` already present.

### Phase 2: Policy evaluation

**Goal:** Denied tool calls return structured `isError` results.

1. Create `internal/mcpproxy/compiler.go`: YAML→Rego compiler using
   `text/template`.
2. Create `internal/mcpproxy/policy.go`: in-process OPA via
   `github.com/open-policy-agent/opa/v1/rego` (OPA 1.0 path).
3. Create `internal/mcpproxy/decompose.go`: shell parsing via
   `mvdan.cc/sh/v3/syntax`, falling back to operator split.
4. Wire into proxy, update `proxy.jsonl` with real decisions.
5. Port Rego templates from sift-mcp.

**New dependencies:**
- `github.com/open-policy-agent/opa` (Apache-2.0)
- `mvdan.cc/sh/v3` (BSD-3-Clause)

### Phase 3: Per-cgroup eBPF enforcement

**Goal:** Each MCP server container gets kernel-enforced policy.

1. **Rekey network maps:** 5 maps. LPM tries: prefix key with 64-bit
   cgroup_id, offset prefix_len by 64 (valid on all LPM_TRIE kernels
   ≥ 4.11; see §3.3 — no fallback needed). `ALLOWED_PORTS`: add
   cgroup_id to key.
2. **Rekey fs/exec maps:** 3 maps. Add cgroup_id to `FsInodeKey` for
   `ALLOWED_INODES`, `DENIED_INODES`, `ALLOWED_EXECS`.
3. **Use existing registration RPCs** for each server container.
4. **Add `PrepareToolCall` + `CompleteToolCall` RPCs.** Correlation
   window is bounded by kernel timestamps (§3.3): events whose
   `ktime` falls between Prepare and Complete carry the correlation
   ID; events outside carry none.
5. **Extend `EnforcementEvent`:** add `correlationId` string field.
   CLI-side `StreamEvents` consumer writes `enforcer.jsonl`.
6. **Hostname resolution:** at registration, proxy resolves hostnames
   to IPs and populates IP-based maps, with re-resolution every 5
   minutes for long sessions (CDN/cloud IPs rotate).
7. **DNS observation (userspace identification).** The `cgroup_skb/ingress`
   parser (`ac_dns_ingress`), gated per-cgroup via `bpf_skb_cgroup_id`, copies
   each enforced cgroup's DNS-response question name (raw wire bytes,
   lowercased, length-prefixed) into a `DnsEvent` and emits one event per
   A/AAAA answer record. Userspace matches the name against a per-cgroup
   tracked-domain set (wire bytes → hostname, populated at `apply_network`) and
   drops the rest — so no hostname identification or hashing runs in the
   kernel. The original plan (rekey an in-kernel SipHash `TRACKED_DOMAINS` map)
   was abandoned: a SipHash over a variable-length name never cleared the BPF
   verifier. Answer records are capped at `MAX_ANSWERS` (4) to stay inside the
   verifier's 1M-insn complexity budget; the filtering resolver (§14) is the
   compensating control for answer sections beyond the cap.
8. **(Stretch) argv capture:** new BPF tracepoint at execve. Truncation
   at 256 bytes/arg, 16 args max. Only if verifier budget allows.

**New dependencies:** None.

### Phase 4: Human-in-the-loop approval

**Goal:** Tools in `requireApproval` pause for human confirmation.

1. Wire `internal/approval/` broker into the proxy.
2. **Approval channels:**
   - **Interactive (TTY available):** prompt on `/dev/tty`.
   - **Daemonized (no TTY):** expose approval over a Unix socket at
     `~/.agentcontainers/approval.sock` (mode `0600`, `SO_PEERCRED`
     UID check — only the owning user can approve). A separate
     `agentcontainer approve` CLI connects to the socket, shows
     pending approvals, accepts/denies.
   - **Timeout:** configurable (default 5 minutes), then deny. Proxy
     sends MCP progress notifications to the client while waiting so
     the client doesn't drop the connection.
3. Emit `approval.jsonl` with hash chain.
4. Test: `run_privileged_command` blocks until examiner approves via
   TTY or `agentcontainer approve`.

**New dependencies:** None.

---

## 10. What's Explicitly Out of Scope

- **Replacing sift-mcp internals.** Defense in depth, not replacement.
- **Multi-tenant / multi-user.** One proxy, one analyst.
- **Hot reload.** Restart to change policy.
- **GUI / dashboard.** DuckDB CLI for audit queries.
- **Firecracker / microVM.** Docker containers only.
- **seccomp profile generation.** Follow-up.
- **eBPF for remote servers.** `type: "remote"` servers get proxy-only
  enforcement (no cgroup to attach to). Document this in the audit
  trail (`metadata.enforcement: "proxy-only"`).

---

## 11. File Layout

```
internal/
├── config/
│   └── config.go                # MODIFIED: extend MCPToolConfig, add MCPServerPolicy
├── mcpproxy/                    # NEW
│   ├── proxy.go                 # MCP JSON-RPC reverse proxy
│   ├── transport.go             # stdio (Docker API) / HTTP / WASM (gRPC) clients
│   ├── policy.go                # Embedded OPA evaluator
│   ├── compiler.go              # YAML→Rego compiler
│   ├── decompose.go             # Shell command decomposition
│   ├── audit.go                 # JSONL audit (three audit.Logger instances)
│   └── *_test.go
├── cli/
│   └── mcp.go                   # NEW: agentcontainer mcp subcommands
├── container/
│   └── mcp_isolation.go         # MODIFIED: proxy integration, stdio lifecycle split
├── enforcement/
│   └── (MODIFIED: PrepareToolCall/CompleteToolCall forwarding)
└── approval/
    └── (MODIFIED: Unix socket channel, SO_PEERCRED, timeout)

enforcer/
├── agentcontainer-ebpf/src/
│   ├── lib.rs                   # entry points
│   ├── maps.rs                  # MODIFIED: per-cgroup keys on 9 maps
│   ├── network/                 # MODIFIED: cgroup-aware LPM lookups
│   └── lsm/                     # MODIFIED: cgroup-aware inode checks
├── agentcontainer-enforcer/
│   ├── proto/enforcer.proto     # MODIFIED: PrepareToolCall, CompleteToolCall,
│   │                            #   correlationId on EnforcementEvent
│   └── src/main.rs              # MODIFIED: correlation window tracking
└── agentcontainer-common/src/
    └── maps.rs                  # MODIFIED: cgroup_id in FsInodeKey, LPM key structs
```

---

## 12. Rego Template Inventory

Unchanged from v2. Ported from sift-mcp Jinja2 to Go `text/template`.

Porting notes (v6): sift-mcp folds `dangerous_flags` into its
`tool_blocked_flags` template — the port **splits it into its own
package** so `policiesEvaluated` matches §6 verbatim. The §5 nested input
shape is authoritative: ported templates are rewritten from sift's flat
`input.tool`/`input.flags` to `input.parsed.binary`/`input.parsed.flags`/
`input.context.*` (`input.tool` stays the MCP tool name), locked by
golden-file tests.

Native addition (v6): `filesystem.rego` enforces `policy.filesystem`
(read/write allowlists + deny patterns, plain prefixes or `/`-delimited
globs like `/cases/*/extractions`) at the proxy on decomposed argument
paths — the argument-level layer of the same policy the eBPF enforcer
applies at the kernel in Phase 3. Device paths are exempt from the read
allowlist (disk-forensics tools address `/dev` specifiers, governed by
`path_policy` and the kernel layer).

| Template | Source | What it checks |
|----------|--------|----------------|
| `denied_binaries.rego` | YAML `denied_binaries` | Binary in denylist |
| `dangerous_flags.rego` | YAML `dangerous_flags` + `tool_allowed_flags` | Global flag denylist with exceptions |
| `tool_blocked_flags.rego` | YAML `tool_blocked_flags` | Per-tool flag denylist |
| `shell_metacharacters.rego` | YAML `shell_metacharacters` | Operators in arguments |
| `path_policy.rego` | YAML `blocked_input_dirs` + exceptions | Reads from system dirs |
| `output_path_policy.rego` | YAML `blocked_output_dirs` + context | Writes outside case dir |
| `rm_protection.rego` | YAML `protected_rm_dirs` | `rm` targeting evidence/case |
| `awk_scanning.rego` | YAML `program_text_tools` | Dangerous constructs in awk |
| `capabilities.rego` | config `policy.shell.commands` | Binary allowlist + denyArgs |
| `network.rego` | config `policy.network` | Egress allowlist (informational) |
| `decision.rego` | (aggregator) | `{allowed, reasons, policiesEvaluated}` |

---

## 13. Testing Strategy

| Layer | Test type | What's verified |
|-------|-----------|----------------|
| Config parsing | Unit | MCPToolConfig extensions, per-type field allowlists (incl. kernel-class policy rejected on remote) |
| YAML→Rego compiler | Unit | Valid Rego output, data.json correctness |
| Policy evaluation | Unit | Known-good/bad inputs, correct decisions |
| Command decomposition | Unit | Compound commands, substitutions, edge cases |
| Hash chain | Unit | Per-file chains validate, cross-file links absent |
| Proxy stdio | Integration | JSON-RPC through proxy to Docker-attached container |
| Proxy HTTP | Integration | JSON-RPC through proxy to Compose service |
| Proxy remote | Integration | JSON-RPC through proxy to URL endpoint |
| WASM routing | Integration | Component tools via enforcer CallTool |
| Bidirectional relay | Integration | Server notifications reach client |
| eBPF per-cgroup | Integration | Server A egress ≠ server B; denied destinations blocked |
| Correlation window | Integration | Events outside Prepare/Complete carry no correlationId |
| Approval TTY | Integration | Interactive prompt works |
| Approval socket | Integration | Daemonized approval via Unix socket, 0600 perms |
| End-to-end | E2E | Full flow with denials, kernel enforcement, audit |
| JSONL + DuckDB | Unit | Files readable, correlation joins, chain validates |

---

## 14. Known Limitations

| Gap | Scope | Mitigation |
|-----|-------|------------|
| Audit patch is a fork divergence until upstreamed | Audit | Fork-local patch (Phase 1, §3.4): typed metadata + full-entry computeHash, written PR-clean; track on rebases; PR after PoC |
| Hostname egress is IP-resolution-based (kernel maps hold IPs, not names) | Phase 3 | Periodic re-resolution (5 min) replaces the cgroup's IP set, so rotated-away IPs lose access; between refreshes a rotated-to IP is briefly denied until the next refresh. Cloud metadata endpoints (169.254.169.254, fd00:ec2::254) are always-denied via BLOCKED_CIDRS ahead of the allow maps, so attacker-influenced DNS on an allowed hostname cannot resolve into the credentials endpoint; `policy.network.deny` CIDRs land in the same always-deny tier |
| Port-scoped egress rules are IPv4-only (`ALLOWED_PORTS` is v4-keyed); an egress rule whose host resolves to IPv6 stays denied on v6 | Phase 3 | Host-wide allows cover v6 (`ALLOWED_V6`); a port-scoped v6 resolution logs a warning instead of silently widening to a host-wide allow |
| Full argv not at kernel level initially | Phase 3 stretch | Binary path + comm; full argv is later |
| ENFORCED_CGROUPS cap 256 | Scale | Fine for forensic; document limit |
| Default serialize per-server | Throughput | maxConcurrentTools override; window exact at 1 |
| Remote servers: proxy-only enforcement | Design | No cgroup; mark in audit as proxy-only |
| Container's cgroup/PID exist only after start, so it cannot be registered before its process begins | Phase 3 | Freeze-on-start: pause immediately after start, apply policy while frozen, unfreeze before the handshake. Residual unenforced window is the Start→Pause interval only; skipped with a warning where the freezer is unavailable |
| Approval socket is security boundary | Phase 4 | 0600 perms + SO_PEERCRED UID check |
| DNS exfiltration when DNS allowed | Upstream | Filtering resolver as compensating control |
| /proc/pid/mem bypasses file_open LSM | Upstream | Container boundary is primary isolation |
| Inode pinning is a point-in-time snapshot: overlayfs copy-up (container writes a lower-layer file) gives the file a new backing inode, and files created after registration are never covered | Phase 3 | Deny-lists pin inodes at `ApplyFilesystemPolicy` time, resolved via `/proc/<init_pid>/root` (container mount namespace). Re-apply policy to re-pin; the proxy filesystem.rego layer (§12) checks paths, not inodes, and is unaffected |
| Filesystem/exec LSM hooks run deny-list-first with a default-allow verdict: `policy.filesystem.read`/`write` allowlists and exec allowlists populate maps but do not confine unlisted inodes | Phase 3 | `deny` entries and SECRET_ACLS are kernel-enforced; read/write allowlists are enforced at the proxy (filesystem.rego), plus kernel write-protection on read-listed inodes. The posture is surfaced, not silent: the proxy warns at backend registration and every tool call for such a backend carries `enforcement: "fs-allowlists:proxy-only"` in proxy.jsonl (§7.1). Kernel-level allowlist confinement needs inode-ancestry matching (future work) |
