# internal/toolpolicy — per-tool-call authorization (Cedar)

A self-contained policy engine that decides **whether one MCP tool call is allowed**,
compiled from `agentcontainer.json` and evaluated with embedded
[`cedar-go`](https://github.com/cedar-policy/cedar-go). ~2.4k source LOC, no external
service or daemon — Cedar is a library dependency, evaluated in-process.

This package was extracted out of `internal/mcpproxy` so it can be read and judged on
its own. The proxy runtime and the `agentcontainer guard` command consume it through a
thin type-alias shim (`internal/mcpproxy/aliases.go`); nothing else changed. That it
detaches this cleanly is the point — it's an additive layer, not something woven
through the rest of the codebase.

## Where it sits (it does not overlap existing policy)

Three policy layers, three different questions:

| package | question it answers | input |
|---|---|---|
| `internal/policy` | how is the *container* confined? | capabilities → network/rootfs/caps/secrets |
| `internal/orgpolicy` | is this *OCI digest* allowed to run? | signed org bundle (deprecations, deny-after) |
| **`internal/toolpolicy`** *(this)* | is this *tool call* allowed? | tool + args + decomposed command + context |

`toolpolicy` never touches the other two. It's the runtime authorization boundary for
the proxy's `tools/call` path (and the guard hook's Bash/write/edit gating).

## What's inside

- **Compile** (`compiler.go`, `cedar_emit.go`, `templates/cedar/`) — turns config
  (allowed/blocked tools, filesystem read/write/deny, network, dangerous flags,
  denied binaries, shell-metacharacter rules) into a **Cedar policy set** plus a
  neutral `Data` document. The emitted Cedar is human-readable and auditable; the
  templates + `command.cedarschema` are the whole surface.
- **Evaluate** (`cedar.go`) — the embedded `cedar-go` engine decides membership /
  authorization; the `PolicyEngine` interface (`engine.go`) is the one boundary the
  proxy calls (`Evaluate` / `EvaluateParsed`), returning a structured `Decision`.
- **Native evaluators** (`paths_eval.go`, `content.go`, `context_eval.go`) — path
  globbing, content/output-dir checks, and URI-scoped transient egress are done in Go
  (not expressible cleanly in Cedar), keyed off the same compiled `Data`.
- **Command decomposition** (`decompose.go`, `wrappers.go`) — parses a shell command
  (`mvdan.cc/sh`), sees through transparent wrappers (`env`, `sudo`, …) and
  interpreter `-c` payloads, and denies unmodeled exec mechanisms by default, so a
  blocked binary can't be laundered through a wrapper.

## Evaluate it yourself

```
go test ./internal/toolpolicy/
```

The evidence worth reading first:

- **`TestEmitCedar_Golden`** (`cedar_test.go`) — asserts the exact Cedar emitted from a
  policy. Read it to see what config compiles *to*.
- **`TestCapabilityMatrixOracle`** / **`TestCapabilityMatrixGuardPath`**
  (`capability_matrix_test.go`, `testdata/capability-matrix.yaml`) — the allow/deny
  oracle across every capability class; the single best proof the engine does what it
  claims, on both the proxy and guard paths.
- **`TestCedarVerdicts`** / **`TestNewCedarEvaluator_FailsClosedOnBadPolicy`** — verdict
  shapes and fail-closed behavior (a malformed policy denies, never opens).
- **`TestURIEgress*`** — URI-scoped transient egress from a user-supplied https URI.
- **`TestOverride*`** — ceiling-bounded, VC-signed operator overrides (a deny can be
  waived only within an operator-set ceiling, audited).

## Dependencies it introduces

- `github.com/cedar-policy/cedar-go` — the engine (embedded, no daemon).
- `mvdan.cc/sh/v3/syntax` — shell parsing for command decomposition.

That's the whole ask: two libraries and this directory. It compiles and tests green
against upstream's control-plane with no changes to existing policy code.
