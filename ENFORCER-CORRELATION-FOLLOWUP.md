# Deferred: enforcer tool-call correlation reconcile

**Status:** open follow-up after the 2026-07-11 merge of `upstream/main` (`abf4c01`).

## What was deferred and why

The merge adopted Cadence's control-plane wholesale (container/enforcement/sidecar,
enforcer Rust) and reworked our `mcpproxy` onto her env-driven mTLS/UDS API. The Go
side is fully reconciled and green. The **enforcer Rust was set to pure upstream**
(`enforcer/` is byte-identical to `upstream/main`) because reconciling it is a real
two-implementations union that is Cadence's domain and only runtime-validatable on
the talos BPF integration job — out of scope for the sync.

## The one debt this leaves

`internal/enforcerapi/enforcer.pb.go` (committed, generated) **contains** the
correlation RPCs `PrepareToolCall` / `CompleteToolCall`, because `mcpproxy/proxy.go`
calls them (tool-call windowing, proxy.go ~L762–799). But the enforcer's
`proto/enforcer.proto` (now pure upstream) **does not** declare them, and her
`grpc.rs` does not implement them.

Consequences:
- **Go builds and the proxy compiles** (pb.go is self-contained).
- **Enforcer builds** (pure upstream, coherent).
- **Drift:** regenerating `enforcer.pb.go` from the current proto would DROP the
  correlation RPCs and break the proxy. Do not regenerate pb.go until the reconcile
  below lands.
- **Runtime:** against a pure-upstream enforcer, `PrepareToolCall`/`CompleteToolCall`
  return `Unimplemented`; the proxy handles the error but tool-call-window scoping is
  inactive until the enforcer implements them.

## The follow-up (a reconcile-PR to Cadence, like #39/#40)

Graft the correlation subsystem onto her enforcer:
1. Add `PrepareToolCall`/`CompleteToolCall` (+ request/response messages) to
   `enforcer.proto` — the union we already validated during the merge.
2. Implement the two handlers in her `grpc.rs` alongside her deny-set/bind/
   reverse-shell RPCs (22-RPC service), porting our correlation state/maps.
3. Reconcile our DNS hook (`dns.rs` `qname`/`DNS_QNAME_MAX`/`DNS_SCRATCH`) onto her
   `DnsEvent` schema — or drop the richer capture if she prefers.
4. Regenerate `enforcer.pb.go` from the reconciled proto (removes this drift).
5. Runtime-validate on the talos BPF integration job.

Our correlation handlers + richer DNS hook are preserved in git history (pre-merge
`main`) and on `feat/*` branches. See memory `upstream-merge-status`,
`upstream-alignment-philosophy`.
