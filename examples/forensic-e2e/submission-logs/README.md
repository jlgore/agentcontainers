# forensic-e2e — agent execution logs

Audit trails and case output from a live `forensic-e2e` run: Claude Code, inside
an agentcontainers-enforced container, investigates a Windows 7 x64 disk image
(`win7-64-nfury-c-drive.E01`) through the kernel-enforced SIFT gateway and stages
findings into a Valhuntir case. Every forensic tool call flows through the MCP
proxy's OPA policy evaluation, correlation-ID tagging, and a hash-chained audit
log; the gateway runs as a kernel-enforced (eBPF LSM) container backend.

**Run session:** `ffb9490a42197fac` · gateway image
`ghcr.io/jlgore/sift-gateway:e2e-ubuntu` (SIFT toolset, 55 tools) · examiner
`jgore` · **9 findings staged (DRAFT)**.

## Contents

- **`audit-chains/`** — hash-chained JSONL audit trails for the run session.
  - `ffb9490a42197fac-proxy.jsonl` — the MCP **proxy** chain: one entry per
    forensic tool call, each with a **correlation ID**, the **OPA policy
    decision** (verdict + reasons), an argument summary, and timing. 95 entries,
    hash-linked (each entry carries the previous entry's hash).
  - `ffb9490a42197fac-enforcer.jsonl` — the eBPF **enforcer** stream for this
    session. Present but empty: the managed enforcer enforces at the kernel
    (BPF LSM) — see `enforcer-diagnose.txt` for live hook status — but does not
    write per-session userspace audit entries in this deployment. Kernel
    enforcement is real (the gateway runs `CapDrop:ALL`, read-only rootfs,
    `--cgroupns=host` under `kernelPrimary`), not inferred from this file.
  - (No `-approval.jsonl`: this run triggered no human-in-the-loop escalations.)
- **`audit-verify.txt`** — output of `agentcontainer audit verify
  ffb9490a42197fac-proxy`: **`OK: 95 entries, chain intact.`** Proves no entry
  was tampered with or removed. Re-run it yourself against the proxy chain.
- **`case-data/`** — the structured investigation output the `forensic-critic`
  subagent verified:
  - `findings.json` — 9 findings (DRAFT, pending human `vhir approve`).
  - `timeline.json` — incident timeline events.
  - `iocs.json` — extracted indicators of compromise.
  - `evidence.json` — evidence registry (the registered `.E01` + its SHA-256).
  - `CASE.yaml` — case metadata.
  - `FRESH-BEFORE.txt` — pre-run snapshot proving the case started empty (0
    findings / 0 timeline / 0 audit) so the output is provably this run's work.
  - `case-audit/` — per-MCP append-only audit JSONL written by the gateway
    backends (`sift-mcp`, `forensic-mcp`, `case-mcp`). This is where
    `run_command` **audit_ids** are persisted — the trail `record_finding`
    validates each finding's provenance against.
- **`gateway-docker.log`** — the SIFT gateway container log: startup, backend
  bring-up, **tool map build (55 tools across 4 backends)**, and the MCP
  handshake.
- **`enforcer-diagnose.txt`** — eBPF enforcer health and BPF LSM hook status
  (`file_open` / `bprm_check` attachment) at capture time.

## Traceability — any finding back to the evidence

A judge can trace any finding end to end:

1. **Finding** in `case-data/findings.json` carries `audit_ids`.
2. Each `audit_id` (e.g. `sift-jgore-20260616-NNN`) is the response ID of a
   `run_command` call — recorded both in the **proxy chain**
   (`audit-chains/…-proxy.jsonl`, with its correlation ID and OPA verdict) and
   in **`case-data/case-audit/sift-mcp.jsonl`** (the trail `record_finding`
   validates against). Provenance is FULL — not the `supporting_commands`
   fallback — because the audit_ids resolve.
3. The `record_finding` call itself appears in the proxy chain with its own
   correlation ID and policy decision.
4. The evidence those commands read is the registered `.E01` in
   `case-data/evidence.json` (path + SHA-256).

Verify the proxy chain is intact:

```bash
agentcontainer audit verify ffb9490a42197fac-proxy
```

## Not included (deliberately)

- The raw `.E01` image and extracted artifacts (too large for git) — referenced
  by SHA-256 in `evidence.json` and by `audit_id` in the chains.
- The full recursive `fls` listing (large) — referenced by `audit_id` in the
  proxy/case-audit chains, not inlined.

The JSONL files are **hash-chained — do not edit them**; any modification breaks
`agentcontainer audit verify`. (`.gitattributes` disables line-ending
normalization to keep the bytes — and the hashes — intact.)
