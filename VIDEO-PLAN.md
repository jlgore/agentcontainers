# Demo video plan — agentcontainers

**Deadline:** Mon Jun 15, 11:45 PM EDT. Target length: **3–5 min**. Record on the
VM (`sansforensics@192.168.8.129`) where the stack is live.

## The one sentence
> **Agentcontainers is a zero-trust execution + audit layer that makes
> autonomous SIFT forensic investigations defensible** — kernel-enforced
> isolation, read-only evidence, per-tool secret gating, and a tamper-evident
> audit chain, all reproducible from published artifacts.

Every segment should visibly tie back to one judging hook: **enforcement,
provenance/traceability, autonomous correction, structured narrative,
reproducibility.**

---

## Pre-flight (do FIRST, morning of — ~45 min, de-risks the record)

Run these and confirm green BEFORE recording. If any fails, use its fallback.

1. **Artifacts pull clean (judge reproducibility).** On a *fresh* shell:
   - `agentcontainer version` → `0.1.3` (pulled, not built).
   - `docker pull ghcr.io/jlgore/{agentcontainer-enforcer,sift-gateway,claude-agent}:latest` → all OK.
2. **Enforcer healthy.** `agentcontainer enforcer diagnose` → all PASS, SERVING.
3. **Proxy-path forensic E2E comes up.** `cd examples/forensic-e2e && CASE_DIR=/cases/e2e-demo ./up.sh`
   → "Backends:" line; gateway is an enforced `ac-mcp-sift-*` container.
4. **Read-only evidence proof works.**
   `agentcontainer exec sift-forensic-agent -- sh -c 'touch /cases/e2e-demo/evidence/x'`
   → `Read-only file system`. (Verified working.)
5. **At least one real forensic tool call produces a finding + audit entry.**
   - ✅ **Diagnosed + working (Jun 15).** A `run_command(["fsstat",
     "/cases/e2e-demo/evidence-raw/ewf1"])` through the proxy returns real NTFS
     output (exit 0) and records a `tool_call`/`allow` entry in the
     `<session>-proxy` hash chain. Three defects were found and fixed to get
     here — do NOT skip the pre-flight, confirm all three hold:
     1. **Gateway image must contain TSK.** The published
        `ghcr.io/jlgore/sift-gateway:e2e` had `sleuthkit` dropped from its
        Dockerfile → `run_command` returned *"Binary 'fsstat' not found"*.
        Rebuilt with `sleuthkit ewf-tools` and pushed. Verify:
        `docker run --rm --entrypoint sh ghcr.io/jlgore/sift-gateway:e2e -c 'which fsstat'`.
     2. **TSK segfaults on `.E01`.** The container's libewf build SIGSEGVs on
        any EWF read. `up.sh` works around it by `ewfmount`-ing the E01 to a raw
        device on the host and binding it read-only as `evidence-raw/ewf1`;
        analyze the raw, not the `.E01`.
     3. Use **`fsstat`/`fls`**, not `mmls` — this is a logical NTFS volume with
        no partition table, so `mmls` returns nothing.
   - **Fallbacks if needed:** (a) small working raw sample instead of the 12 GB
     image; (b) show the pre-existing `508-intrusion` case as "what a completed
     investigation produces," clearly labeled as a prior run.
6. **Audit chain verifies.** `agentcontainer audit list` → grab the session →
   `agentcontainer audit verify <session-id>-proxy` → one continuous chain.
   (`verify` requires a session-id argument; the no-arg form errors.)
7. Screen/terminal recorder ready (asciinema for crisp terminal, or OBS for
   screen + voiceover). Font large, terminal wide, scrollback cleared.

---

## Shot list (record in segments; stitch in post)

### 0. Cold open (15s)
- Title card + the one sentence. Optionally a single striking frame: the
  `Read-only file system` denial on evidence.

### 1. Reproducibility — "a judge runs this" (40s)
- Fresh clone (or pre-cloned) → `sudo ./scripts/bootstrap.sh` (fast-forward in
  post; show it **pulling** the CLI release + enforcer image, no compiler).
- `agentcontainer version` → 0.1.3.
- **Beat:** "No build step. The CLI, enforcer, and SIFT gateway are all pulled
  from GitHub — same as a judge would."

### 2. The enforced architecture (45s)
- `agentcontainer enforcer diagnose` → all PASS, **SERVING at 127.0.0.1** (mTLS,
  loopback).
- `examples/forensic-e2e/up.sh` → proxy launches the **SIFT gateway as a
  kernel-enforced container backend** (not a standalone server).
- `docker ps` → the `ac-mcp-sift-*` backend, hardened (read-only rootfs).
- **Beat:** "The forensic toolserver runs behind the MCP proxy under the eBPF
  enforcer — every tool call is policy-evaluated, correlated, and audited."

### 3. Zero-trust, shown live (60s) — the money shots
- **Read-only evidence (verified):** through the proxy,
  `run_command(["dd","if=/dev/null","of=/cases/e2e-demo/evidence/x"])` →
  `Read-only file system`; writing under `extractions/`/`findings/` succeeds.
  (Evidence immutable, outputs writable; both calls land in the `-proxy` chain.)
  - ⚠️ Do NOT use `agentcontainer exec … sh -c 'touch …'` for this — `sh -c` is
    guard-denied (M3 wrapper-bypass), so you'd film the wrong denial.
- **Guard / HITL approval (verified):** `agentcontainer exec sift-forensic-agent
  -- sh -c 'id'` → **denied: "interpreter sh with -c flag denied (M3)"**. And any
  `agentcontainer exec … -- <binary>` prompts the approval broker
  (`Choice [d/o/s/p]`) — approve/deny on camera. This is the wrapper-bypass +
  HITL money shot.
- **Secret gating:** show a restricted secret only readable by its tool during
  an active tool-call window (or describe briefly if time-constrained).
- **Beat:** "Tampering with evidence, wrapper-bypassing the guard, or acting
  without approval are all policy-gated and audited."
  - ⚠️ **Accuracy:** the kernel `<session>-enforcer` audit chain is **empty on
    this VM** (BPF-LSM/streaming gap). Don't claim "the kernel audit shows the
    denial" — the audited record is the `-proxy` tool_call chain; the read-only
    block is the `:ro` mount (kernel EROFS). Say "policy-enforced and audited,"
    not "kernel audit chain."

### 4. The investigation + traceability (60s)
- Run a real forensic tool call through the proxy: `run_command(["fsstat",
  "/cases/e2e-demo/evidence-raw/ewf1"])` (and `fls` for a file listing) → real
  NTFS output + an `audit_id`. (Evidence is the E01 presented raw via host
  `ewfmount`; see pre-flight #5. Use `fsstat`/`fls`, not `mmls`.)
- Show the recorded call + verdict in the audit chain, then verify it:
  `agentcontainer audit list` → `agentcontainer audit show <session-id>-proxy`
  (the `tool_call`/`allow` entry with its correlation ID) →
  `agentcontainer audit verify <session-id>-proxy` → **one unbroken hash chain**.
- Show the case artifacts: `findings/`, `timeline/`.
- **Beat:** "Every action ties to evidence and to a tamper-evident audit chain —
  the investigation is defensible, not just produced."

### 5. Close (20s)
- Recap the one sentence over the artifact tree + a green
  `agentcontainer audit verify <session-id>-proxy`.
- "Reproducible from source. Policy-enforced. Auditable end to end."

---

## Risks & mitigations
- **E01 readability — RESOLVED (Jun 15).** Host TSK reads it; the gateway needs
  the raw `ewfmount` presentation (its libewf segfaults) and the rebuilt image
  that actually contains `sleuthkit`. All three are fixed and the proxy-path
  `fsstat` + audit entry are confirmed working. Still re-run pre-flight #5 the
  morning of — don't record the investigation segment until it's green again.
- **Kernel `-enforcer` audit chain is empty on this VM** (BPF-LSM gap). The
  audited-enforcement story rides on the `-proxy` tool_call chain + the
  read-only mount — see segment 3's accuracy note. Don't promise a populated
  kernel audit chain on camera.
- **Timing/flakiness** → record each segment separately; keep takes short; it's
  fine to fast-forward `bootstrap`/`up.sh` in edit.
- **Don't show secrets/tokens** on screen (the demo uses `insecureDev` + dummy
  creds; still scrub the terminal).
- **Be honest** about what's live vs. pre-staged (judges value rigor; label the
  508-intrusion case as a prior run if used).

## Assets to have open
- Terminal on the VM (recording).
- The repo `README` / `examples/forensic-e2e/README.md` for any on-screen
  reference.
- A second pane tailing the proxy audit log if you want to show entries landing.
