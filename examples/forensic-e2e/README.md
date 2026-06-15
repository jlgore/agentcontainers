# Forensic E2E (proxy path, read-only evidence)

A reproducible, **proxy-path** forensic demo: the SIFT gateway runs as a
kernel-enforced container backend *behind* the MCP proxy, so every forensic tool
call is policy-evaluated, approval-gated, correlation-tagged, and recorded with a
verdict in the `<session>-proxy` audit hash chain. Acquired evidence is mounted
**read-only**.

> The separate `<session>-enforcer` chain is fed from kernel (eBPF) StreamEvents.
> On hosts without full BPF-LSM it stays empty even though policy is enforced
> (read-only mount, capability/guard/approval denials) — lean on the `-proxy`
> chain + the read-only mount for the audited-enforcement story, not the
> `-enforcer` chain.

## Why this exists

The earlier VM demo (`~/e2e-up.sh`) ran the gateway as a *standalone* remote MCP
server and pointed the agent straight at it. That bypassed the project's whole
point: the proxy's correlation IDs, the approval broker, and the audit chain were
never exercised, and the gateway could write to the evidence. This example runs
the gateway **through** the proxy with split mounts, and is checked into the repo
so a fresh VM reproduces it from source — no VM-local script required.

## Layout the case like this

```
/cases/<case>/
  evidence/<image>.E01     # acquired image — mounted READ-ONLY
  findings/ timeline/ audit/ extractions/   # examiner outputs — writable
```

## Run

```sh
# Prereqs: scripts/bootstrap.sh has installed Docker, the agentcontainer CLI
# (built from THIS source), the enforcer image, and BPF LSM. The SIFT gateway
# image (sift-gateway:e2e) is built — see examples/sift-platform/build.sh.

CASE_DIR=/cases/e2e-demo ./up.sh
```

`up.sh` starts the agent under enforcement and launches the MCP proxy, which
brings up the gateway as an enforced container backend mounting the case
(evidence read-only). `agentcontainer.json` references `/cases/e2e-demo`; for a
different case, set `CASE_DIR` and `up.sh` renders a copy with the paths
substituted.

## Evidence is presented as a raw device (EWF/E01)

The gateway image's bundled sleuthkit (Debian TSK + libewf2) **segfaults reading
`.E01` directly** via libewf. So `up.sh` runs `ewfmount` on the **host** to decode
the EWF and expose a flat raw image at `<case>/.ewfraw/ewf1`; the gateway binds
that **read-only** (`…/.ewfraw:…/evidence-raw:ro`) and TSK reads it natively — no
libewf in the container path. Analyze evidence at
`/cases/<case>/evidence-raw/ewf1`. The original `.E01` stays mounted read-only at
`/cases/<case>/evidence/` for integrity/registration. Requires `ewf-tools` on the
host and `user_allow_other` in `/etc/fuse.conf` (so the Docker daemon can
traverse the FUSE mount, via `ewfmount -X allow_root`); `up.sh` sets these up.

Use `fsstat`/`fls` directly on the raw image — this is a logical NTFS volume, so
`mmls` (partition-table lister) finds nothing.

## What it proves

- **Enforced path** — calls go through `agentcontainer mcp start` (the proxy),
  not a standalone gateway, so correlation IDs + approval + audit apply.
- **Read-only evidence** — the nested `…/evidence:…:ro` mount makes the acquired
  image unwritable inside the gateway while case outputs stay writable. Prove it
  through the proxy (the call is policy-gated and audited):

  ```sh
  # via the gateway's run_command tool (writing into evidence/ fails):
  #   run_command(["dd","if=/dev/null","of=/cases/e2e-demo/evidence/x"])
  #   -> "Read-only file system"
  ```

  Note: `agentcontainer exec … -- sh -c '…'` is NOT a read-only test — the guard
  denies `sh -c` (M3 wrapper-bypass defense), and every `exec` is HITL approval-
  gated (`Choice [d/o/s/p]`). Those are separate enforcement layers, not the ro
  mount.

- **Continuous audit** — each proxied tool call is recorded with a verdict and
  correlation ID in the `<session>-proxy` hash chain. Find the session and
  verify the chain:

  ```sh
  agentcontainer audit list                       # find <session-id>
  agentcontainer audit show  <session-id>-proxy   # tool_call entries + verdicts
  agentcontainer audit verify <session-id>-proxy  # -> OK: N entries, chain intact
  ```

  (`audit verify` takes a session id; the kernel `<session>-enforcer` chain is a
  separate file fed from enforcer events.)

## Teardown

```sh
./down.sh
```
