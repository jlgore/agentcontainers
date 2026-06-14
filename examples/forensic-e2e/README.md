# Forensic E2E (proxy path, read-only evidence)

A reproducible, **proxy-path** forensic demo: the SIFT gateway runs as a
kernel-enforced container backend *behind* the MCP proxy, so every forensic tool
call is policy-evaluated, approval-gated, correlation-tagged, and recorded in the
proxy + enforcer audit chains. Acquired evidence is mounted **read-only**.

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

## What it proves

- **Enforced path** — calls go through `agentcontainer mcp start` (the proxy),
  not a standalone gateway, so correlation IDs + approval + audit apply.
- **Read-only evidence** — the nested `…/evidence:…:ro` mount makes the acquired
  image unwritable inside the gateway while case outputs stay writable:

  ```sh
  agentcontainer exec sift-forensic-agent -- sh -c 'touch /cases/e2e-demo/evidence/x'
  #  -> Read-only file system
  ```

- **Continuous audit** — `agentcontainer audit verify` validates one unbroken
  hash chain across the session (including across proxy restarts).

## Teardown

```sh
./down.sh
```
