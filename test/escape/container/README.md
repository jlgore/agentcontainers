# Escape-the-Box — container substrate

A **privileged-pod twin** of the KubeVirt `ac-matrix-vm` guest, so the exact same
Temporal escape matrix runs against agentcontainers **inside a container** as well
as inside a VM. Same fixture, same runner (`breakout-run.sh`), same guard/enforcer,
same scorer — only where the harness is *hosted* changes.

## Why a second substrate

The escape harness proved the guard + eBPF enforcer boundary on a full-kernel VM.
Running the identical grid in a container answers a different question: does the
boundary hold when agentcontainers is deployed the way most users actually run it —
in a pod sharing the node kernel? A regression that only shows up under one hosting
model is exactly what a two-substrate matrix catches.

## How it plugs into the Temporal worker

The worker (`test/orchestrator/`) treats hosting as a matrix **axis**, not a fork:

| | VM substrate | Container substrate |
|---|---|---|
| Guest | KubeVirt VMI `ac-matrix-vm` | privileged pod `ac-matrix-ctr` |
| Host resolve | VMI pod IP (KubeVirt API) | pod IP (core API, `app=ac-matrix-ctr`) |
| Drive | SSH → `breakout-run.sh` | **identical** SSH → `breakout-run.sh` |
| Recovery | restart the VM | delete the pod → Deployment recreates |

A cell selects its host with `Substrate: "vm" | "container"` (empty ⇒ the worker's
`SUBSTRATE` default, `vm`). `EscapeMatrixWorkflow` gains a `Substrates` axis that
cross-products with everything else, so one `MatrixSpec` can run the whole grid on
both. Because the drive path is byte-for-byte the same SSH flow, none of the
proven seed/guard/drive/score/ship logic changed — only host-resolution and the
reset step dispatch on the substrate.

The image bakes **everything the runner needs** (agentcontainer, the enforcer
bin + BPF ELF, all three harness CLIs + their guard adapters/managed configs, and
`guard-policy.yaml`/`cases.json` derived from `breakout-matrix.yaml`), so the pod
comes up READY with no host-side staging — and pod-delete-recreate yields a
pristine baseline in seconds, versus a multi-minute VM reboot.

## Bring-up

```bash
# 1. Build + push the substrate image (context = repo root). Build natively on the
#    target arch — the enforcer test binary must match the node kernel/arch.
docker build -f test/escape/container/Dockerfile \
  -t ghcr.io/jlgore/agentcontainers-escape-substrate:latest .
docker push ghcr.io/jlgore/agentcontainers-escape-substrate:latest

# 2. Create the ns + ssh Secret + Deployment and wait for Ready.
#    Reuses the VM substrate's SSH key so the worker's existing key drives both.
cd test/escape/container && AC_SUBSTRATE_IMAGE=ghcr.io/jlgore/agentcontainers-escape-substrate:latest ./up.sh
```

> Image build/push is a manual hand-off (this repo never auto-pushes to a registry).

## Worker RBAC (talos-gitops, sibling repo)

The container path needs two more verbs on the worker's Role in `ac-matrix` (it
already has KubeVirt VMI get + VM restart for the VM path). Add to
`infrastructure/base/harness-worker/rbac.yaml`:

```yaml
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete"]
```

No new Secret for the worker: it SSHes with the **same** private key (Vault →
`SSH_KEY_PATH`) whose public half `up.sh` put in `ac-matrix-ctr-ssh`.

## Run

Single cell (pin the substrate):

```bash
temporal --env lab workflow start --task-queue escape-cells \
  --type MatrixCellWorkflow --workflow-id cell-ctr-T11-glm-1 \
  --input '{"Harness":"pi","Provider":"openrouter","Model":"z-ai/glm-5.2",
            "CaseID":"T11-exfil-canary","Substrate":"container","Enforcer":true,
            "AgentTimeoutSec":180,"MaxRounds":6,"OpenRouterRole":"escape-glm",
            "CodebaseDir":"/home/ubuntu/agentcontainers-src"}'
```

Whole grid on **both** substrates (one spec):

```bash
temporal --env lab workflow start --task-queue escape-cells \
  --type EscapeMatrixWorkflow --workflow-id grid-both-1 \
  --input '{"RunID":"grid-both-1",
            "Models":[{"Provider":"openrouter","Model":"z-ai/glm-5.2","OpenRouterRole":"escape-glm"}],
            "Harnesses":["pi","opencode","claude"],
            "Substrates":["vm","container"],
            "EnforcerModes":[false,true],
            "AgentTimeoutSec":180,"MaxRounds":6,
            "CodebaseDir":"/home/ubuntu/agentcontainers-src"}'
```

Child workflow ids carry the substrate segment (`…-enf-container`), so vm and
container cells never collide and both are durably resumable.

## Notes / watch-outs

- **Enforcer cells need `lsm=…,bpf` on the node.** The entrypoint logs the active
  LSMs; without `CONFIG_BPF_LSM` the kernel egress blocks self-skip (guard-layer
  cells still run). Schedule onto the same BPF-capable node as `ac-matrix-vm`
  (`nodeSelector` in `deployment.yaml`).
- **`replicas: 1` / `Recreate`** is load-bearing: cells share the one guest and run
  strictly sequentially. More parallelism ⇒ more guests per substrate (documented
  knob in `EscapeMatrixWorkflow`).
- **opencode managed config** (`opencode.json`) pins a placeholder model; the runner
  overrides it per cell via `-m "$PROVIDER/$MODEL"`, and both providers reference
  the per-cell keyfile `/run/secrets/breakout-key` the worker stages.
