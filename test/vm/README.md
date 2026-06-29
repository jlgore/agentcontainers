# Capability-matrix VM substrate (Phase 2)

A KubeVirt VM that gives the cross-harness capability test matrix a **real guest
kernel** — so the eBPF-LSM (`bprm_check`) and egress hooks the enforcer relies on
arm for real, instead of self-skipping the way they would inside a privileged
Job that shares the node kernel. See the design at `docs` → Project → Test Matrix.

## What it is

- `vm.yaml` — a CDI `DataVolume` (Ubuntu 24.04 cloud image) + a `VirtualMachine`,
  pinned via `nodeSelector` to `talos-node` (the only node exposing `/dev/kvm`;
  `talos-node-2` is unreachable). cloud-init lives in `cloud-init.yaml` and is
  loaded by `up.sh` into the `ac-matrix-cloudinit` Secret (inline userData
  exceeds KubeVirt's 2048-byte cap). cloud-init:
  1. **arms the bpf LSM** — appends `bpf` to the kernel `lsm=` cmdline and reboots
     once (Ubuntu compiles `CONFIG_BPF_LSM=y` but doesn't enable `bpf` by
     default). Without this the enforcer self-skips and C7–C9 pass vacuously.
  2. installs substrate tooling (node, `@anthropic-ai/claude-code`, `opencode-ai`).
- `up.sh` / `down.sh` — bring up / tear down. `up.sh` generates an SSH keypair at
  `~/.ssh/ac-matrix-vm` and injects the public key.
- `smoke.sh` — Phase-2 acceptance: **hard**-checks the kernel substrate (bpf in
  the active LSM list, `CONFIG_BPF_LSM=y`, BTF present) and **soft**-checks tooling.

## Usage

```bash
cd test/vm
./up.sh        # apply, import the image, wait for the VMI to run
./smoke.sh     # validate the substrate (re-run until green; cloud-init reboots once)
./down.sh      # tear down
```

SSH in directly:

```bash
virtctl ssh ubuntu@vmi/ac-matrix-vm -n ac-matrix -i ~/.ssh/ac-matrix-vm \
  -t '-o StrictHostKeyChecking=no'
```

## Prerequisites

`kubectl` (context `admin@talos-cluster`) and `virtctl` on PATH; KubeVirt + CDI
installed on the cluster (they are). The cluster must reach
`cloud-images.ubuntu.com` for the CDI import.

## Scope

Phase 2 proves the substrate is real (kernel can do BPF-LSM, tooling present).
Actually *running* the enforcer to confirm it attaches its LSM programs and the
C7–C9 egress/exec asserts are **Phase 3**; the Layer-2 agent cells are Phase 4+.
