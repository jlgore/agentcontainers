# applevm kernel (BPF-LSM + BTF enabled)

The stock Apple containerization kernel and the Kata 3.17.0 kernel both lack
`CONFIG_BPF_LSM` and BTF, so the agentcontainers eBPF/BPF-LSM enforcer cannot
attach its LSM hooks inside the microVM (verified via `/proc/config.gz` and the
absent `/sys/kernel/btf/vmlinux`). This directory builds a kernel that closes
that gap.

## What it is

- `config-fragment` — the extra `CONFIG_*` options (LSM framework, `CONFIG_BPF_LSM`,
  BTF). Merged onto apple/containerization's `kernel/config-arm64` base, then
  `make olddefconfig` resolves dependencies.
- The build runs in CI — see `.github/workflows/applevm-kernel.yml`.

## Why CI, not the Mac

Building the kernel is a **pure Linux cross-compile** (arm64). macOS is only
needed to *run* the kernel under Virtualization.framework. The workflow
cross-compiles on `ubuntu-latest` (so it doesn't depend on arm64 runner
availability) and — crucially — uses an Ubuntu image with a modern `pahole`,
which is what generates BTF (the containerization builder image ships
`ubuntu:focal`, whose pahole is too old for current kernels).

## Build it

Trigger the **applevm-kernel** workflow (Actions tab → Run workflow), or push a
change under `applevm/kernel/`. It pins the apple/containerization ref so the
kernel version + base config match the library the daemon links; override via
the `containerization_ref` input. Download the `ac-applevm-vmlinux` artifact
(contains `vmlinux` and the resolved `.config`).

## Use it on the Mac

```bash
cp vmlinux ~/.agentcontainers/applevm/kernel    # or set AC_APPLEVM_KERNEL
# boot a VM, then verify inside it:
#   zcat /proc/config.gz | grep -E 'BPF_LSM|DEBUG_INFO_BTF'   -> =y
#   ls /sys/kernel/btf/vmlinux                                -> present
#   cat /sys/kernel/security/lsm                              -> includes "bpf"
```

Once those hold, the in-VM enforcer can attach its BPF-LSM hooks instead of
degrading to audit/off.
