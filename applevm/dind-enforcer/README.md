# applevm microVM image with the enforcer embedded

The applevm microVM workload image — plain `docker:dind` with the
**agentcontainers enforcer embedded**. The enforcer image is baked in as a
tarball and loaded into the in-VM Docker daemon on startup, so the enforcer
sidecar runs **without pulling from ghcr** at runtime (offline / air-gapped, and
pinned to the embedded image).

## How it works

`internal/sidecar` starts the enforcer as a sidecar container and `EnsureImage`
checks the local image store **before** pulling. This image makes that local
check succeed:

- `Dockerfile` shadows `docker:dind`'s `dockerd-entrypoint.sh` with a wrapper
  (preserving the original as `real-dockerd-entrypoint.sh`). The wrapper hands
  off to the real entrypoint to run dockerd, and in the background — once dockerd
  is up — runs `docker load -i /opt/ac/enforcer.tar`.
- Because the agentcontainers runtime invokes `dockerd-entrypoint.sh dockerd
  -H ...`, swapping that script needs **no daemon or runtime code change**.
- The tarball is `docker save`'d with the enforcer's ghcr tag preserved, so
  `docker load` restores the exact ref `internal/sidecar.DefaultEnforcerImage`
  looks up locally.

## Build

Built in CI for `linux/arm64` (Apple silicon microVMs) — see
`.github/workflows/applevm-dind.yml`. It saves the arm64 enforcer image into the
build context, then buildx-builds and pushes
`ghcr.io/<owner>/agentcontainer-applevm-dind`. Trigger via the
**applevm-dind-enforcer** workflow (override the embedded enforcer with the
`enforcer_ref` input) or by pushing changes under `applevm/dind-enforcer/`.

`enforcer.tar` is produced by CI and is git-ignored — never commit it.

## Use (opt-in)

The default applevm workload remains `docker:dind`. Opt into the embedded image
per run:

```bash
AC_APPLEVM_DIND_IMAGE=ghcr.io/<owner>/agentcontainer-applevm-dind \
  sudo -E ./.build/release/ac-applevmd
```

(Prefer the `@sha256:...` digest form for reproducibility — the CI run summary
prints it.) Then `agentcontainer run --runtime=applevm` starts the enforcer from
the embedded image; verify by confirming no ghcr pull occurs and the enforcer
container reports the embedded image ref.

## Note

This bundles the enforcer **userspace image** into the VM. Whether the enforcer
can actually attach its BPF-LSM hooks still depends on the **kernel** — use the
BPF-LSM + BTF kernel from `applevm/kernel/` (the default; see
`applevm/ac-applevmd/README.md`).
