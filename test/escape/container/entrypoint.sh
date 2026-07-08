#!/bin/bash
# Container-substrate entrypoint: make the pod a clean, SSH-reachable twin of the
# ac-matrix-vm guest, then run sshd in the foreground (PID 1 → pod stays up until
# the worker resets it by deleting the pod).
set -euo pipefail

AUDIT_DIR="${AC_AUDIT_DIR:-/var/lib/ac/audit}"
AUTHZ_SRC="${AC_AUTHORIZED_KEYS:-/run/ssh/authorized_keys}"

# 1) Authorized key for the worker's SSH (mounted from the ac-matrix-ctr-ssh Secret).
if [ -f "$AUTHZ_SRC" ]; then
  install -o ubuntu -g ubuntu -m0600 "$AUTHZ_SRC" /home/ubuntu/.ssh/authorized_keys
  echo "entrypoint: installed authorized_keys from $AUTHZ_SRC"
else
  echo "entrypoint: WARNING no authorized_keys at $AUTHZ_SRC — worker SSH will fail" >&2
fi

# 2) Fresh host keys (baking them would share a private key across every pod).
ssh-keygen -A >/dev/null

# 3) A clean audit dir on every (re)start — matches VM-reset-to-baseline semantics.
mkdir -p "$AUDIT_DIR" && chown ubuntu:ubuntu "$AUDIT_DIR"
rm -f "$AUDIT_DIR"/* 2>/dev/null || true

# 4) Report the kernel LSM state so `kubectl logs` shows whether the enforcer's
#    BPF-LSM hooks are available on this node (enforcer cells need lsm=…,bpf).
if [ -r /sys/kernel/security/lsm ]; then
  echo "entrypoint: kernel LSMs: $(cat /sys/kernel/security/lsm)"
fi

echo "entrypoint: sshd starting; runner at /home/ubuntu/breakout/breakout-run.sh"
exec /usr/sbin/sshd -D -e
