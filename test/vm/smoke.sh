#!/usr/bin/env bash
# Phase 2 smoke test: prove the VM substrate is real.
#
# HARD checks (exit non-zero on failure) — the kernel substrate the enforcer
# depends on, the thing that would otherwise self-skip and turn C7–C9 into
# silent false-greens:
#   - bpf is in the active LSM list (/sys/kernel/security/lsm)
#   - CONFIG_BPF_LSM=y in the running kernel
#   - BTF present (/sys/kernel/btf/vmlinux) for CO-RE
# SOFT checks (warn only) — substrate tooling for later phases:
#   - node, claude-code, opencode present; ac-matrix-ready sentinel written
set -uo pipefail

cd "$(dirname "$0")"
NS=ac-matrix
VM=ac-matrix-vm
KEY="${AC_MATRIX_SSH_KEY:-$HOME/.ssh/ac-matrix-vm}"

# Run a command in the guest over virtctl ssh, capturing stdout. virtctl wants
# the "type/name" target form (user@vmi/<name>).
guest() {
  virtctl ssh "ubuntu@vmi/$VM" -n "$NS" -i "$KEY" \
    -t "-o StrictHostKeyChecking=no" \
    -t "-o UserKnownHostsFile=/dev/null" \
    -t "-o LogLevel=ERROR" \
    -c "$1" 2>/dev/null
}

fail=0
hard() { # name, command, expected-substring
  local out; out=$(guest "$2")
  if echo "$out" | grep -q "$3"; then
    echo "  PASS  $1  ($(echo "$out" | head -1))"
  else
    echo "  FAIL  $1  (got: $(echo "$out" | head -1 | cut -c1-80))"
    fail=1
  fi
}
soft() {
  local out; out=$(guest "$2")
  if echo "$out" | grep -q "$3"; then
    echo "  ok    $1  ($(echo "$out" | head -1))"
  else
    echo "  WARN  $1  (got: $(echo "$out" | head -1 | cut -c1-80))"
  fi
}

echo "== probing guest (waiting for ssh) =="
for _ in $(seq 1 60); do
  guest "true" >/dev/null 2>&1 && break
  sleep 5
done
guest "true" >/dev/null 2>&1 || { echo "FAIL: guest unreachable over virtctl ssh"; exit 1; }

# Wait for setup sentinel (cloud-init may still be installing / mid-reboot).
echo "== waiting for setup to finish =="
for _ in $(seq 1 60); do
  guest "test -f /var/lib/ac-matrix-ready && echo ready" 2>/dev/null | grep -q ready && break
  sleep 10
done

echo "== HARD: kernel substrate =="
hard "bpf-lsm-active"   "cat /sys/kernel/security/lsm"                     "bpf"
hard "config-bpf-lsm"   "grep -h CONFIG_BPF_LSM /boot/config-\$(uname -r)" "CONFIG_BPF_LSM=y"
hard "btf-present"      "test -e /sys/kernel/btf/vmlinux && echo present"  "present"

echo "== SOFT: tooling =="
soft "setup-sentinel"   "test -f /var/lib/ac-matrix-ready && echo ready"   "ready"
soft "node"             "node --version 2>/dev/null || echo missing"       "v"
soft "claude-code"      "claude --version 2>/dev/null || echo missing"     "."
soft "opencode"         "opencode --version 2>/dev/null || echo missing"   "."

echo
if [ "$fail" = 0 ]; then
  echo "SMOKE: PASS — kernel substrate is real; bpf LSM is armed."
else
  echo "SMOKE: FAIL — kernel substrate not ready (see HARD failures above)."
fi
exit "$fail"
