#!/usr/bin/env bash
# Live "kernel holds" proof — the floor the Phase 5b/6b soft-hook-bypass
# assertions point to. Phases 4-6 prove the guard (soft, per-harness, bypassable)
# gates C1-C6 across Claude Code / opencode / pi. This runs the eBPF enforcer on
# the VM's REAL kernel and shows the SAME capability classes enforced underneath,
# with NO in-harness hook involved:
#
#   C9 exec   — the fixture's C1 shell allowlist applied as the kernel
#               exec-allowlist: cat/ls/grep/tar run; dd/mkfs/nc are denied at the
#               bprm_check LSM hook with EACCES
#               (test_capability_matrix_exec_under_enforcer)
#   C7/C8 egress — a declared host connects; an undeclared host is blocked at the
#               connect4 hook with EPERM
#               (test_egress_allowlist_allows_declared_denies_undeclared)
#   + the existing C9 true/false controls.
#
# This is the "agent disables its own hook, kernel blocks anyway" claim made
# concrete: the enforcer governs a real cgroup and the kernel denies the exec /
# egress regardless of any harness. (Governing a full live agent process tree —
# the `agentcontainer run` containerized path — needs Docker, which this VM
# lacks; the kernel MECHANISM is identical and is what this proves.)
#
# Mirrors kernel-asserts.sh: native build -> strip -> virtctl scp -> run as root.
# AC_SKIP_BUILD=1 reuses an existing build.
set -euo pipefail

cd "$(dirname "$0")"
NS=ac-matrix
VM=ac-matrix-vm
KEY="${AC_MATRIX_SSH_KEY:-$HOME/.ssh/ac-matrix-vm}"
ENFORCER="$(cd ../../enforcer && pwd)"
SSHOPTS=(-t "-o StrictHostKeyChecking=no" -t "-o UserKnownHostsFile=/dev/null" -t "-o LogLevel=ERROR")
guest() { virtctl ssh "ubuntu@vmi/$VM" -n "$NS" -i "$KEY" "${SSHOPTS[@]}" -c "$1"; }

if [ -t 1 ]; then B='\033[1;34m'; G='\033[1;32m'; R='\033[1;31m'; Z='\033[0m'; else B=''; G=''; R=''; Z=''; fi
log() { printf "${B}==>${Z} %s\n" "$*"; }

# The live-demo tests (the new matrix-tied one + the kernel C7/C8/C9 asserts).
TESTS=(
  test_capability_matrix_exec_under_enforcer
  test_egress_allowlist_allows_declared_denies_undeclared
  test_capability_matrix_exfil_under_enforcer
  test_exec_allowlist_denies_nonlisted_binary
  test_exec_allowlist_permits_listed_binary
)

# 1) Build the test binary (same invocation as kernel-asserts.sh / CI).
if [ "${AC_SKIP_BUILD:-0}" != 1 ]; then
  log "building bpf_integration (native)…"
  ( cd "$ENFORCER" && cargo test -p agentcontainer-enforcer --test bpf_integration --no-run )
fi

# 2) Locate the content-hashed test binary + the aya-build eBPF ELF.
BIN=$(ls -t "$ENFORCER"/target/debug/deps/bpf_integration-* 2>/dev/null | grep -v '\.d$' | head -1)
ELF=$(find "$ENFORCER"/target -path '*/out/agentcontainer-ebpf-progs' 2>/dev/null | xargs ls -t 2>/dev/null | head -1)
[ -n "$ELF" ] || ELF="$ENFORCER/target/bpfel-unknown-none/debug/agentcontainer-ebpf-progs"
[ -x "$BIN" ] || { echo "FAIL: test binary not found (build first)"; exit 1; }
[ -f "$ELF" ] || { echo "FAIL: ebpf ELF not found"; exit 1; }
echo "    bin: $BIN"
echo "    elf: $ELF"

# 3) Strip + copy to the guest (cuts the virtctl transfer dramatically).
log "copying artifacts to the VM…"
STRIPPED=$(mktemp)
cp "$BIN" "$STRIPPED" && strip "$STRIPPED" 2>/dev/null || cp "$BIN" "$STRIPPED"
virtctl scp "$STRIPPED" "ubuntu@vmi/$VM:/home/ubuntu/bpf_integration" -n "$NS" -i "$KEY" "${SSHOPTS[@]}"
rm -f "$STRIPPED"
virtctl scp "$ELF" "ubuntu@vmi/$VM:/home/ubuntu/agentcontainer-ebpf-progs" -n "$NS" -i "$KEY" "${SSHOPTS[@]}"
guest "dpkg -s libelf1 >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libelf1 || (sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libelf1)"
guest "chmod +x /home/ubuntu/bpf_integration"

# 4) Run the live-demo tests as root (CAP_BPF/SYS_ADMIN via sudo), single-threaded.
log "running the live kernel-holds tests on the VM kernel…"
guest "sudo AC_BPF_ELF_PATH=/home/ubuntu/agentcontainer-ebpf-progs /home/ubuntu/bpf_integration \
  --test-threads=1 --nocapture ${TESTS[*]} 2>&1 | grep -vE '^\s*\$' | tail -80"

cat <<EOT

${G}If the tests above passed, the kernel boundary is proven live:${Z}
  C9 exec   cat/ls/grep/tar run, dd/mkfs/nc denied (EACCES) at bprm_check
  C7/C8 net declared host allowed, undeclared denied (EPERM) at connect4
  exfil    the python urllib exfil that ESCAPED the guard layer
           (Escape-the-Box F-L1-interp-egress) is denied at connect4; canary empty
…all with NO in-harness hook — the floor the Phase 5b/6b bypass cells point to,
and the close-the-loop on the interpreter-egress escape the guard could not stop.
EOT
