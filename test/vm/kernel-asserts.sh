#!/usr/bin/env bash
# Phase 3: build the enforcer BPF integration suite locally and run it on the
# capability-matrix VM's REAL kernel, proving the kernel hard-boundary classes
#   C7 declared-egress allow / C8 undeclared-egress deny / C9 non-allowlisted exec deny
# plus that the BPF LSM actually attached (not self-skipped).
#
# Native build: the local WSL2 toolchain (nightly + bpf-linker + clang) matches
# the VM glibc (both Ubuntu noble, 2.39). Set AC_SKIP_BUILD=1 to reuse a build.
set -euo pipefail

cd "$(dirname "$0")"
NS=ac-matrix
VM=ac-matrix-vm
KEY="${AC_MATRIX_SSH_KEY:-$HOME/.ssh/ac-matrix-vm}"
ENFORCER="$(cd ../../enforcer && pwd)"
SSHOPTS=(-t "-o StrictHostKeyChecking=no" -t "-o UserKnownHostsFile=/dev/null" -t "-o LogLevel=ERROR")
guest() { virtctl ssh "ubuntu@vmi/$VM" -n "$NS" -i "$KEY" "${SSHOPTS[@]}" -c "$1"; }

# 1) Build (the same invocation as Dockerfile.test / CI).
if [ "${AC_SKIP_BUILD:-0}" != 1 ]; then
  echo "==> building bpf_integration (native)…"
  ( cd "$ENFORCER" && cargo test -p agentcontainer-enforcer --test bpf_integration --no-run )
fi

# 2) Locate the content-hashed test binary + the aya-build eBPF ELF.
BIN=$(ls -t "$ENFORCER"/target/debug/deps/bpf_integration-* 2>/dev/null | grep -v '\.d$' | head -1)
# Newest canonical aya-build ELF (the top-level out/ copy, not the nested dupes).
ELF=$(find "$ENFORCER"/target -path '*/out/agentcontainer-ebpf-progs' 2>/dev/null | xargs ls -t 2>/dev/null | head -1)
[ -n "$ELF" ] || ELF="$ENFORCER/target/bpfel-unknown-none/debug/agentcontainer-ebpf-progs"
[ -x "$BIN" ] || { echo "FAIL: test binary not found (build first)"; exit 1; }
[ -f "$ELF" ] || { echo "FAIL: ebpf ELF not found"; exit 1; }
echo "    bin: $BIN"
echo "    elf: $ELF"

# 3) Copy artifacts into the guest. Strip the (huge, unstripped) debug test
#    binary first — it cuts the virtctl-tunnelled transfer from ~400MB to tens of MB.
echo "==> copying artifacts to the VM…"
STRIPPED=$(mktemp)
cp "$BIN" "$STRIPPED" && strip "$STRIPPED" 2>/dev/null || cp "$BIN" "$STRIPPED"
virtctl scp "$STRIPPED" "ubuntu@vmi/$VM:/home/ubuntu/bpf_integration" -n "$NS" -i "$KEY" "${SSHOPTS[@]}"
rm -f "$STRIPPED"
virtctl scp "$ELF" "ubuntu@vmi/$VM:/home/ubuntu/agentcontainer-ebpf-progs" -n "$NS" -i "$KEY" "${SSHOPTS[@]}"

# 4) libelf1 is needed at runtime to load BPF.
guest "dpkg -s libelf1 >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libelf1 || (sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libelf1)"
guest "chmod +x /home/ubuntu/bpf_integration"

# 5) Run as root (cgroup rw + CAP_BPF/SYS_ADMIN via sudo), single-threaded.
echo "==> running the suite on the VM kernel…"
guest "sudo AC_BPF_ELF_PATH=/home/ubuntu/agentcontainer-ebpf-progs /home/ubuntu/bpf_integration --test-threads=1 --nocapture 2>&1 | grep -vE '^\s*$' | tail -200"
