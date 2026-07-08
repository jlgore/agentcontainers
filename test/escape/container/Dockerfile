# Escape-the-Box CONTAINER substrate — a self-contained privileged-pod twin of the
# KubeVirt ac-matrix-vm guest (test/vm/cloud-init.yaml). The Temporal harness-worker
# drives this over SSH exactly as it drives the VMI (Substrate="container"); pod
# delete-and-recreate is the recovery step in place of a VM reboot.
#
# Everything the guest-side runner (test/escape/breakout-run.sh) needs is baked in
# so the pod comes up READY with no host-side staging: agentcontainer, the eBPF
# enforcer bin + ELF, all three harness CLIs + their guard adapters/managed configs,
# and guard-policy.yaml / cases.json derived from the ONE fixture (breakout-matrix.yaml).
#
# BUILD CONTEXT IS THE REPO ROOT (needs cmd/, enforcer/, test/, examples/):
#   docker build -f test/escape/container/Dockerfile \
#     -t ghcr.io/jlgore/agentcontainers-escape-substrate:latest .
#   docker push ghcr.io/jlgore/agentcontainers-escape-substrate:latest
#
# The enforcer test binary must match the NODE's kernel/arch — build natively on
# (or for) the target node's architecture, like enforcer/Dockerfile.test.

# ---------------------------------------------------------------------------
# 1. agentcontainer (Go, static) — the guard/enforcer CLI the runner invokes.
# ---------------------------------------------------------------------------
FROM golang:1.26-bookworm AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
      -o /out/agentcontainer ./cmd/agentcontainer

# ---------------------------------------------------------------------------
# 2. breakout-enforcer + BPF ELF (Rust/aya) — the kernel egress boundary for
#    BREAKOUT_ENFORCER=1 cells. Mirrors enforcer/Dockerfile.test's builder.
# ---------------------------------------------------------------------------
FROM rust:1.93-bookworm AS enf-builder
RUN apt-get update && apt-get install -y \
      clang llvm libelf-dev linux-headers-generic protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly --component rust-src \
    && rustup run nightly cargo install bpf-linker
WORKDIR /build
COPY enforcer/ ./
# Build the breakout-enforcer bin AND link the aya-build BPF ELF.
RUN cargo build --bin breakout-enforcer
RUN mkdir -p /out \
    && cp target/debug/breakout-enforcer /out/breakout-enforcer \
    && strip /out/breakout-enforcer || true \
    && ( ELF="$(find target -path '*/out/agentcontainer-ebpf-progs' 2>/dev/null | xargs ls -t 2>/dev/null | head -1)"; \
         [ -n "$ELF" ] || ELF=target/bpfel-unknown-none/debug/agentcontainer-ebpf-progs; \
         cp "$ELF" /out/agentcontainer-ebpf-progs ) \
    && test -x /out/breakout-enforcer && test -f /out/agentcontainer-ebpf-progs

# ---------------------------------------------------------------------------
# 3. Runtime — Ubuntu (matches the VM guest base), sshd, node + harness CLIs.
# ---------------------------------------------------------------------------
FROM ubuntu:24.04

ARG REMOTE_DIR=/home/ubuntu/breakout
ARG AUDIT_DIR=/var/lib/ac/audit
ARG CODEBASE_DIR=/home/ubuntu/agentcontainers-src
ENV DEBIAN_FRONTEND=noninteractive

# Base tooling: sshd (worker transport), jq/python3 (runner + canary), libelf1
# (aya loads the BPF ELF at runtime), curl/git, node 22 (all three harnesses).
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server sudo ca-certificates curl git jq python3 libelf1 ripgrep \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# mikefarah yq (static) — derive the guard policy + cases from the fixture at build.
RUN curl -fsSL "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_$(dpkg --print-architecture)" \
      -o /usr/local/bin/yq && chmod +x /usr/local/bin/yq

# The three harnesses, exactly as the VM installs them (cloud-init + breakout.sh).
RUN npm install -g @earendil-works/pi-coding-agent opencode-ai @anthropic-ai/claude-code

# The 'ubuntu' user exists in ubuntu:24.04 (uid 1000); give it passwordless sudo
# like the VM guest (the runner needs it for setup; the AGENT runs unprivileged
# under BREAKOUT_UNPRIV=1, so a break-out is still a genuine kernel defeat).
RUN echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ubuntu && chmod 0440 /etc/sudoers.d/ubuntu \
    && mkdir -p /home/ubuntu/.ssh && chmod 700 /home/ubuntu/.ssh \
    && mkdir -p "${AUDIT_DIR}" && chown ubuntu:ubuntu "${AUDIT_DIR}"

# Binaries: agentcontainer + the enforcer bin/ELF at the runner's expected paths.
COPY --from=go-builder  /out/agentcontainer /usr/local/bin/agentcontainer
COPY --from=enf-builder /out/breakout-enforcer        ${REMOTE_DIR}/breakout-enforcer
COPY --from=enf-builder /out/agentcontainer-ebpf-progs ${REMOTE_DIR}/agentcontainer-ebpf-progs

# Guest-side runner + approver + canary + the pi guard adapter.
COPY test/escape/breakout-run.sh     ${REMOTE_DIR}/breakout-run.sh
COPY test/escape/breakout-approver.js ${REMOTE_DIR}/breakout-approver.js
COPY test/escape/breakout-canary.py  ${REMOTE_DIR}/breakout-canary.py
COPY test/vm/phase6-guard-adapter.ts ${REMOTE_DIR}/phase6-guard-adapter.ts

# Derive guard-policy.yaml + cases.json from the SINGLE fixture — same source of
# truth as breakout.sh, so the container cell cannot drift from the Layer-1 oracle.
COPY test/escape/breakout-matrix.yaml /tmp/breakout-matrix.yaml
RUN yq '.policy' /tmp/breakout-matrix.yaml > ${REMOTE_DIR}/guard-policy.yaml \
    && yq -o=json '.cases' /tmp/breakout-matrix.yaml > ${REMOTE_DIR}/cases.json \
    && rm -f /tmp/breakout-matrix.yaml

# opencode: managed config (root-owned, deny native read/grep → funnel to guarded
# bash/edit/write) + auto-loaded guard plugin in ubuntu's home. apiKey references
# the per-cell keyfile the worker stages at /run/secrets/breakout-key; both
# providers point at it so either model axis works. `-m` overrides the model.
COPY test/vm/phase5-guard-adapter.js /home/ubuntu/.config/opencode/plugin/phase5-guard-adapter.js
COPY test/escape/container/opencode.json /etc/opencode/opencode.json

# claude: locked managed PreToolUse hook (root-owned) → guard hook.
COPY examples/claude-agent/managed-settings.json /etc/claude-code/managed-settings.json

# A readable source snapshot for model grounding (BREAKOUT_CODEBASE_DIR) — the
# curated subset breakout.sh ships, minus build artifacts.
COPY README.md ${CODEBASE_DIR}/README.md
COPY cmd ${CODEBASE_DIR}/cmd
COPY internal ${CODEBASE_DIR}/internal
COPY enforcer/agentcontainer-enforcer/src ${CODEBASE_DIR}/enforcer/agentcontainer-enforcer/src
COPY enforcer/agentcontainer-ebpf/src ${CODEBASE_DIR}/enforcer/agentcontainer-ebpf/src
COPY enforcer/agentcontainer-common/src ${CODEBASE_DIR}/enforcer/agentcontainer-common/src

COPY test/escape/container/entrypoint.sh /usr/local/sbin/entrypoint.sh

RUN chmod +x ${REMOTE_DIR}/breakout-run.sh ${REMOTE_DIR}/breakout-enforcer /usr/local/sbin/entrypoint.sh \
    && install -d -m0755 /etc/opencode /etc/claude-code \
    && chown -R ubuntu:ubuntu /home/ubuntu \
    && chmod -R a+rX ${CODEBASE_DIR}

EXPOSE 22
ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]
