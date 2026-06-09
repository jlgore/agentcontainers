#!/usr/bin/env bash
#
# bootstrap.sh — one-shot workstation setup for running agentcontainers.
#
# Goal: a judge (or anyone) clones this repo onto a fresh Ubuntu host, runs
# this script once, and ends up with everything needed to `agentcontainer run`
# a real agent under full BPF enforcement.
#
# It is idempotent and re-runnable. Enabling the BPF LSM requires a one-time
# kernel cmdline change + reboot; when that is needed the script configures
# GRUB, tells you to reboot, and exits. Run it again after rebooting and it
# picks up where it left off.
#
# Usage:
#   sudo ./scripts/bootstrap.sh [options]
#
# Options:
#   --enforcer-image REF   Enforcer image to pull (default: $ENFORCER_IMAGE or
#                          ghcr.io/jlgore/agentcontainer-enforcer:latest)
#   --skip-lsm             Don't touch GRUB / BPF LSM. Network + DNS enforcement
#                          still works; file/binary credential gating won't.
#   --skip-enforcer-image  Don't pull/tag the enforcer image (e.g. not built yet).
#   --skip-signing-tools   Don't install cosign + crane (sign/verify/attest demos).
#   --skip-smoke           Don't run the post-install enforcer smoke test.
#   -h, --help             Show this help.
#
# Environment:
#   ENFORCER_IMAGE   Same as --enforcer-image.
#   GHCR_TOKEN       If set, `docker login ghcr.io` is performed before pulling
#                    (needed while the fork's package is private). Pairs with
#                    GHCR_USER (default: derived from the image owner).
#   GHCR_USER        Username for the ghcr login (default: image owner).
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration / defaults
# ---------------------------------------------------------------------------
# The CLI hardcodes this upstream reference as the default enforcer image and
# checks the LOCAL image store before pulling. We pull the fork image and tag
# it as this reference so the stock CLI finds it locally with no config change.
UPSTREAM_ENFORCER_IMAGE="ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:latest"
DEFAULT_FORK_IMAGE="ghcr.io/jlgore/agentcontainer-enforcer:latest"

ENFORCER_IMAGE="${ENFORCER_IMAGE:-$DEFAULT_FORK_IMAGE}"
SKIP_LSM=0
SKIP_ENFORCER_IMAGE=0
SKIP_SIGNING_TOOLS=0
SKIP_SMOKE=0

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REBOOT_REQUIRED=0

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RESET='\033[0m'; C_BLUE='\033[1;34m'; C_GREEN='\033[1;32m'
  C_YELLOW='\033[1;33m'; C_RED='\033[1;31m'; C_DIM='\033[2m'
else
  C_RESET=''; C_BLUE=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_DIM=''
fi
step()  { printf "${C_BLUE}==>${C_RESET} %s\n" "$*"; }
ok()    { printf "  ${C_GREEN}OK${C_RESET}  %s\n" "$*"; }
info()  { printf "  ${C_DIM}--${C_RESET}  %s\n" "$*"; }
warn()  { printf "  ${C_YELLOW}!!${C_RESET}  %s\n" "$*" >&2; }
die()   { printf "${C_RED}xx  %s${C_RESET}\n" "$*" >&2; exit 1; }

usage() { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --enforcer-image) ENFORCER_IMAGE="${2:?--enforcer-image needs a value}"; shift 2 ;;
    --enforcer-image=*) ENFORCER_IMAGE="${1#*=}"; shift ;;
    --skip-lsm) SKIP_LSM=1; shift ;;
    --skip-enforcer-image) SKIP_ENFORCER_IMAGE=1; shift ;;
    --skip-signing-tools) SKIP_SIGNING_TOOLS=1; shift ;;
    --skip-smoke) SKIP_SMOKE=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# Phase 0 — preflight
# ---------------------------------------------------------------------------
step "Preflight"

[ "$(id -u)" -eq 0 ] || die "must run as root: re-run with 'sudo $0'"

# The non-root user who should own the docker group membership.
TARGET_USER="${SUDO_USER:-$(id -un)}"
if [ "$TARGET_USER" = "root" ]; then
  warn "no non-root user detected (SUDO_USER unset); will add 'root' to docker group only"
fi
info "target user: $TARGET_USER"

# OS + arch.
. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
case "${ID:-}${ID_LIKE:-}" in
  *debian*|*ubuntu*) : ;;
  *) warn "untested distro '${PRETTY_NAME:-unknown}' — assuming apt/Debian-family" ;;
esac
info "os: ${PRETTY_NAME:-unknown}"

case "$(uname -m)" in
  x86_64)  ARCH=amd64; CRANE_ARCH=x86_64 ;;
  aarch64) ARCH=arm64; CRANE_ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
info "arch: $ARCH ($(uname -m)), kernel $(uname -r)"

# cgroup v2 unified hierarchy is required by the cgroup-scoped BPF hooks.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  ok "cgroup v2 (unified) present"
else
  die "cgroup v2 unified hierarchy not found — enforcement requires it"
fi

# Connectivity (warn-only): the demo run pulls base images + the enforcer.
for url in https://ghcr.io/v2/ https://mcr.microsoft.com/v2/ https://go.dev/; do
  if curl -fsS -m 8 -o /dev/null "$url" 2>/dev/null || [ "$(curl -s -m 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)" -ge 200 ]; then
    info "reachable: $url"
  else
    warn "cannot reach $url — pulls/installs may fail behind this network"
  fi
done

# ---------------------------------------------------------------------------
# Phase 1 — base utilities
# ---------------------------------------------------------------------------
step "Base utilities (curl, ca-certificates, jq, tar)"
need_pkgs=()
for pkg in curl ca-certificates jq tar; do
  dpkg -s "$pkg" >/dev/null 2>&1 || need_pkgs+=("$pkg")
done
if [ ${#need_pkgs[@]} -gt 0 ]; then
  info "installing: ${need_pkgs[*]}"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need_pkgs[@]}"
  ok "installed ${need_pkgs[*]}"
else
  ok "all present"
fi

# ---------------------------------------------------------------------------
# Phase 2 — Docker Engine
# ---------------------------------------------------------------------------
step "Docker Engine"
if command -v docker >/dev/null 2>&1; then
  ok "docker present: $(docker --version)"
else
  info "installing Docker Engine via get.docker.com"
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  sh /tmp/get-docker.sh
  ok "installed: $(docker --version)"
fi

systemctl enable --now docker >/dev/null 2>&1 || true
if systemctl is-active --quiet docker || docker info >/dev/null 2>&1; then
  ok "docker daemon active"
else
  die "docker daemon is not running and could not be started"
fi

# docker group membership for the interactive (non-root) user.
if getent group docker >/dev/null 2>&1; then
  if id -nG "$TARGET_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    ok "$TARGET_USER already in docker group"
  else
    usermod -aG docker "$TARGET_USER"
    warn "$TARGET_USER added to 'docker' group — they must re-login (or run 'newgrp docker') for it to take effect"
  fi
fi

# ---------------------------------------------------------------------------
# Phase 3 — Go toolchain + agentcontainer CLI
# ---------------------------------------------------------------------------
step "Go toolchain"
# Pin to whatever go.mod requires so the toolchain never drifts from the source.
GO_VERSION="$(awk '/^go [0-9]/{print $2; exit}' "$REPO_ROOT/go.mod")"
[ -n "$GO_VERSION" ] || die "could not read Go version from $REPO_ROOT/go.mod"
info "go.mod requires Go $GO_VERSION"

go_ok() {
  command -v /usr/local/go/bin/go >/dev/null 2>&1 || return 1
  local have; have="$(/usr/local/go/bin/go env GOVERSION 2>/dev/null | sed 's/^go//')"
  [ -n "$have" ] || return 1
  # ok if installed >= required
  [ "$(printf '%s\n%s\n' "$GO_VERSION" "$have" | sort -V | head -1)" = "$GO_VERSION" ]
}

if go_ok; then
  ok "Go present: $(/usr/local/go/bin/go env GOVERSION)"
else
  info "installing Go $GO_VERSION to /usr/local/go"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
  echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
  chmod 644 /etc/profile.d/go.sh
  ok "installed $(/usr/local/go/bin/go env GOVERSION)"
fi
export PATH="$PATH:/usr/local/go/bin"

step "Build agentcontainer CLI"
info "building from $REPO_ROOT (CGO disabled, static)"
( cd "$REPO_ROOT" && CGO_ENABLED=0 /usr/local/go/bin/go build -trimpath \
    -o /usr/local/bin/agentcontainer ./cmd/agentcontainer )
chmod 755 /usr/local/bin/agentcontainer
ok "installed: $(/usr/local/bin/agentcontainer version 2>/dev/null | head -1 || echo /usr/local/bin/agentcontainer)"

# ---------------------------------------------------------------------------
# Phase 4 — signing tools (optional, for sign/verify/attest demos)
# ---------------------------------------------------------------------------
if [ "$SKIP_SIGNING_TOOLS" -eq 1 ]; then
  step "Signing tools — skipped (--skip-signing-tools)"
else
  step "Signing tools (cosign, crane)"
  if command -v cosign >/dev/null 2>&1; then
    ok "cosign present: $(cosign version 2>/dev/null | awk '/GitVersion|^v/{print $NF; exit}')"
  else
    if curl -fsSL -o /usr/local/bin/cosign \
        "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-${ARCH}"; then
      chmod 755 /usr/local/bin/cosign; ok "installed cosign"
    else
      warn "cosign download failed — sign/verify demos won't work (non-fatal)"
    fi
  fi
  if command -v crane >/dev/null 2>&1; then
    ok "crane present"
  else
    if curl -fsSL "https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_${CRANE_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin crane 2>/dev/null; then
      chmod 755 /usr/local/bin/crane; ok "installed crane"
    else
      warn "crane download failed — attest demos may be limited (non-fatal)"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Phase 5 — BPF LSM (kernel cmdline) — gates full file/binary enforcement
# ---------------------------------------------------------------------------
if [ "$SKIP_LSM" -eq 1 ]; then
  step "BPF LSM — skipped (--skip-lsm); network + DNS enforcement only"
else
  step "BPF LSM (file_open / bprm_check credential gating)"
  if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    ok "bpf is active in the kernel LSM list"
  elif ! grep -q 'CONFIG_BPF_LSM=y' "/boot/config-$(uname -r)" 2>/dev/null; then
    warn "kernel was not built with CONFIG_BPF_LSM=y — cannot enable BPF LSM on this kernel"
    warn "continuing with network + DNS enforcement only"
  else
    # Base the new lsm= list on what is ACTIVE now (preserves apparmor etc.),
    # then append bpf. This avoids accidentally enabling LSMs that are compiled
    # in but currently off.
    base_lsm="$(cat /sys/kernel/security/lsm)"
    desired_lsm="${base_lsm},bpf"

    if grep -qE '^GRUB_CMDLINE_LINUX="[^"]*lsm=[^"]*bpf' /etc/default/grub; then
      ok "GRUB already configured with bpf in lsm= (reboot pending)"
    else
      info "configuring GRUB: lsm=$desired_lsm"
      cp -a /etc/default/grub "/etc/default/grub.bak.$(date +%s)"
      if grep -qE '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
        val="$(grep -E '^GRUB_CMDLINE_LINUX=' /etc/default/grub | head -1 | sed -E 's/^GRUB_CMDLINE_LINUX=//')"
        val="${val%\"}"; val="${val#\"}"
        # strip any existing lsm= token, collapse spaces, append our lsm=
        val="$(printf '%s' "$val" | sed -E 's/(^| )lsm=[^ ]*//g; s/  +/ /g; s/^ //; s/ $//')"
        val="${val:+$val }lsm=$desired_lsm"
        val_esc="$(printf '%s' "$val" | sed -e 's/[&\\|]/\\&/g')"
        sed -i -E "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$val_esc\"|" /etc/default/grub
      else
        printf 'GRUB_CMDLINE_LINUX="lsm=%s"\n' "$desired_lsm" >> /etc/default/grub
      fi
      update-grub
      ok "GRUB updated (backup saved alongside /etc/default/grub)"
    fi
    REBOOT_REQUIRED=1
  fi
fi

# ---------------------------------------------------------------------------
# Phase 6 — enforcer image
# ---------------------------------------------------------------------------
if [ "$SKIP_ENFORCER_IMAGE" -eq 1 ]; then
  step "Enforcer image — skipped (--skip-enforcer-image)"
else
  step "Enforcer image"
  info "image: $ENFORCER_IMAGE"
  # Derive the ghcr owner from the image for login default.
  img_owner="$(printf '%s' "$ENFORCER_IMAGE" | sed -E 's#^ghcr.io/([^/]+)/.*#\1#')"
  if [ -n "${GHCR_TOKEN:-}" ]; then
    info "logging in to ghcr.io as ${GHCR_USER:-$img_owner}"
    printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u "${GHCR_USER:-$img_owner}" --password-stdin
  fi
  if docker pull "$ENFORCER_IMAGE"; then
    ok "pulled $ENFORCER_IMAGE"
    if [ "$ENFORCER_IMAGE" != "$UPSTREAM_ENFORCER_IMAGE" ]; then
      docker tag "$ENFORCER_IMAGE" "$UPSTREAM_ENFORCER_IMAGE"
      ok "tagged as $UPSTREAM_ENFORCER_IMAGE (so the stock CLI finds it locally)"
    fi
  else
    warn "could not pull $ENFORCER_IMAGE"
    warn "the package may not exist yet or may be private. Options:"
    warn "  - publish it from your fork CI (push to enforcer/** triggers .github/workflows/docker.yml)"
    warn "  - or set GHCR_TOKEN (a PAT with read:packages) and re-run"
    warn "  - or build locally: docker build -t $ENFORCER_IMAGE enforcer/ && docker push $ENFORCER_IMAGE"
    die "enforcer image unavailable — re-run once it's published, or pass --skip-enforcer-image"
  fi
fi

# ---------------------------------------------------------------------------
# Reboot gate
# ---------------------------------------------------------------------------
if [ "$REBOOT_REQUIRED" -eq 1 ]; then
  printf "\n${C_YELLOW}========================================================${C_RESET}\n"
  printf "${C_YELLOW} REBOOT REQUIRED to activate the BPF LSM.${C_RESET}\n"
  printf " The kernel cmdline now requests 'bpf' in the LSM list.\n"
  printf " Run:   ${C_GREEN}sudo reboot${C_RESET}\n"
  printf " Then re-run this script to finish (it will skip what's done\n"
  printf " and run the enforcer smoke test).\n"
  printf "${C_YELLOW}========================================================${C_RESET}\n"
  exit 0
fi

# ---------------------------------------------------------------------------
# Phase 7 — smoke test
# ---------------------------------------------------------------------------
if [ "$SKIP_SMOKE" -eq 1 ] || [ "$SKIP_ENFORCER_IMAGE" -eq 1 ]; then
  step "Smoke test — skipped"
else
  step "Smoke test (start enforcer, health-check, stop)"
  smoke_fail=0
  /usr/local/bin/agentcontainer enforcer start  || smoke_fail=1
  /usr/local/bin/agentcontainer enforcer status || smoke_fail=1
  /usr/local/bin/agentcontainer enforcer diagnose || true
  /usr/local/bin/agentcontainer enforcer stop --force >/dev/null 2>&1 || true
  if [ "$smoke_fail" -eq 0 ]; then
    ok "enforcer started, reported healthy, and stopped cleanly"
  else
    warn "smoke test had failures — inspect 'agentcontainer enforcer diagnose' output above"
  fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
printf "\n${C_GREEN}Bootstrap complete.${C_RESET}\n"
cat <<EOF

Next steps:
  1. If you were just added to the docker group, log out/in (or: newgrp docker).
  2. Try the bundled example:
       cd $REPO_ROOT/examples/minimal
       agentcontainer run
       agentcontainer exec minimal-agent -- bash
       agentcontainer stop minimal-agent
  3. Or scaffold your own:  agentcontainer init  (in any project dir)

Enforcer image in use: $ENFORCER_IMAGE
EOF
