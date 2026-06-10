# Claude Code, containerized under agentcontainers enforcement.
#
# The agent's own Bash is gated by a PreToolUse hook that ships every command to
# an out-of-band guard (`agentcontainer guard serve`, running on the host) over
# a bind-mounted unix socket. The guard runs the command through the same OPA
# policy that gates the MCP forensic tools and escalates denials to a human.
# Network egress is kernel-enforced by the eBPF sidecar; the Anthropic API key
# is read from /run/secrets via apiKeyHelper, never from the environment.
#
# The decision authority lives on the host, outside the agent's reach: the hook
# only carries a request to the socket and renders the verdict. It cannot allow
# what the host denies.
#
# Build context is the REPOSITORY ROOT (see build.sh) so stage 1 can compile the
# agentcontainer binary that provides `agentcontainer guard hook`.

# ---- stage 1: build the agentcontainer binary ------------------------------
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/agentcontainer ./cmd/agentcontainer

# ---- stage 2: Claude Code runtime ------------------------------------------
FROM node:22-bookworm-slim

# Claude Code CLI plus the few tools its own operation needs. The forensic
# tooling itself is not installed here — it lives behind the MCP proxy.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git jq \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code

COPY --from=build /out/agentcontainer /usr/local/bin/agentcontainer

# Managed settings are root-owned and world-readable but NOT writable. Claude
# Code treats /etc/claude-code/managed-settings.json as the highest-precedence
# settings source, so the agent cannot override the guard hook or the
# apiKeyHelper from its own user/project config.
COPY examples/claude-agent/managed-settings.json /etc/claude-code/managed-settings.json
RUN chown root:root /etc/claude-code/managed-settings.json \
    && chmod 0644 /etc/claude-code/managed-settings.json

# apiKeyHelper: emit the key from the tmpfs secret, never an env var.
COPY examples/claude-agent/api-key-helper.sh /usr/local/bin/ac-api-key
RUN chmod 0755 /usr/local/bin/ac-api-key

COPY examples/claude-agent/entrypoint.sh /usr/local/bin/claude-agent-entrypoint
RUN chmod 0755 /usr/local/bin/claude-agent-entrypoint

# Run as the node base image's unprivileged user (uid 1000). That uid matches
# the host user running `guard serve`, so the 0600 guard socket is accessible
# across the bind mount (see README "uid alignment"). HOME lives under the
# writable /workspace mount because the enforcer mounts the rootfs read-only.
ENV HOME=/workspace \
    CLAUDE_CONFIG_DIR=/workspace/.claude \
    NODE_NO_WARNINGS=1
WORKDIR /workspace
USER node
ENTRYPOINT ["/usr/local/bin/claude-agent-entrypoint"]
CMD ["sleep", "infinity"]
