# sift-gateway container image — the mainline AppliedIR/sift-mcp forensic
# platform (forensic-mcp, sift-mcp, case-mcp, report-mcp) aggregated behind one
# HTTP MCP endpoint, for use as an agentcontainers container-type MCP tool
# (agent.tools.mcp.<name>: { type: container, transport: http, port: 4508 }).
#
# Build context is a clone of github.com/AppliedIR/sift-mcp with this Dockerfile,
# gateway.docker.yaml, and entrypoint.sh copied into its root — see build.sh.
#
# Runtime note: agentcontainers runs MCP tool containers hardened — read-only
# rootfs, all caps dropped, and only /run/secrets writable (tmpfs). Every
# mutable path below is therefore funneled under /run/secrets, and bytecode
# writes are disabled.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv

WORKDIR /app

# vhir-cli (required by case-mcp / report-mcp) lives in a separate public repo.
ARG VHIR_REF=main
RUN git clone --depth 1 --branch "$VHIR_REF" \
      https://github.com/AppliedIR/Valhuntir.git /app/vhir

# The sift-mcp monorepo (this build context).
COPY . /app/sift-mcp

# One system venv on PATH so the gateway's `python -m <backend>` subprocesses
# resolve to the installed packages.
ENV VIRTUAL_ENV=/app/venv
RUN uv venv "$VIRTUAL_ENV" --seed
ENV PATH="/app/venv/bin:$PATH"

# Install vhir-cli + the gateway and its core local backends (deps first).
RUN uv pip install \
      -e /app/vhir \
      -e /app/sift-mcp/packages/sift-common \
      -e /app/sift-mcp/packages/forensic-knowledge \
      -e /app/sift-mcp/packages/sift-gateway \
      -e /app/sift-mcp/packages/forensic-mcp \
      -e /app/sift-mcp/packages/sift-mcp \
      -e /app/sift-mcp/packages/case-mcp \
      -e /app/sift-mcp/packages/report-mcp

COPY gateway.docker.yaml /app/gateway.yaml
COPY entrypoint.sh /usr/local/bin/sift-entrypoint
RUN chmod 755 /usr/local/bin/sift-entrypoint

# Funnel all mutable state under the single writable tmpfs (/run/secrets) and
# stop CPython writing .pyc into the read-only editable source trees.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/run/secrets \
    TMPDIR=/run/secrets/tmp \
    VHIR_CASE_DIR=/run/secrets/case \
    VHIR_CASES_DIR=/run/secrets/cases \
    VHIR_AUDIT_DIR=/run/secrets/audit \
    VHIR_ACTIVE_CASE="" \
    VHIR_EXAMINER=agentcontainer

EXPOSE 4508
ENTRYPOINT ["/usr/local/bin/sift-entrypoint"]
