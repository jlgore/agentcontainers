#!/bin/sh
# Create the writable working dirs under the only writable mount (/run/secrets
# is a tmpfs, empty at container start) before launching the gateway. Each is
# also where the SIFT MCP backends and the audit writer expect to write.
set -eu

mkdir -p \
  "${TMPDIR:-/run/secrets/tmp}" \
  "${VHIR_CASE_DIR:-/run/secrets/case}" \
  "${VHIR_CASES_DIR:-/run/secrets/cases}" \
  "${VHIR_AUDIT_DIR:-/run/secrets/audit}"

# cwd must be writable too (some libraries touch it); /run/secrets is tmpfs.
cd /run/secrets

exec sift-gateway --config /app/gateway.yaml --host 0.0.0.0 --port 4508
