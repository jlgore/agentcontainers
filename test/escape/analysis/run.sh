#!/usr/bin/env bash
# Run the escape-the-box DuckDB model against R2 (bucket: agentcontainers-audit).
#
# Provide R2 S3 credentials via env (an R2 API token's Access Key ID + Secret):
#   export AWS_ACCESS_KEY_ID=<r2-access-key-id>
#   export AWS_SECRET_ACCESS_KEY=<r2-secret-access-key>
# then:  ./run.sh                 # runs the canned report queries
#        ./run.sh -interactive    # drops into a DuckDB shell with views loaded
#
# The account id is embedded in escape_box.sql (not sensitive); the secret is
# never written to disk — DuckDB's credential_chain reads it from the env above.
set -euo pipefail
cd "$(dirname "$0")"

: "${AWS_ACCESS_KEY_ID:?set AWS_ACCESS_KEY_ID to an R2 access key id}"
: "${AWS_SECRET_ACCESS_KEY:?set AWS_SECRET_ACCESS_KEY to the R2 secret}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-auto}"

if [[ "${1:-}" == "-interactive" ]]; then
  # load the model, then hand over an interactive prompt
  exec duckdb -init escape_box.sql
else
  exec duckdb < escape_box.sql
fi
