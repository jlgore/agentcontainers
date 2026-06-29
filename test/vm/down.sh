#!/usr/bin/env bash
# Tear down the capability-matrix VM substrate (and its imported disk).
set -uo pipefail
cd "$(dirname "$0")"
kubectl delete -f vm.yaml --ignore-not-found
kubectl -n ac-matrix delete secret ac-matrix-cloudinit --ignore-not-found 2>/dev/null
echo "torn down (namespace ac-matrix removed; the SSH key at \$HOME/.ssh/ac-matrix-vm is kept)."
