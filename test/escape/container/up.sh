#!/usr/bin/env bash
# Bring up the escape-the-box CONTAINER substrate (privileged-pod twin of
# ac-matrix-vm). Idempotent: re-running re-applies and waits.
#
# Reuses the SAME SSH keypair as the VM substrate (test/vm/up.sh) by default, so
# the harness-worker's existing key drives BOTH substrates. The pod's
# authorized_keys is the PUBLIC key; the worker mounts the private key (Vault →
# SSH_KEY_PATH) exactly as for the VM.
set -euo pipefail

cd "$(dirname "$0")"
NS=ac-matrix
KEY="${AC_MATRIX_SSH_KEY:-$HOME/.ssh/ac-matrix-vm}"
IMAGE="${AC_SUBSTRATE_IMAGE:-ghcr.io/jlgore/agentcontainers-escape-substrate:latest}"

command -v kubectl >/dev/null || { echo "kubectl not found"; exit 1; }

# 1) SSH key (shared with the VM substrate). Generate only if wholly absent.
if [ ! -f "$KEY" ]; then
  echo "==> generating SSH key at $KEY (shared with the VM substrate)"
  mkdir -p "$(dirname "$KEY")"
  ssh-keygen -t ed25519 -N "" -C "ac-matrix" -f "$KEY" >/dev/null
fi
PUB=$(cat "$KEY.pub")

# 2) Namespace + authorized_keys Secret consumed by the pod's entrypoint.
echo "==> namespace + ssh secret (ac-matrix-ctr-ssh)"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic ac-matrix-ctr-ssh \
  --from-literal=authorized_keys="$PUB" \
  --dry-run=client -o yaml | kubectl apply -f -

# 3) Apply the Deployment with the image substituted in.
echo "==> applying Deployment ac-matrix-ctr (image: $IMAGE)"
sed "s#REPLACE_WITH_IMAGE#$IMAGE#" deployment.yaml | kubectl apply -f -

# 4) Wait for the pod to be Ready.
echo "==> waiting for the substrate pod to be Ready…"
kubectl -n "$NS" rollout status deploy/ac-matrix-ctr --timeout=300s

POD=$(kubectl -n "$NS" get pod -l app=ac-matrix-ctr -o jsonpath='{.items[0].metadata.name}')
IP=$(kubectl -n "$NS" get pod -l app=ac-matrix-ctr -o jsonpath='{.items[0].status.podIP}')
echo
echo "substrate up: pod=$POD ip=$IP"
echo "logs:  kubectl -n $NS logs deploy/ac-matrix-ctr"
echo "SSH:   kubectl -n $NS exec -it $POD -- bash   # or from the worker: ssh ubuntu@$IP"
echo
echo "Drive one container cell (worker's SUBSTRATE default stays 'vm'; pin per-cell):"
echo "  temporal --env lab workflow start --task-queue escape-cells \\"
echo "    --type MatrixCellWorkflow --workflow-id cell-ctr-REG-nc-1 \\"
echo "    --input '{\"Harness\":\"pi\",\"Provider\":\"openrouter\",\"Model\":\"z-ai/glm-5.2\",\"CaseID\":\"REG-nc\",\"Substrate\":\"container\",\"AgentTimeoutSec\":180,\"OpenRouterRole\":\"escape-glm\"}'"
