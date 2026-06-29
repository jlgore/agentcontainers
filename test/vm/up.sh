#!/usr/bin/env bash
# Bring up the KubeVirt capability-matrix VM substrate (Phase 2).
# Idempotent: re-running re-applies and waits. Generates an SSH keypair on first
# use (used by smoke.sh / virtctl ssh).
set -euo pipefail

cd "$(dirname "$0")"
NS=ac-matrix
VM=ac-matrix-vm
KEY="${AC_MATRIX_SSH_KEY:-$HOME/.ssh/ac-matrix-vm}"

command -v kubectl >/dev/null || { echo "kubectl not found"; exit 1; }
command -v virtctl >/dev/null || { echo "virtctl not found"; exit 1; }

# 1) SSH key for virtctl ssh into the guest.
if [ ! -f "$KEY" ]; then
  echo "==> generating SSH key at $KEY"
  mkdir -p "$(dirname "$KEY")"
  ssh-keygen -t ed25519 -N "" -C "ac-matrix" -f "$KEY" >/dev/null
fi
PUB=$(cat "$KEY.pub")

# 2) Namespace + cloud-init Secret (userData exceeds the inline 2048-byte limit).
echo "==> namespace + cloud-init secret"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
sed "s|__SSH_PUBKEY__|$PUB|" cloud-init.yaml > .userdata.rendered
kubectl -n "$NS" create secret generic ac-matrix-cloudinit \
  --from-file=userdata=.userdata.rendered \
  --dry-run=client -o yaml | kubectl apply -f -
rm -f .userdata.rendered

# 3) Apply the VM.
echo "==> applying VM (node: talos-node)"
kubectl apply -f vm.yaml

# 4) Wait for the CDI import, then the VMI to be Running.
echo "==> waiting for DataVolume import (Ubuntu cloud image)…"
kubectl -n "$NS" wait --for=condition=Ready --timeout=900s \
  dv/ac-matrix-vm-root 2>/dev/null || kubectl -n "$NS" get dv ac-matrix-vm-root

echo "==> waiting for VMI to be Running…"
for _ in $(seq 1 120); do
  phase=$(kubectl -n "$NS" get vmi "$VM" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  echo "    VMI phase: ${phase:-<none>}"
  [ "$phase" = "Running" ] && break
  sleep 5
done

echo
echo "VM is scheduled. cloud-init then arms the bpf LSM and reboots once;"
echo "tooling install follows. Give it ~3–5 min, then run: ./smoke.sh"
echo "SSH:  virtctl ssh ubuntu@vmi/$VM -n $NS -i $KEY -t '-o StrictHostKeyChecking=no'"
