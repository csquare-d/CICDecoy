#!/usr/bin/env bash
# Local mirror of .github/workflows/e2e-k3d.yaml. Creates a throwaway k3d
# cluster, builds images, helm installs, runs the smoke test, tears down.
#
# Requires: docker, k3d, kubectl, helm, sshpass (optional — smoke script will
# try to install it).
set -euo pipefail

CLUSTER="${CLUSTER:-cicdecoy-e2e-local}"
K3S_IMAGE="${K3S_IMAGE:-rancher/k3s:v1.30.0-k3s1}"
KEEP="${KEEP:-0}"

cleanup() {
  local rc=$?
  if [[ "$KEEP" != "1" ]]; then
    echo "[local] deleting k3d cluster ${CLUSTER}"
    k3d cluster delete "${CLUSTER}" >/dev/null 2>&1 || true
  else
    echo "[local] KEEP=1 set; leaving cluster ${CLUSTER} running"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

for bin in docker k3d kubectl helm; do
  command -v "$bin" >/dev/null 2>&1 || {
    echo "[local] missing required binary: $bin" >&2
    exit 1
  }
done

echo "[local] creating k3d cluster ${CLUSTER}"
k3d cluster create "${CLUSTER}" \
  --agents 1 \
  --no-lb \
  --image "${K3S_IMAGE}" \
  --k3s-arg "--disable=traefik@server:0" \
  --wait --timeout 180s

echo "[local] building images"
docker build -t cicdecoy/cicdecoy-ssh:e2e ./ssh-decoy
docker build -t cicdecoy/cicdecoy-cti-pipeline:e2e ./cti
docker build -t cicdecoy/cicdecoy-dashboard:e2e ./dashboard
docker build -t cicdecoy/cicdecoy-operator:e2e ./platform/operator

echo "[local] importing images into k3d"
k3d image import \
  cicdecoy/cicdecoy-ssh:e2e \
  cicdecoy/cicdecoy-cti-pipeline:e2e \
  cicdecoy/cicdecoy-dashboard:e2e \
  cicdecoy/cicdecoy-operator:e2e \
  -c "${CLUSTER}"

echo "[local] building helm dependencies"
helm repo add nats https://nats-io.github.io/k8s/helm/charts/ >/dev/null 2>&1 || true
helm repo update >/dev/null
helm dependency build ./platform/helm/cicdecoy

echo "[local] helm install"
kubectl create namespace cicdecoy-system
kubectl create namespace decoys-test
helm install cicdecoy ./platform/helm/cicdecoy \
  --namespace cicdecoy-system \
  --set global.imageRegistry=cicdecoy \
  --set global.imageTag=e2e \
  --set global.imagePullPolicy=Never \
  --set dashboard.auth.apiKey=e2e-test-key \
  --set decoyNamespaces='{decoys-test}' \
  --wait --timeout 5m

kubectl wait --for=condition=available --timeout=5m \
  deployment --all -n cicdecoy-system

echo "[local] deploying test Decoy"
kubectl apply -f tests/e2e/fixtures/test-decoy.yaml
kubectl wait --for=condition=ready --timeout=2m \
  pod -l cicdecoy.io/decoy=test-decoy -n decoys-test

echo "[local] running smoke"
CICDECOY_API_KEY=e2e-test-key bash tests/e2e/run_smoke.sh

echo "[local] PASS"
