#!/usr/bin/env bash
# Diagnostic dump for failed E2E runs. Never fails — just prints everything.
set +e

header() { printf '\n========== %s ==========\n' "$1"; }

header "kubectl get all -A"
kubectl get all -A

header "kubectl get decoys -A"
kubectl get decoys.cicdecoy.io -A -o wide

header "kubectl describe pods -n cicdecoy-system"
kubectl describe pods -n cicdecoy-system

header "kubectl describe pods -n decoys-test"
kubectl describe pods -n decoys-test

header "events (cicdecoy-system)"
kubectl get events -n cicdecoy-system --sort-by=.lastTimestamp

header "events (decoys-test)"
kubectl get events -n decoys-test --sort-by=.lastTimestamp

dump_ns_logs() {
  local ns=$1
  local pods
  pods=$(kubectl get pods -n "$ns" -o name 2>/dev/null)
  for pod in $pods; do
    header "logs ${ns}/${pod}"
    kubectl logs -n "$ns" "$pod" --all-containers=true --tail=500 2>&1
    header "previous logs ${ns}/${pod} (if any)"
    kubectl logs -n "$ns" "$pod" --all-containers=true --previous --tail=200 2>&1
  done
}

dump_ns_logs cicdecoy-system
dump_ns_logs decoys-test

header "helm status cicdecoy"
helm status cicdecoy -n cicdecoy-system

header "helm get values cicdecoy"
helm get values cicdecoy -n cicdecoy-system -a

header "port-forward logs"
[ -f /tmp/pf-ssh.log ] && { echo '--- pf-ssh.log'; cat /tmp/pf-ssh.log; }
[ -f /tmp/pf-dashboard.log ] && { echo '--- pf-dashboard.log'; cat /tmp/pf-dashboard.log; }

exit 0
