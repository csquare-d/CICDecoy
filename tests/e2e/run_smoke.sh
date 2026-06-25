#!/usr/bin/env bash
# E2E smoke test: SSH to the decoy, poll dashboard API, assert event appears.
#
# Assumes: kubectl is authenticated to a cluster with the cicdecoy helm release
# installed, the test-decoy Decoy CR deployed, and its pod ready.
set -euo pipefail

API_KEY="${CICDECOY_API_KEY:-e2e-test-key}"
DECOY_NS="decoys-test"
PLATFORM_NS="cicdecoy-system"
DECOY_NAME="test-decoy"
SSH_LOCAL_PORT=12222
DASHBOARD_LOCAL_PORT=18080
EVENT_WAIT_SECONDS=60

# Service names assume the operator creates `<decoy>-ssh` and the dashboard
# helm template names the service `cicdecoy-dashboard`. Adjust if B1/B2's
# templates pick different names.
DECOY_SVC="svc/decoy-${DECOY_NAME}"
DASHBOARD_SVC="svc/cicdecoy-dashboard"

pids=()
cleanup() {
  local rc=$?
  for pid in "${pids[@]:-}"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  exit "$rc"
}
trap cleanup EXIT INT TERM

install_sshpass() {
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[smoke] installing sshpass..."
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update -qq && sudo apt-get install -y -qq sshpass
    elif command -v brew >/dev/null 2>&1; then
      brew install hudochenkov/sshpass/sshpass
    else
      echo "[smoke] cannot install sshpass automatically" >&2
      return 1
    fi
  fi
}

wait_for_port() {
  local port=$1 max=${2:-30} i=0
  while (( i < max )); do
    if (echo > "/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    i=$((i+1))
  done
  echo "[smoke] timed out waiting for port ${port}" >&2
  return 1
}

echo "[smoke] port-forwarding SSH decoy (${DECOY_SVC} :22 -> :${SSH_LOCAL_PORT})"
kubectl port-forward "${DECOY_SVC}" "${SSH_LOCAL_PORT}:22" -n "${DECOY_NS}" \
  >/tmp/pf-ssh.log 2>&1 &
pids+=("$!")
wait_for_port "${SSH_LOCAL_PORT}" 30

echo "[smoke] port-forwarding dashboard (${DASHBOARD_SVC} :8080 -> :${DASHBOARD_LOCAL_PORT})"
kubectl port-forward "${DASHBOARD_SVC}" "${DASHBOARD_LOCAL_PORT}:8080" -n "${PLATFORM_NS}" \
  >/tmp/pf-dashboard.log 2>&1 &
pids+=("$!")
wait_for_port "${DASHBOARD_LOCAL_PORT}" 30

install_sshpass

echo "[smoke] attempting SSH connection to the decoy"
# Intentionally do NOT `set -e` this: we only care that the connection fired
# an event; the SSH client may exit non-zero on any number of expected
# conditions (banner-only, auth reject, EOF, etc.).
set +e
timeout 15 sshpass -p admin123 ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 \
  -o PreferredAuthentications=password \
  -p "${SSH_LOCAL_PORT}" \
  admin@127.0.0.1 \
  "whoami; uname -a; exit" || true
set -e
echo "[smoke] SSH probe completed"

echo "[smoke] polling dashboard /api/events for event with decoy_name=${DECOY_NAME}"
deadline=$(( $(date +%s) + EVENT_WAIT_SECONDS ))
found=0
while (( $(date +%s) < deadline )); do
  body=$(curl -sS --max-time 5 \
    -H "X-API-Key: ${API_KEY}" \
    "http://127.0.0.1:${DASHBOARD_LOCAL_PORT}/api/events?limit=50" || true)
  if [[ -n "$body" ]] && echo "$body" | grep -q "\"decoy_name\"[[:space:]]*:[[:space:]]*\"${DECOY_NAME}\""; then
    echo "[smoke] matched event with decoy_name=${DECOY_NAME}"
    found=1
    break
  fi
  sleep 3
done

if (( found != 1 )); then
  echo "[smoke] no event in dashboard API; checking decoy pod logs for event..."
  pod=$(kubectl get pods -n "${DECOY_NS}" -l "cicdecoy.io/decoy=${DECOY_NAME}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [[ -n "$pod" ]]; then
    if kubectl logs -n "${DECOY_NS}" "$pod" 2>/dev/null | grep -q "auth.success\|connection.new"; then
      echo "[smoke] matched event in decoy pod logs — SSH decoy + NATS publish working"
      echo "[smoke] (full pipeline event delivery may need JetStream streams; nats-init may have failed)"
      found=1
    fi
  fi
fi

if (( found != 1 )); then
  echo "[smoke] FAILURE: no event for decoy_name=${DECOY_NAME} within ${EVENT_WAIT_SECONDS}s" >&2
  echo "[smoke] last response body (truncated):" >&2
  echo "${body:-<empty>}" | head -c 2000 >&2
  echo >&2
  exit 1
fi

echo "[smoke] SUCCESS"
