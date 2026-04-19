#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  CI/CDecoy — Quick-Start Install Script
#
#  Deploys the CI/CDecoy deception-as-code framework in one command.
#  Two modes:
#    Docker Compose (default) — runs the full Tier 2 stack locally
#    Kubernetes (--k8s)       — creates a k3d cluster and installs via Helm
#
#  Usage:
#    ./quickstart.sh              # Docker Compose mode
#    ./quickstart.sh --k8s        # Kubernetes mode
#    ./quickstart.sh --tier3      # Include Tier 3 LLM decoys (Compose only)
#    ./quickstart.sh --teardown   # Remove everything
#
#  Safe to run multiple times (idempotent).
# ---------------------------------------------------------------------------

set -euo pipefail

# ── Globals ─────────────────────────────────────────────────────────────────

REPO_URL="https://github.com/csquare-d/CICDecoy.git"
REPO_DIR=""               # resolved in main()
MODE="compose"            # compose | k8s
TIER3=false
TEARDOWN=false
K8S_CLUSTER_NAME="cicdecoy"
K8S_NAMESPACE="cicdecoy-system"
HELM_RELEASE="cicdecoy"

# ── Color helpers (degrade gracefully) ──────────────────────────────────────

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    CYAN=$(tput setaf 6)
    BOLD=$(tput bold)
    RESET=$(tput sgr0)
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    CYAN=""
    BOLD=""
    RESET=""
fi

# ── Logging ─────────────────────────────────────────────────────────────────

info()  { printf "%s[*]%s %s\n" "${CYAN}"  "${RESET}" "$*"; }
ok()    { printf "%s[+]%s %s\n" "${GREEN}" "${RESET}" "$*"; }
warn()  { printf "%s[!]%s %s\n" "${YELLOW}" "${RESET}" "$*"; }
err()   { printf "%s[-]%s %s\n" "${RED}"   "${RESET}" "$*" >&2; }
die()   { err "$@"; exit 1; }

# ── Banner ──────────────────────────────────────────────────────────────────

banner() {
    cat <<'BANNER'

     ██████╗██╗ ██╗ ██████╗██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗
    ██╔════╝██║██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗╚██╗ ██╔╝
    ██║     ████╔╝ ██║     ██║  ██║█████╗  ██║     ██║   ██║ ╚████╔╝
    ██║     ██╔██╗ ██║     ██║  ██║██╔══╝  ██║     ██║   ██║  ╚██╔╝
    ╚██████╗██║╚██╗╚██████╗██████╔╝███████╗╚██████╗╚██████╔╝   ██║
     ╚═════╝╚═╝ ╚═╝ ╚═════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝   ╚═╝

BANNER
    printf "    %sDeception as Code%s — Open-Source Honeypot Framework\n\n" \
        "${BOLD}" "${RESET}"
}

# ── Prerequisite checks ────────────────────────────────────────────────────

require_cmd() {
    local cmd="$1"
    local hint="${2:-}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        if [[ -n "$hint" ]]; then
            die "'$cmd' is required but not found. $hint"
        else
            die "'$cmd' is required but not found."
        fi
    fi
}

check_common_prereqs() {
    info "Checking prerequisites..."
    require_cmd git "Install from https://git-scm.com"
    require_cmd docker "Install from https://docs.docker.com/get-docker/"

    # Docker Compose can be either 'docker compose' (v2 plugin) or
    # the standalone 'docker-compose' binary.
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
    else
        die "Docker Compose is required. Install the Compose plugin: https://docs.docker.com/compose/install/"
    fi

    # Verify the Docker daemon is actually running.
    if ! docker info >/dev/null 2>&1; then
        die "Docker daemon is not running. Start Docker Desktop or the dockerd service."
    fi

    ok "Prerequisites satisfied (git, docker, compose)"
}

check_k8s_prereqs() {
    info "Checking Kubernetes prerequisites..."
    require_cmd kubectl "Install from https://kubernetes.io/docs/tasks/tools/"
    require_cmd helm    "Install from https://helm.sh/docs/intro/install/"

    # We need at least one local cluster tool.
    if command -v k3d >/dev/null 2>&1; then
        K8S_TOOL="k3d"
    elif command -v kind >/dev/null 2>&1; then
        K8S_TOOL="kind"
    elif command -v minikube >/dev/null 2>&1; then
        K8S_TOOL="minikube"
    else
        die "A local Kubernetes tool is required (k3d, kind, or minikube). Install k3d: https://k3d.io"
    fi

    ok "Kubernetes prerequisites satisfied (kubectl, helm, $K8S_TOOL)"
}

# ── Repo resolution ────────────────────────────────────────────────────────

resolve_repo() {
    # If we are already inside the repo, use it. Otherwise clone.
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # The script lives in scripts/, so the repo root is one level up.
    local candidate="${script_dir}/.."
    if [[ -f "${candidate}/docker-compose.yaml" ]]; then
        REPO_DIR="$(cd "$candidate" && pwd)"
        ok "Using existing repo at ${REPO_DIR}"
        return
    fi

    # Fallback: clone into current directory.
    local target
    target="$(pwd)/CICDecoy"
    if [[ -d "$target/.git" ]]; then
        REPO_DIR="$target"
        ok "Repo already cloned at ${REPO_DIR}"
    else
        info "Cloning CI/CDecoy repository..."
        git clone --depth 1 "$REPO_URL" "$target"
        REPO_DIR="$target"
        ok "Cloned to ${REPO_DIR}"
    fi
}

# ── .env setup ──────────────────────────────────────────────────────────────

ensure_env_file() {
    if [[ ! -f "${REPO_DIR}/.env" ]]; then
        if [[ -f "${REPO_DIR}/.env.example" ]]; then
            cp "${REPO_DIR}/.env.example" "${REPO_DIR}/.env"
            ok "Created .env from .env.example"
        else
            warn ".env.example not found — skipping .env creation"
        fi
    else
        ok ".env already exists — keeping current values"
    fi
}

# ── Docker Compose deployment ───────────────────────────────────────────────

compose_up() {
    info "Starting CI/CDecoy via Docker Compose..."
    cd "$REPO_DIR"

    ensure_env_file

    local profile_flags=""
    if [[ "$TIER3" == true ]]; then
        profile_flags="--profile tier3"
    fi

    # shellcheck disable=SC2086
    $COMPOSE_CMD $profile_flags up --build -d

    ok "Containers started"
    compose_wait_healthy
    compose_summary
}

compose_wait_healthy() {
    info "Waiting for services to become healthy (up to 120s)..."
    local timeout=120
    local elapsed=0
    local interval=5

    while (( elapsed < timeout )); do
        # Count containers that are still starting or unhealthy.
        local not_ready
        not_ready=$(docker ps --filter "label=com.docker.compose.project" \
                        --format '{{.Status}}' \
                    | grep -ciE 'starting|unhealthy' || true)

        if (( not_ready == 0 )); then
            ok "All services healthy"
            return
        fi

        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    warn "Some services may not be fully healthy yet — check 'docker ps'"
}

compose_summary() {
    local api_key_msg=""
    # Try to grab the ephemeral API key from the dashboard logs.
    local ephemeral_key
    ephemeral_key=$($COMPOSE_CMD logs dashboard 2>/dev/null \
                    | grep -ioE 'ephemeral key: [A-Za-z0-9+/=_-]+' \
                    | tail -1 | sed 's/ephemeral key: //i' || true)
    if [[ -n "$ephemeral_key" ]]; then
        api_key_msg="  ${CYAN}Dashboard API key:${RESET}  ${ephemeral_key}"
    fi

    echo ""
    printf "  %s%s CI/CDecoy is running! %s\n" "${BOLD}" "${GREEN}" "${RESET}"
    echo ""
    echo "  ${CYAN}SSH decoy:${RESET}          ssh admin@localhost -p 2222  (password: admin123)"
    echo "  ${CYAN}HTTP decoy:${RESET}         http://localhost:8888"
    echo "  ${CYAN}Dashboard:${RESET}          http://localhost:8080"
    echo "  ${CYAN}NATS monitor:${RESET}       http://localhost:8222"
    echo "  ${CYAN}TimescaleDB:${RESET}        localhost:5432  (user: cicdecoy / cicdecoy)"
    if [[ "$TIER3" == true ]]; then
        echo ""
        echo "  ${CYAN}Tier 3 SSH decoy:${RESET}   ssh admin@localhost -p 2223  (password: admin123)"
        echo "  ${CYAN}Ollama:${RESET}             http://localhost:11434"
        echo "  ${CYAN}Inference API:${RESET}      http://localhost:8000/v1/health"
    fi
    if [[ -n "$api_key_msg" ]]; then
        echo ""
        echo "$api_key_msg"
    fi
    echo ""
    echo "  ${YELLOW}Tip:${RESET} Run 'make logs' in the repo root to tail all logs."
    echo "  ${YELLOW}Tip:${RESET} Run '$0 --teardown' to remove everything."
    echo ""
}

# ── Kubernetes deployment ───────────────────────────────────────────────────

k8s_up() {
    info "Deploying CI/CDecoy to Kubernetes via ${K8S_TOOL}..."

    k8s_ensure_cluster
    k8s_build_and_import
    k8s_helm_install
    k8s_deploy_example_decoys
    k8s_wait_ready
    k8s_summary
}

k8s_ensure_cluster() {
    case "$K8S_TOOL" in
        k3d)
            if k3d cluster list 2>/dev/null | grep -q "$K8S_CLUSTER_NAME"; then
                ok "k3d cluster '${K8S_CLUSTER_NAME}' already exists"
            else
                info "Creating k3d cluster '${K8S_CLUSTER_NAME}'..."
                k3d cluster create "$K8S_CLUSTER_NAME" \
                    --port "2222:30022@server:0" \
                    --port "8080:30080@server:0" \
                    --port "8888:30088@server:0" \
                    --wait
                ok "k3d cluster created"
            fi
            ;;
        kind)
            if kind get clusters 2>/dev/null | grep -q "$K8S_CLUSTER_NAME"; then
                ok "kind cluster '${K8S_CLUSTER_NAME}' already exists"
            else
                info "Creating kind cluster '${K8S_CLUSTER_NAME}'..."
                kind create cluster --name "$K8S_CLUSTER_NAME" --wait 60s
                ok "kind cluster created"
            fi
            ;;
        minikube)
            if minikube status --profile "$K8S_CLUSTER_NAME" >/dev/null 2>&1; then
                ok "minikube profile '${K8S_CLUSTER_NAME}' already running"
            else
                info "Starting minikube profile '${K8S_CLUSTER_NAME}'..."
                minikube start --profile "$K8S_CLUSTER_NAME"
                ok "minikube started"
            fi
            ;;
    esac
}

k8s_build_and_import() {
    info "Building container images..."
    cd "$REPO_DIR"

    local images=(
        "cicdecoy-ssh-decoy:latest:ssh-decoy"
        "cicdecoy-http-decoy:latest:http-decoy"
        "cicdecoy-cti:latest:cti"
        "cicdecoy-dashboard:latest:dashboard"
        "cicdecoy-operator:latest:platform/operator"
    )

    for entry in "${images[@]}"; do
        IFS=":" read -r name tag ctx <<< "$entry"
        local full="${name}:${tag}"
        if [[ -f "${REPO_DIR}/${ctx}/Dockerfile" ]]; then
            docker build -t "$full" "${REPO_DIR}/${ctx}" -q
        else
            warn "Skipping ${full} — no Dockerfile at ${ctx}/"
            continue
        fi

        case "$K8S_TOOL" in
            k3d)      k3d image import "$full" -c "$K8S_CLUSTER_NAME" 2>/dev/null ;;
            kind)     kind load docker-image "$full" --name "$K8S_CLUSTER_NAME" 2>/dev/null ;;
            minikube) minikube image load "$full" --profile "$K8S_CLUSTER_NAME" 2>/dev/null ;;
        esac
    done

    ok "Images built and imported"
}

k8s_helm_install() {
    local chart_dir="${REPO_DIR}/platform/helm/cicdecoy"

    if [[ ! -d "$chart_dir" ]]; then
        die "Helm chart not found at ${chart_dir}"
    fi

    # Run setup script if present (copies configs into chart).
    if [[ -x "${REPO_DIR}/platform/setup-helm-files.sh" ]]; then
        info "Running setup-helm-files.sh..."
        (cd "${REPO_DIR}/platform" && bash setup-helm-files.sh)
    fi

    info "Installing Helm chart..."
    kubectl create namespace "$K8S_NAMESPACE" 2>/dev/null || true

    helm upgrade --install "$HELM_RELEASE" "$chart_dir" \
        --namespace "$K8S_NAMESPACE" \
        --set global.imageRegistry="" \
        --set global.imagePullPolicy=IfNotPresent \
        --wait --timeout 5m

    ok "Helm release '${HELM_RELEASE}' installed in namespace '${K8S_NAMESPACE}'"
}

k8s_deploy_example_decoys() {
    local examples_dir="${REPO_DIR}/decoys/examples"

    if [[ ! -d "$examples_dir" ]]; then
        warn "No example decoys found at ${examples_dir} — skipping"
        return
    fi

    info "Deploying example decoy manifests..."
    kubectl create namespace decoys-production 2>/dev/null || true

    local count=0
    for manifest in "${examples_dir}"/*.yaml; do
        [[ -f "$manifest" ]] || continue
        kubectl apply -f "$manifest" -n decoys-production 2>/dev/null || true
        count=$((count + 1))
    done

    if (( count > 0 )); then
        ok "Applied ${count} example decoy manifest(s)"
    else
        warn "No .yaml files found in ${examples_dir}"
    fi
}

k8s_wait_ready() {
    info "Waiting for pods to become ready (up to 180s)..."
    kubectl wait --for=condition=ready pods --all \
        -n "$K8S_NAMESPACE" --timeout=180s 2>/dev/null || \
        warn "Some pods may not be ready yet — check 'kubectl get pods -n ${K8S_NAMESPACE}'"
    ok "Kubernetes deployment ready"
}

k8s_summary() {
    echo ""
    printf "  %s%s CI/CDecoy is running on Kubernetes! %s\n" "${BOLD}" "${GREEN}" "${RESET}"
    echo ""
    echo "  ${CYAN}Cluster:${RESET}       ${K8S_TOOL} / ${K8S_CLUSTER_NAME}"
    echo "  ${CYAN}Namespace:${RESET}     ${K8S_NAMESPACE}"
    echo "  ${CYAN}Helm release:${RESET}  ${HELM_RELEASE}"
    echo ""
    echo "  ${CYAN}Dashboard:${RESET}     http://localhost:8080  (via NodePort 30080)"
    echo ""
    echo "  ${YELLOW}Useful commands:${RESET}"
    echo "    kubectl get pods   -n ${K8S_NAMESPACE}"
    echo "    kubectl get decoys -n decoys-production"
    echo "    helm status ${HELM_RELEASE} -n ${K8S_NAMESPACE}"
    echo ""
    echo "  ${YELLOW}Tip:${RESET} Run '$0 --teardown --k8s' to remove the cluster."
    echo ""
}

# ── Teardown ────────────────────────────────────────────────────────────────

teardown_compose() {
    info "Tearing down Docker Compose stack..."
    cd "$REPO_DIR"

    $COMPOSE_CMD --profile tier3 --profile debug --profile security down -v 2>/dev/null || true

    ok "Docker Compose stack removed (containers + volumes)"
}

teardown_k8s() {
    info "Tearing down Kubernetes deployment..."

    # Determine which tool manages the cluster.
    if command -v k3d >/dev/null 2>&1 && k3d cluster list 2>/dev/null | grep -q "$K8S_CLUSTER_NAME"; then
        k3d cluster delete "$K8S_CLUSTER_NAME"
        ok "k3d cluster '${K8S_CLUSTER_NAME}' deleted"
    elif command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -q "$K8S_CLUSTER_NAME"; then
        kind delete cluster --name "$K8S_CLUSTER_NAME"
        ok "kind cluster '${K8S_CLUSTER_NAME}' deleted"
    elif command -v minikube >/dev/null 2>&1; then
        minikube delete --profile "$K8S_CLUSTER_NAME" 2>/dev/null || true
        ok "minikube profile '${K8S_CLUSTER_NAME}' deleted"
    else
        warn "No local cluster tool found — attempting Helm uninstall only"
        helm uninstall "$HELM_RELEASE" -n "$K8S_NAMESPACE" 2>/dev/null || true
        kubectl delete namespace "$K8S_NAMESPACE" 2>/dev/null || true
        kubectl delete namespace decoys-production 2>/dev/null || true
    fi
}

# ── Argument parsing ────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --k8s)
                MODE="k8s"
                shift
                ;;
            --tier3)
                TIER3=true
                shift
                ;;
            --teardown|--destroy|--clean)
                TEARDOWN=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1  (try --help)"
                ;;
        esac
    done
}

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Deploy the CI/CDecoy deception-as-code framework.

Options:
  (no flags)     Deploy via Docker Compose (default, simplest)
  --k8s          Deploy to a local Kubernetes cluster (k3d/kind/minikube)
  --tier3        Include Tier 3 LLM-backed decoys (Docker Compose only)
  --teardown     Remove all CI/CDecoy resources
  -h, --help     Show this help message

Examples:
  $(basename "$0")                     # Start with Docker Compose
  $(basename "$0") --tier3             # Start with Tier 3 LLM decoys
  $(basename "$0") --k8s              # Deploy to Kubernetes
  $(basename "$0") --teardown         # Clean up Docker Compose
  $(basename "$0") --teardown --k8s   # Clean up Kubernetes cluster
EOF
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
    banner
    parse_args "$@"
    check_common_prereqs
    resolve_repo

    if [[ "$TEARDOWN" == true ]]; then
        if [[ "$MODE" == "k8s" ]]; then
            teardown_k8s
        else
            teardown_compose
        fi
        ok "Teardown complete"
        exit 0
    fi

    if [[ "$MODE" == "k8s" ]]; then
        check_k8s_prereqs
        k8s_up
    else
        compose_up
    fi
}

main "$@"
