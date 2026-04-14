#!/usr/bin/env bash
# setup-helm-files.sh — Copies config files into the Helm chart's files/ directory
# Run from platform/ directory
set -euo pipefail

CHART_FILES="helm/cicdecoy/files"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Setting up Helm chart files ==="

mkdir -p "$CHART_FILES/profiles" "$CHART_FILES/responses"

# Database schema
for f in "$REPO_ROOT"/config/schema.sql "$REPO_ROOT"/config/002_fs_delta.sql; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/" && echo "  ✓ $(basename "$f")"
done

# Platform configs
for f in "$REPO_ROOT"/config/engage-annotations.yaml "$REPO_ROOT"/config/falco-rules.yaml "$REPO_ROOT"/config/model-config.yaml "$REPO_ROOT"/config/model-config-local.yaml; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/" && echo "  ✓ $(basename "$f")"
done

# Device profiles
for f in "$REPO_ROOT"/decoys/profiles/*.json; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/profiles/" && echo "  ✓ profiles/$(basename "$f")"
done

# Scripted response databases
for f in "$REPO_ROOT"/decoys/responses/*.json; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/responses/" && echo "  ✓ responses/$(basename "$f")"
done

# Decoy manifests (example CRs)
for f in "$REPO_ROOT"/decoys/examples/*.yaml; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/" && echo "  ✓ examples/$(basename "$f")"
done

echo ""
echo "=== Done. Chart files populated: ==="
find "$CHART_FILES" -type f | sort | sed 's/^/  /'
echo ""
echo "Next: make deploy"
