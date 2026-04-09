#!/usr/bin/env bash
# setup-helm-files.sh — Copies MVP config files into the Helm chart's files/ directory
# Run from repo root (MVP/)
set -euo pipefail

CHART_FILES="helm/cicdecoy/files"

echo "=== Setting up Helm chart files from MVP configs ==="

mkdir -p "$CHART_FILES/profiles" "$CHART_FILES/responses"

# Database schema
for f in config/schema.sql config/002_fs_delta.sql; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/" && echo "  ✓ $f"
done

# Platform configs
for f in config/engage-annotations.yaml config/falco-rules.yaml config/model-config.yaml config/model-config-local.yaml; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/" && echo "  ✓ $f"
done

# Device profiles
for f in profiles/*.json; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/profiles/" && echo "  ✓ $f"
done

# Scripted response databases
for f in ssh-decoy/responses/*.json; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/responses/" && echo "  ✓ $f"
done

# Decoy manifests (example CRs)
for f in config/dev-decoy.yaml config/dev-decoy-tier3.yaml; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/" && echo "  ✓ $f"
done

echo ""
echo "=== Done. Chart files populated: ==="
find "$CHART_FILES" -type f | sort | sed 's/^/  /'
echo ""
echo "Next: make deploy"
