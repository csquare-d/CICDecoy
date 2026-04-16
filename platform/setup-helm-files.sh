#!/usr/bin/env bash
# setup-helm-files.sh — Re-sync the Helm chart's files/ directory from the
# canonical sources under config/ and decoys/.
#
# You do NOT need to run this before `helm install` or `helm package`.
# The files in helm/cicdecoy/files/ are committed to the repo and the chart
# installs cleanly without running this script. Run it only after editing a
# canonical source (e.g. config/schema.sql) to refresh the chart copy.
set -euo pipefail

CHART_FILES="helm/cicdecoy/files"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$(dirname "$0")"

echo "=== Re-syncing Helm chart files from canonical sources ==="

mkdir -p "$CHART_FILES/profiles" "$CHART_FILES/responses"

# Database schema
for f in "$REPO_ROOT"/config/schema.sql "$REPO_ROOT"/config/002_fs_delta.sql; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/" && echo "  sync $(basename "$f")"
done

# Platform configs
for f in "$REPO_ROOT"/config/engage-annotations.yaml "$REPO_ROOT"/config/falco-rules.yaml "$REPO_ROOT"/config/model-config.yaml "$REPO_ROOT"/config/model-config-local.yaml; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/" && echo "  sync $(basename "$f")"
done

# Device profiles
for f in "$REPO_ROOT"/decoys/profiles/*.json; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/profiles/" && echo "  sync profiles/$(basename "$f")"
done

# Scripted response databases
for f in "$REPO_ROOT"/decoys/responses/*.json; do
  [ -f "$f" ] && cp "$f" "$CHART_FILES/responses/" && echo "  sync responses/$(basename "$f")"
done

echo ""
echo "=== Done. Current chart files: ==="
find "$CHART_FILES" -type f | sort | sed 's/^/  /'
echo ""
echo "Review the diff and commit the changes if any files were updated."
