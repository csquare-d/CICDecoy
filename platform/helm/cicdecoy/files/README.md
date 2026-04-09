# This directory is populated by setup-helm-files.sh
# It copies config files from your MVP into the Helm chart
# so they can be mounted as ConfigMaps.
#
# Run from repo root:
#   ./setup-helm-files.sh
#
# Expected contents after setup:
#   schema.sql
#   002_fs_delta.sql
#   engage-annotations.yaml
#   falco-rules.yaml
#   model-config.yaml
#   profiles/dev-workstation.json
#   responses/dev-workstation.json
