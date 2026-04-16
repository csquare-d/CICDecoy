# Helm chart static file assets

This directory is part of the chart. Its contents are committed to the
repository and consumed by templates via `.Files.Get` / `.Files.Glob`, so
`helm install ./platform/helm/cicdecoy` works on a fresh clone with no
pre-install scripts.

## Canonical sources and sync

These files are copies of canonical sources that live elsewhere in the repo:

| File                                | Canonical source                     |
| ----------------------------------- | ------------------------------------ |
| `schema.sql`                        | `config/schema.sql`                  |
| `002_fs_delta.sql`                  | `config/002_fs_delta.sql`            |
| `engage-annotations.yaml`           | `config/engage-annotations.yaml`     |
| `falco-rules.yaml`                  | `config/falco-rules.yaml`            |
| `model-config.yaml`                 | `config/model-config.yaml`           |
| `profiles/*.json`                   | `decoys/profiles/*.json`             |
| `responses/*.json`                  | `decoys/responses/*.json`            |

To refresh this directory from the canonical sources after editing them,
run `platform/setup-helm-files.sh`. The sync script does NOT need to be
run before `helm install` or `helm package` — it only needs to run when
a canonical source file changes.
