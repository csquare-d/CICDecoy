{{- define "cicdecoy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "cicdecoy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | lower | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | lower | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "cicdecoy.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "cicdecoy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: cicdecoy
{{- end }}

{{- define "cicdecoy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cicdecoy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Resolve a container image reference for a cicdecoy component.
Input: dict with keys:
  ctx       - the root context (.)
  component - values sub-object (e.g. .Values.operator) with .image.repository / .image.tag
  default   - default image short name, e.g. "cicdecoy-operator"
Returns "<repository>:<tag>".
  - If component.image.repository is set, it is used verbatim.
  - Otherwise "<global.imageRegistry>/<default>" is used.
  - tag falls back to component.image.tag, then to .Chart.AppVersion.
*/}}
{{- define "cicdecoy.image" -}}
{{- $ctx := .ctx -}}
{{- $component := .component -}}
{{- $default := .default -}}
{{- $registry := $ctx.Values.global.imageRegistry | default "ghcr.io/csquare-d" -}}
{{- $repo := "" -}}
{{- if and $component $component.image $component.image.repository -}}
{{- $repo = $component.image.repository -}}
{{- else -}}
{{- $repo = printf "%s/%s" $registry $default -}}
{{- end -}}
{{- $tag := "" -}}
{{- if and $component $component.image $component.image.tag -}}
{{- $tag = $component.image.tag -}}
{{- else -}}
{{- $tag = $ctx.Chart.AppVersion -}}
{{- end -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end }}

{{/*
Resolve the imagePullPolicy for a component, falling back to
global.imagePullPolicy then to IfNotPresent.
*/}}
{{- define "cicdecoy.imagePullPolicy" -}}
{{- $ctx := .ctx -}}
{{- $component := .component -}}
{{- if and $component $component.image $component.image.pullPolicy -}}
{{- $component.image.pullPolicy -}}
{{- else if $ctx.Values.global.imagePullPolicy -}}
{{- $ctx.Values.global.imagePullPolicy -}}
{{- else -}}
IfNotPresent
{{- end -}}
{{- end }}

{{/*
Render imagePullSecrets from global.imagePullSecrets (a list of strings or
name-dicts). Output is a `imagePullSecrets:` block suitable for a PodSpec,
or nothing when none are configured.
*/}}
{{- define "cicdecoy.imagePullSecrets" -}}
{{- $secrets := .Values.global.imagePullSecrets | default (list) -}}
{{- if $secrets }}
imagePullSecrets:
{{- range $s := $secrets }}
{{- if kindIs "string" $s }}
  - name: {{ $s }}
{{- else }}
  - {{ toYaml $s | nindent 4 }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Resolve the TimescaleDB password.
Precedence:
  1. If values.timescaledb.auth.existingSecret is set, caller should consume
     that Secret directly; this helper returns an empty string (not used).
  2. If values.timescaledb.auth.password is a non-empty string, use it.
  3. If a Secret named `{fullname}-db-credentials` already exists in the
     release namespace, re-use the stored password (idempotent upgrades).
  4. Otherwise generate a new 24-character randAlphaNum.
*/}}
{{- define "cicdecoy.db.password" -}}
{{- $fullname := include "cicdecoy.fullname" . -}}
{{- $secretName := printf "%s-db-credentials" $fullname -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $secretName -}}
{{- $prior := "" -}}
{{- if and $existing $existing.data -}}
{{- if index $existing.data "password" -}}
{{- $prior = index $existing.data "password" | b64dec -}}
{{- end -}}
{{- end -}}
{{- if .Values.timescaledb.auth.password -}}
{{- .Values.timescaledb.auth.password -}}
{{- else if $prior -}}
{{- $prior -}}
{{- else -}}
{{- randAlphaNum 24 -}}
{{- end -}}
{{- end }}

{{/*
Name of the Secret holding DB credentials — either user-provided
existingSecret or the chart-managed `{fullname}-db-credentials`.
*/}}
{{- define "cicdecoy.db.secretName" -}}
{{- if .Values.timescaledb.auth.existingSecret -}}
{{- .Values.timescaledb.auth.existingSecret -}}
{{- else -}}
{{ include "cicdecoy.fullname" . }}-db-credentials
{{- end -}}
{{- end }}

{{/*
Name of the Secret holding the NATS auth token — either user-provided
existingSecret or the chart-managed `{fullname}-nats-auth`.
*/}}
{{- define "cicdecoy.natsAuthSecretName" -}}
{{- if .Values.nats.existingSecret -}}
{{- .Values.nats.existingSecret -}}
{{- else -}}
{{ include "cicdecoy.fullname" . }}-nats-auth
{{- end -}}
{{- end }}

{{/* Common env block for DB + NATS connection */}}
{{- define "cicdecoy.dataEnv" -}}
- name: NATS_URL
  value: "nats://{{ include "cicdecoy.fullname" . }}-nats.{{ .Release.Namespace }}.svc.cluster.local:4222"
{{- if .Values.nats.auth.enabled }}
- name: NATS_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "cicdecoy.natsAuthSecretName" . }}
      key: token
{{- end }}
- name: DB_DSN
  valueFrom:
    secretKeyRef:
      name: {{ include "cicdecoy.db.secretName" . }}
      key: dsn
{{- end }}

{{/* Init containers that wait for NATS + TimescaleDB */}}
{{- define "cicdecoy.waitContainers" -}}
- name: wait-db
  image: busybox:1.36
  command: ['sh', '-c', 'until nc -z {{ include "cicdecoy.fullname" . }}-timescaledb 5432; do sleep 2; done']
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
        - ALL
  resources:
    requests:
      cpu: 10m
      memory: 16Mi
    limits:
      cpu: 100m
      memory: 64Mi
- name: wait-nats
  image: busybox:1.36
  command: ['sh', '-c', 'until nc -z {{ include "cicdecoy.fullname" . }}-nats 4222; do sleep 2; done']
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
        - ALL
  resources:
    requests:
      cpu: 10m
      memory: 16Mi
    limits:
      cpu: 100m
      memory: 64Mi
{{- end }}
