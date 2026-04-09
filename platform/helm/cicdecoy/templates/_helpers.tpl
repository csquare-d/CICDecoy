{{- define "cicdecoy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "cicdecoy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
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

{{/* Common env block for DB + NATS connection */}}
{{- define "cicdecoy.dataEnv" -}}
- name: NATS_URL
  value: "nats://{{ include "cicdecoy.fullname" . }}-nats:4222"
- name: DB_DSN
  valueFrom:
    secretKeyRef:
      name: {{ include "cicdecoy.fullname" . }}-db-credentials
      key: dsn
{{- end }}

{{/* Init containers that wait for NATS + TimescaleDB */}}
{{- define "cicdecoy.waitContainers" -}}
- name: wait-db
  image: busybox:1.36
  command: ['sh', '-c', 'until nc -z {{ include "cicdecoy.fullname" . }}-timescaledb 5432; do sleep 2; done']
- name: wait-nats
  image: busybox:1.36
  command: ['sh', '-c', 'until nc -z {{ include "cicdecoy.fullname" . }}-nats 4222; do sleep 2; done']
{{- end }}
