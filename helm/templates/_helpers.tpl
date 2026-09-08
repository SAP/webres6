{{/*
Expand the name of the chart.
*/}}
{{- define "webres6.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "webres6.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "webres6.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "webres6.labels" -}}
helm.sh/chart: {{ include "webres6.chart" . }}
{{ include "webres6.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "webres6.selectorLabels" -}}
app.kubernetes.io/name: {{ include "webres6.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "webres6.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "webres6.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Selenium hub URL — auto-derived when selenium.deploy is true, otherwise uses selenium.url.
*/}}
{{- define "webres6.selenium.url" -}}
{{- if .Values.selenium.deploy -}}
http://{{ .Release.Name }}-selenium-hub:4444/wd/hub
{{- else -}}
{{ .Values.selenium.url }}
{{- end -}}
{{- end }}

{{/*
Selenium basic-auth secret name — auto-derived when selenium.deploy is true, otherwise uses selenium.secret.
*/}}
{{- define "webres6.selenium.secret" -}}
{{- if .Values.selenium.deploy -}}
{{ .Release.Name }}-selenium-basic-auth-secrets
{{- else -}}
{{ .Values.selenium.secret }}
{{- end -}}
{{- end }}

{{/*
Guard: ingress and Gateway API routing are mutually exclusive — enabling both
would double-expose every path. Fail rendering early with a clear message.
*/}}
{{- define "webres6.routing.guard" -}}
{{- if and .Values.ingress.enabled .Values.gateway.enabled -}}
{{- fail "ingress.enabled and gateway.enabled are mutually exclusive — pick one router" -}}
{{- end -}}
{{- end }}

{{/*
Gateway parentRef name — the existing (shared) Gateway to attach the HTTPRoute
to, defaulting to the chart's own Gateway name when not overridden.
*/}}
{{- define "webres6.gateway.parentName" -}}
{{- .Values.gateway.gatewayRef.name | default (include "webres6.fullname" .) -}}
{{- end }}

{{/*
Valkey connection URL — auto-derived when valkey.deploy is true, otherwise uses valkey.url.
*/}}
{{- define "webres6.valkey.url" -}}
{{- if .Values.valkey.deploy -}}
valkey://{{ .Release.Name }}-valkey:6379/0
{{- else -}}
{{ .Values.valkey.url }}
{{- end -}}
{{- end }}
