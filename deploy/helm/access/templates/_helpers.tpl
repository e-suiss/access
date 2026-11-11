{{/* OP-49: the image by digest */}}
{{- define "access.image" -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- end }}

{{- define "access.labels" -}}
app.kubernetes.io/name: access-server
app.kubernetes.io/part-of: access
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
