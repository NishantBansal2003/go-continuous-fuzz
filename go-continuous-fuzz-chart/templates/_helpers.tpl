{{- define "go-continuous-fuzz-chart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "go-continuous-fuzz-chart.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "go-continuous-fuzz-chart.roleName" -}}
{{- default (printf "%s-role" (include "go-continuous-fuzz-chart.fullname" .)) .Values.rbac.roleName }}
{{- end }}

{{- define "go-continuous-fuzz-chart.roleBindingName" -}}
{{- default (printf "%s-rolebinding" (include "go-continuous-fuzz-chart.fullname" .)) .Values.rbac.roleBindingName }}
{{- end }}


{{- define "go-continuous-fuzz-chart.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}