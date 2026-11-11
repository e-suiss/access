{{/*
CMP-22, CR-21, OP-158 m.3 (y), m.4 (k): the two signers as native sidecars, in a file of their
own beside the server's StatefulSet template.
*/}}
{{- define "access.signers" -}}
      # CMP-22, CR-21: the two signers, each in its own container with its own token and vault
      initContainers:
        # CMP-22a: the authority signer beside the server, reached only over the shared socket
        # directory; no network port. A native sidecar (OP-94, OP-158 m.3 (y)): it starts before
        # the server and gets SIGTERM only after the server has drained, so it stops accepting,
        # finishes in flight, drops its keys and closes its HSM sessions last
        - name: authority-signer
          restartPolicy: Always
          image: {{ include "access.image" . }}
          imagePullPolicy: IfNotPresent
          command: ["/usr/local/bin/access-signer"]
          env:
            - name: ACCESS_SIGNER_CONFIG
              value: /etc/access/signer.toml
          volumeMounts:
            - name: config
              mountPath: /etc/access
              readOnly: true
            - name: {{ if .Values.planes.split }}authority-secrets{{ else }}secrets{{ end }}
              mountPath: /run/secrets
              readOnly: true
            - name: sockets
              mountPath: /run/access
            - name: signer-vault
              mountPath: /var/lib/access/signer
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            privileged: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            capabilities:
              drop: [ALL]
            seccompProfile:
              type: RuntimeDefault
        # CMP-22b: the identity signer beside the server, reached only over the shared socket
        # directory; no network port; a native sidecar like the authority signer
        - name: identity-signer
          restartPolicy: Always
          image: {{ include "access.image" . }}
          imagePullPolicy: IfNotPresent
          command: ["/usr/local/bin/access-identity-signer"]
          env:
            - name: ACCESS_IDENTITY_SIGNER_CONFIG
              value: /etc/access/identity-signer.toml
          volumeMounts:
            - name: config
              mountPath: /etc/access
              readOnly: true
            - name: {{ if .Values.planes.split }}identity-secrets{{ else }}secrets{{ end }}
              mountPath: /run/secrets
              readOnly: true
            - name: sockets
              mountPath: /run/access
            - name: identity-signer-vault
              mountPath: /var/lib/access/identity-signer
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            privileged: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            capabilities:
              drop: [ALL]
            seccompProfile:
              type: RuntimeDefault
{{- end }}
