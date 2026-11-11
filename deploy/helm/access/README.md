# Access Helm chart

One Access cell: `access-server` with its authority and identity signers as native sidecars, the
schema migration Job, the Services, the PodDisruptionBudget, the network policies and the secret
store classes. It renders the same objects as `deploy/k8s` (kustomize).

```sh
helm install access deploy/helm/access --namespace access \
  --set image.sha256=<digest hex> \
  --set cells.this=eu-central-1
```

| Values file | Profile |
|---|---|
| `values.yaml` | A replicated cell: three replicas, a hard spread over at least three zones |
| `values-small-provider.yaml` | One replica, `durability: single-node` |
| `values-plane-split.yaml` | The authority plane's and the identity plane's signers read separate secret stores under separate operator roles |

The lifecycle values are the server's own: preStop 5 s, then a 2 s drain while not ready and a
15 s bound for in-flight requests, inside a 45 s grace period. Liveness never waits on readiness;
migrations run as their own Job.

`rendered/` holds what the chart renders for each profile. After a change, run `just helm-render`;
`just helm-check` (CI) fails when the chart and its renders differ.
