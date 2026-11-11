# OpenTofu

OpenTofu provisions an Access cell's infrastructure: the namespaces, the secret store roles and
the Helm release of `deploy/helm/access`. It never configures a realm, a domain or a client:
that configuration is an Exercise through the management API, decided and recorded like any
other change. `cargo xtask check` (`tofu-infra-only`) refuses any file here that names an `idp.*`
action, the decision or management API, or the Access CLI.

```sh
cd deploy/tofu/cell
tofu init
tofu apply -var cell=eu-central-1 -var region=eu-central -var image_digest=sha256:...
```

The database cluster (CloudNativePG, `deploy/k8s/cnpg/`), the HSM partitions and the cluster
itself belong to the operator's own infrastructure code.
