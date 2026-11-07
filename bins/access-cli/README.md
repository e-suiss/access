# access-cli

The Access command line for operators and developers.

```
access-cli [--config <PATH>] [--log <FILTER>] <COMMAND>
```

`--config` names the configuration file (default `access.toml`); each command reads only its own
sections of it. Secrets never come from arguments or the environment: the configuration names
credential files. Logs go to standard error as JSON; a command's result goes to standard output.

| Exit code | Meaning |
|---|---|
| 0 | Success |
| 2 | The command line is not valid |
| 3 | The configuration, or a file it names, cannot be used |
| 4 | The database cannot be reached or is not safe to use |
| 5 | The command ran and failed |

## `migrate`

Applies the schema migrations as the migration login and prints the ones it applied:

```
$ access-cli migrate --config /etc/access/migrate.toml
{"applied":[{"version":"20261107160000","description":"m2 sandbox domains"}]}
```

It reads the `[database]` section with its `migrator` role:

```toml
[database]
host = "access-db.access-db.svc"
port = 5432
name = "access"
root_cert_file = "/run/tls/ca.crt"
durability = "replicated"
migrator = { user = "access_migrator_login", password_file = "/run/secrets/db-migrator" }
```

The connection verifies the server's certificate against `root_cert_file` and checks the server
before anything runs. Applied migrations are skipped, so a second run prints `{"applied":[]}`.
The server never migrates on start; run this job before each rollout.

Migrations follow expand/contract: a release adds only what the running version ignores and
removes nothing it still reads, so the old version keeps serving while the job runs and during
the rollout. An index on a live table is built with `CREATE INDEX CONCURRENTLY` in a migration of
its own whose first line is `-- no-transaction`; `cargo xtask check` refuses one that is not.

### Kubernetes

`deploy/k8s/migrate-job.yaml` runs `access-cli migrate` as a Job from the server's image, with
the `migrate.toml` key of the server's ConfigMap and only the migration login's password. Argo CD
runs it as a `PreSync` hook. With Flux, keep the Job in a Kustomization of its own that the
server's Kustomization `dependsOn`; the Job is recreated on each change.
