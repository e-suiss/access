# access-cli

The Access command line for operators and developers.

The management commands (`admin`, `export`, `diff`, `apply`) act as an agent Instance, not with an administrator token. Every read uses a short-lived token bound to the Instance key with DPoP; every write is drafted, checked, signed as the Instance's own statement (AIS) and committed as one Exercise. There is no `--token` or `--bearer` option: a stolen read token is useless without the key and cannot write anyway.

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
| 5 | The command ran and failed, or a plan has conflicts; nothing after the failure was applied |
| 6 | The management API refused or did not answer |
| 7 | `diff`: changes pending; `replay`: mismatch |

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

## Connecting

Every management command takes:

| Option | Meaning |
|---|---|
| `--api <URL>` | The management API origin, `https://host[:port]` |
| `--realm <SLUG>` | The realm |
| `--issuer <URL>` | The realm issuer; its metadata names the token endpoint |
| `--client-id <ID>` | The Instance's client at the realm (`private_key_jwt`) |
| `--ca <PATH>` | PEM file of the CA the API and the issuer chain to |
| `--key-file <PATH>` or `--pkcs11 <URI>` | The Instance key: a PKCS#8 P-256 (or Ed25519) PEM file, or an RFC 7512 URI `pkcs11:token=…;object=…?module-path=…&pin-source=file:…` |
| `--basis <BASIS>` | What the AIS declares as its authority: `public:<GrantID>`, `anchor:<AnchorID>` or `holding:<GrantID>:<PartyID>:<since>`; required for writes |

Secrets never come from arguments or the environment: the PKCS#11 PIN is read from the file the URI names.

## Management commands

```text
access-cli admin  <connect> get|list|create|update|retire <resource> [key] [--body FILE] [--patch]
access-cli export <connect> [--with-generated] [--output FILE]
access-cli diff   <connect> --file realm.yaml [--prune]
access-cli apply  <connect> --file realm.yaml [--prune] [--proposals FILE]
access-cli apply  <connect> --release <kind>/<key> [--proposals FILE]
access-cli replay --bundle bundle.json
```

- **`admin`** reads and writes the resources the management API contract (`sdks/openapi/admin-v1.json`) lists: `clients`, `groups`, `upstream-idps`, `accounts`, `settings/<section>`, `mappers`. A name the contract does not list is refused before anything is sent. `update` reads the current `ETag` and sends it as `If-Match`. `retire` is the only removal; nothing is deleted.
- **`export`** writes the realm's configuration as YAML: resources sorted by their natural key, keys sorted, strings quoted, server-generated members and retired resources left out (keep them with `--with-generated`). Secrets appear only as `secret://` references; a secret value anywhere stops the export.
- **`diff`** shows the plan from the running realm to a document, without writing. Only the members the document sets are compared: deleting a line from the file stops managing that member, it does not reset it. Exit status 0 means in sync, 7 means changes, 5 means conflicts.
- **`apply`** reconciles: each change is one Exercise, applied in plan order, stopping at the first failure. A plan with a conflict applies nothing.
- **`replay`** re-evaluates a recorded decision with the Kernel from a bundle `{"input": <hex CBOR>, "decision": <hex CBOR>, "fuel": <n>}` and prints `match` or `mismatch`.

## The reconciler's rules

- It acts as its own agent Instance under its own Grant. That Grant holds no reserved action, so reserved changes (an upstream identity provider, the RP ID) are never applied: they are written as proposals for a quorum to sign.
- A resource retired at runtime is a restriction. The reconciler reports it and never brings it back.
- The emergency escape is `apply --release <kind>/<key>`. It is not an "unmanage" switch: it proposes the resource's retirement as an audited restriction, and once that commits, the reconciler leaves it retired.
- Runtime resources the document does not name are left alone, unless `--prune` retires them.

## Document format

```yaml
realm: "acme"
clients:
  - client_id: "c-1"
    display_name: "Billing"
    redirect_uris:
      - "https://billing.example/cb"
    token_endpoint_auth_method: "private_key_jwt"
groups:
  - name: "ops"
    display_name: "Operations"
    membership_issuer: "admin"
upstream_idps: []
settings:
  branding:
    display_name: "Acme"
```

A client without `client_id` is created and the server assigns one; add it to the file afterwards. The reader accepts plain YAML block style, comments, quoted and plain scalars, and one-line JSON values; anchors, tags, block scalars and multiple documents are refused with the line number.
