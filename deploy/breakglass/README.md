# Operator break-glass

`access-breakglass` is the cell operator's way in when the normal path is down. It is a separate
binary with no database, Redis, signer, Relay, risk engine or MFA dependency. It never makes an
authority decision and never touches authority state or user data: emergencies inside a tenant's
authority go through the tenant's own break-glass Grants, not through this tool.

What it can do:

| Operation | Effect |
|---|---|
| `config.read` | prints the cell's `access.toml` |
| `health` | probes the internal `/healthz` |
| `epoch.floor` | every session and refresh family issued before now ends |
| `leader.unhealthy` / `leader.healthy` | the leader gives its leases up and takes none, or leads again |
| `flag:<name>:on` / `flag:<name>:off` | an operational feature flag |

## Cell layout

```text
/etc/access/breakglass/<cell>/
  cell            settings (see example/cell)
  keys            this cell's approver keys and quorum (see example/keys)
  directive.key   the cell's directive signing seed, 0400, owner only
/var/lib/access/breakglass/<cell>/   state: trail, nonces, spent key generations
/var/lib/access/ops/directives/      signed directives access-server reads every second
```

Every cell has its own keys. `access-server` is told where the directives are and which key
signs them:

```toml
[breakglass]
cell = "eu-1"
directives = "/var/lib/access/ops/directives"
directive_key = "<the public key access-breakglass keygen printed for directive.key>"
```

Make the trail append-only on the host (`chattr +a /var/lib/access/breakglass/<cell>/trail`).

## Using it

```sh
# one approver drafts a document valid for at most 15 minutes
access-breakglass document eu-1 epoch.floor,leader.unhealthy 15 incident.cbor
# two of the three approvers sign it offline, each with their own key file
access-breakglass approve incident.cbor alice /media/alice/breakglass.seed
access-breakglass approve incident.cbor bora /media/bora/breakglass.seed
# the operator on the cell runs it
access-breakglass run /etc/access/breakglass/eu-1 incident.cbor
```

A FIDO2 security key approves by signing the document's challenge (printed by `document`) for
relying party `rp`; its assertion goes into the document's approvals.

Each run:

- verifies the document offline: the cell, a window of at most 15 minutes that holds now, and a
  quorum of distinct approver keys;
- refuses a nonce it has seen and a key set it has already used;
- writes every step to the hash-chained trail, to syslog and, when it answers, to the SIEM
  collector, and refuses to run at all when the trail does not verify;
- runs the alarm hook and applies nothing unless it succeeds;
- writes one signed directive per operation and spends the key set.

After a use, rotate: generate new approver keys and install them with a higher generation.

```sh
access-breakglass rotate /etc/access/breakglass/eu-1 keys-generation-2
```

## Drills

Once a quarter, run a real document through `access-breakglass drill`: the whole path runs, the
trail and the alarm record it, and nothing is applied.

## Operator database access

Operators read the database only as `access_operator`: certificate login, read-only, no table
grant by default, and every statement and connection logged. Apply `operator-role.sql` once and
add `pg_hba-operator.conf` and `pg_ident-operator.conf` to the cluster's configuration. There is
no standing emergency administrator account in the database.
