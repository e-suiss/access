# access-identity-audit

Audit chains of Access and their external renderings.

## Chains

| Chain | Rows | Checkpoint origin |
|---|---|---|
| Identity audit log | `access.identity_audit`: one minimal row written in the business transaction | `<cell>/identity-audit` |
| Authority operational stream | `access_ops.authority_audit`: protocol rejections, audit-depth reads and exports, which make no record | `<cell>/authority-operational` |

Rows are sequenced by the database and integrated off the request path into an RFC 9162 Merkle
tree, one tree per chain. Each checkpoint is a C2SP signed note of the cell's `audit-checkpoint`
key. Audit is never sampled: every rejection, every audit read and every export is one row, and
the answer leaves only after its row is in.

## Taxonomy and renderings

Every event name the code writes is listed in
[`conformance/catalog/audit-taxonomy.toml`](../../conformance/catalog/audit-taxonomy.toml),
compiled into `domain::taxonomy`, with its static OCSF class and activity and its CAEP
counterpart, if any. An event outside the taxonomy is never rendered.

One `AuditRecord` (common `txn`, `occurred_at`, `recorded_at`, `checkpoint_at`) renders three
ways, all of them copies, never the record:

| Adapter | Output |
|---|---|
| `adapters::ocsf` | OCSF 1.x JSON event |
| `adapters::cef` | Common Event Format line |
| `adapters::set` | Security Event Token claims (RFC 8417), signed as `secevent+jwt` |

The renderings are pinned by the vectors in [`conformance/audit/`](../../conformance/audit).

## Tests

```
cargo nextest run -p access-identity-audit
```

The checkpoint tests need PostgreSQL (`DATABASE_URL`).
