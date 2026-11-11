# High availability, backup and recovery

A cell's canonical PostgreSQL is a primary and two synchronous standbys in three availability
zones. Every security write waits for one of the two standbys (`ANY 1 (sb_a, sb_b)`,
`synchronous_commit = on`), so losing a zone loses no acknowledged write, and losing one standby
does not stop writes. Backups go to two encrypted repositories with continuous WAL archiving.

| File | What it is |
|---|---|
| `../k8s/cnpg/cluster.yaml` | the cell under CloudNativePG (the Kubernetes default) |
| `../patroni/patroni.yml` | the cell under Patroni (self-hosted, outside Kubernetes) |
| `pgbackrest.conf` | pgBackRest: two encrypted repositories, archive, verification |
| `schedule.yaml` | full, differential and incremental backups and the daily `verify` |

wal-g is a documented alternative to pgBackRest; the configuration here is pgBackRest.

## What `access-server` checks at start

- `synchronous_commit` is `on` on every security connection (the server sets it at connect, so a
  role or database default of `local` cannot weaken it).
- In the replicated profile, `synchronous_standby_names` is `ANY k (...)` with at least two
  standbys and more standbys than `k`. One standby with `on` is refused: losing it would hang
  every write.
- With `[database.topology]` declared, every standby of the quorum is declared, each in a zone of
  its own away from the primary, and a standby in another region is accepted only in the
  multi-region sync class under the OP-28 round-trip ceiling. Synchronous writing across continents is
  refused.
- No logical replication subscription and no multi-primary extension (`bdr`, `pglogical`,
  `spock`, `pgactive`) writes into the canonical store: last-writer-wins and quorum-less
  multi-primary are refused.

Each pool follows the writable host. `[database] hosts` lists the cell's other nodes
(`name` or `name:port`); a pool opens connections only to the host whose `pg_is_in_recovery()`
is false, and once that host changes every connection opened before is evicted. While no host
accepts writes, the pools answer errors (never a write to a read-only standby) and back off.

The read replica (`replica_host`) serves only admin search and listing, reports and the audit
trail, and a user's own profile under read-your-writes. A replica behind its threshold
(`replica_max_lag_ms`, 5 s by default) is taken out of use. Every read that feeds a security
decision goes to the primary.

## Failover

The orchestrator promotes only a synchronous standby of the same cluster. Neither manifest has a
replica cluster or a standby cluster: there is no automatic failover across clusters, and an async
copy is never promoted into an authority domain's lineage. After a promote, the next sequencer
leader takes the domain under a new epoch; the old leader's writes no longer commit.

Moving a domain to another cell is a seal and an acceptance: the source seals the head at
position q under epoch e and appends nothing more; the target replays the image (chain, Merkle
root, fold from Genesis) and accepts it at (q, e + 1). After a region loss the domain continues
only with a fence proof of the lost cell's storage and with its last committed head and its
witnessed checkpoint covered; otherwise it stays closed and the path is `domain.recover`.

## Restore

1. Restore to a separate instance first (`pgbackrest restore --type=time --target=...`). A restore
   never goes straight back into traffic.
2. Run `access-server reshred`. Until the shred journal is applied again the server refuses to
   serve (`restore-reshred-pending`).
3. Run `access-server drill restore <baseline.json>` against it (see below). An authority log
   behind the checkpoint its witnesses saw is not opened: its missing suffix comes from the
   domain's replica and must reproduce the witnessed root, or the domain is recovered with
   `domain.recover`. A restore never reuses a position or changes a lineage.
4. Only then switch traffic.

There is no row-level restore of a tenant or a realm. `pg_restore -t` does not bring dependent
rows and objects. The documented path is a side restore and a logical copy: restore the cluster
to a point in time on another instance, copy the realm's rows in dependency order, and apply the
deletion facts again with `access-server reshred`. An authority domain is rebuilt from its log,
body store and replica by a fold from Genesis and accepted by a seal and acceptance; that is
rebuilding a domain, not restoring a tenant.

## Restore drill

Quarterly, against a side restore:

```sh
access-server drill baseline > baseline.json        # before the backup the drill restores
# restore with pgBackRest to a point in time, then:
access-server drill restore baseline.json
```

The drill runs the nine items in order and prints a report; a failed item fails the command. The
report's digest is written to the identity audit log as `drill.restore`, under the cell's signed
audit checkpoint.

| # | Item | How it is checked |
|---|---|---|
| 1 | point-in-time recovery to a chosen moment | no authority record after the target |
| 2 | signing keys back together | every realm's key set and every domain's event key load |
| 3 | JWKS serves the same `kid`s | every realm's `kid`s equal the baseline's |
| 4 | schema version fits the binary | the newest applied migration is this binary's |
| 5 | RTO with and without tuned parallelism | `rto_ms` in the baseline file, from the restore |
| 6 | repository integrity | `repo_verified` in the baseline file, from `pgbackrest verify` |
| 7 | deletion facts applied again | no restore generation waits for a re-shred |
| 8 | authority log against its witnessed checkpoint | chain, Merkle root and fold of every domain |
| 9 | break-glass path in the restored environment | the cell's directives read |

Items 5 and 6 take the backup tool's own evidence as input and are `not-run` without it.

## Async DR profile

A realm may declare the async DR profile (`idp.realm.dr_profile {rpo_s}`, CT3): a single region
plus an async copy, with a declared RPO above zero. After the orchestrator promotes the copy, run
`access-server dr-promote` before anything serves. It refuses unless every live realm of the cell
declared the profile; otherwise it ends every session and refresh family (everyone signs in
again; password and MFA changes in the loss window may be lost), records the promote and a restore
generation, and keeps every authority domain unled until it continues under a fence proof. Then
run `access-server reshred`.

## Rolling upgrade

```sh
access-server upgrade-check --manifest > target.json    # with the new build
access-server upgrade-check --to target.json            # with the running build: 0, 3 or 4
```

| Exit | Meaning |
|---|---|
| 0 | a rolling upgrade is possible |
| 3 | it is not: stop every node, then start the new build |
| 4 | rolling upgrades are switched off here (`[upgrade] rolling = false`) |

During the roll every node runs the new binary but evaluates the old semantic version. A new
version takes effect only after its activation record (`version_activate`) commits; from then on
only nodes that evaluate it lead the domain.
