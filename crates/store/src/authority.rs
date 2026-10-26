//! Authority log, head, lease and the atomic batch commit (OP-130 m.5, m.6; §17.1.1 steps 10–12).

use std::time::Duration;

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// A log record as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecord {
    /// Position.
    pub pos: u64,
    /// `genesis`, `opening`, `decision` or `claim`.
    pub kind: &'static str,
    /// Trusted time in milliseconds.
    pub recorded_at: u64,
    /// Leaf hash.
    pub leaf_hash: [u8; 32],
    /// Canonical CBOR of the record envelope.
    pub envelope: Vec<u8>,
}

/// The stored head of a domain log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadRow {
    /// Position of the last record.
    pub pos: u64,
    /// Epoch of the last leader that acquired the domain.
    pub epoch: u64,
    /// Leaf hash of the last record.
    pub leaf_hash: [u8; 32],
    /// Its `recorded_at`.
    pub recorded_at: u64,
    /// Merkle frontier, largest subtree first.
    pub frontier: Vec<[u8; 32]>,
}

/// A consumed nonce (TI-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceRow {
    /// The nonce.
    pub nonce: Vec<u8>,
    /// Actor reference bytes.
    pub actor: Vec<u8>,
    /// Intent digest.
    pub intent_digest: [u8; 32],
    /// Position of the `DecisionRecord` it maps to.
    pub decision_pos: u64,
}

/// One outbox event, written with the record it derives from (OP-130 m.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxRow {
    /// Position of the record.
    pub pos: u64,
    /// Index of the event within the record.
    pub idx: u32,
    /// Keyed event id (OP-130 m.8).
    pub event_id: [u8; 32],
    /// Event payload.
    pub event: Vec<u8>,
}

/// Signed bytes kept verbatim (§17.6.1 rule 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofRow {
    /// Digest of `bytes`.
    pub digest: [u8; 32],
    /// The exact bytes received.
    pub bytes: Vec<u8>,
}

/// A draw on a counter: allowed while `used + draw <= limit` (§17.1.1 step 9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draw {
    /// Counter key.
    pub key: Vec<u8>,
    /// The limit the evaluation saw.
    pub limit: u64,
    /// Amount drawn.
    pub draw: u64,
}

/// Everything one batch writes, in one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBatch {
    /// Leader epoch.
    pub epoch: u64,
    /// Head position the batch extends.
    pub after: u64,
    /// Records in position order.
    pub records: Vec<LogRecord>,
    /// The head after the batch.
    pub head: HeadRow,
    /// Nonces consumed by the batch.
    pub nonces: Vec<NonceRow>,
    /// Outbox events.
    pub outbox: Vec<OutboxRow>,
    /// Proof bytes.
    pub proofs: Vec<ProofRow>,
    /// Keys the evaluations read, with the version each saw; 0 means absent (TI-4).
    pub reads: Vec<(Vec<u8>, u64)>,
    /// Keys the records change, with the position that changes them.
    pub writes: Vec<(Vec<u8>, u64)>,
    /// Counter draws.
    pub draws: Vec<Draw>,
    /// Single-use flags set, with the position that sets them.
    pub single_use: Vec<(Vec<u8>, u64)>,
}

/// A held sequencer lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    /// The epoch this lease fences writes with.
    pub epoch: u64,
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn hash(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn millis(d: Duration) -> Result<i64, StoreError> {
    i64::try_from(d.as_millis()).map_err(|_| StoreError::Range)
}

fn kind(k: &str) -> Result<&'static str, StoreError> {
    ["genesis", "opening", "decision", "claim"]
        .into_iter()
        .find(|known| *known == k)
        .ok_or(StoreError::Corrupt)
}

/// Creates a domain from its Genesis record (position 0) and maps it to a tenant (OP-12 m.1).
///
/// # Errors
/// [`StoreError`]; a second Genesis for the same domain fails on the primary key.
pub async fn create_domain(
    sequencer: &PgPool,
    domain: &DomainId,
    tenant: [u8; 16],
    genesis: &LogRecord,
) -> Result<HeadRow, StoreError> {
    if genesis.pos != 0 || genesis.kind != "genesis" {
        return Err(StoreError::Range);
    }
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let id = domain.as_bytes().as_slice();
    sqlx::query!(
        "INSERT INTO access.authority_domain (domain_id, tenant_id) VALUES ($1, $2)",
        id,
        sqlx::types::Uuid::from_bytes(tenant),
    )
    .execute(&mut *t.tx)
    .await?;
    let recorded_at = signed(genesis.recorded_at)?;
    sqlx::query!(
        "INSERT INTO access.authority_log (domain_id, pos, kind, recorded_at, leaf_hash, envelope)
         VALUES ($1, 0, 'genesis', $2, $3, $4)",
        id,
        recorded_at,
        genesis.leaf_hash.as_slice(),
        genesis.envelope.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    let frontier = vec![genesis.leaf_hash.to_vec()];
    sqlx::query!(
        "INSERT INTO access.domain_head (domain_id, pos, epoch, leaf_hash, recorded_at, frontier)
         VALUES ($1, 0, 0, $2, $3, $4)",
        id,
        genesis.leaf_hash.as_slice(),
        recorded_at,
        &frontier,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(HeadRow {
        pos: 0,
        epoch: 0,
        leaf_hash: genesis.leaf_hash,
        recorded_at: genesis.recorded_at,
        frontier: vec![genesis.leaf_hash],
    })
}

/// Acquires the domain's sequencer lease under a new epoch and fences the head with it, so a
/// previous leader's next head compare-and-set fails (TI-2, OP-31).
///
/// # Errors
/// [`StoreError::LeaseHeld`] while another holder's lease is live.
pub async fn acquire_lease(
    sequencer: &PgPool,
    domain: &DomainId,
    holder: &str,
    ttl: Duration,
) -> Result<(Lease, HeadRow), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let id = domain.as_bytes().as_slice();
    let ms = millis(ttl)?;
    let epoch = sqlx::query_scalar!(
        "INSERT INTO access.sequencer_lease (domain_id, holder, epoch, acquired_at, expires_at)
         SELECT domain_id, $2, epoch + 1, now(), now() + $3::bigint * interval '1 millisecond'
           FROM access.domain_head WHERE domain_id = $1
         ON CONFLICT (domain_id) DO UPDATE
           SET holder = EXCLUDED.holder, epoch = GREATEST(sequencer_lease.epoch, EXCLUDED.epoch - 1) + 1,
               acquired_at = EXCLUDED.acquired_at, expires_at = EXCLUDED.expires_at, released_at = NULL
           WHERE sequencer_lease.expires_at < now() OR sequencer_lease.released_at IS NOT NULL
              OR sequencer_lease.holder = EXCLUDED.holder
         RETURNING epoch",
        id,
        holder,
        ms,
    )
    .fetch_optional(&mut *t.tx)
    .await?
    .ok_or(StoreError::LeaseHeld)?;
    sqlx::query!(
        "UPDATE access.domain_head SET epoch = $2 WHERE domain_id = $1 AND epoch < $2",
        id,
        epoch,
    )
    .execute(&mut *t.tx)
    .await?;
    let head = read_head_in(&mut t).await?;
    t.commit().await?;
    Ok((
        Lease {
            epoch: unsigned(epoch)?,
        },
        head,
    ))
}

/// Extends a held lease.
///
/// # Errors
/// [`StoreError::LeaseLost`] when the lease expired to, or was taken by, another holder.
pub async fn renew_lease(
    sequencer: &PgPool,
    domain: &DomainId,
    holder: &str,
    lease: Lease,
    ttl: Duration,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let rows = sqlx::query!(
        "UPDATE access.sequencer_lease SET expires_at = now() + $4::bigint * interval '1 millisecond'
          WHERE domain_id = $1 AND holder = $2 AND epoch = $3 AND released_at IS NULL AND expires_at >= now()",
        domain.as_bytes().as_slice(),
        holder,
        signed(lease.epoch)?,
        millis(ttl)?,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::LeaseLost);
    }
    t.commit().await
}

/// Releases a held lease so a new leader need not wait for expiry (OP-31).
///
/// # Errors
/// [`StoreError::LeaseLost`] when the lease is no longer ours.
pub async fn release_lease(
    sequencer: &PgPool,
    domain: &DomainId,
    holder: &str,
    lease: Lease,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let rows = sqlx::query!(
        "UPDATE access.sequencer_lease SET released_at = now()
          WHERE domain_id = $1 AND holder = $2 AND epoch = $3 AND released_at IS NULL",
        domain.as_bytes().as_slice(),
        holder,
        signed(lease.epoch)?,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::LeaseLost);
    }
    t.commit().await
}

async fn read_head_in(t: &mut DomainTx) -> Result<HeadRow, StoreError> {
    let row = sqlx::query!(
        "SELECT pos, epoch, leaf_hash, recorded_at, frontier FROM access.domain_head WHERE domain_id = $1",
        t.domain.as_bytes().as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok(HeadRow {
        pos: unsigned(row.pos)?,
        epoch: unsigned(row.epoch)?,
        leaf_hash: hash(row.leaf_hash)?,
        recorded_at: unsigned(row.recorded_at)?,
        frontier: row
            .frontier
            .into_iter()
            .map(hash)
            .collect::<Result<_, _>>()?,
    })
}

/// Reads the stored head.
///
/// # Errors
/// [`StoreError`].
pub async fn read_head(pool: &PgPool, domain: &DomainId) -> Result<HeadRow, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let head = read_head_in(&mut t).await?;
    t.commit().await?;
    Ok(head)
}

/// Commits a batch atomically: head compare-and-set first, then records, nonces, outbox and
/// proofs (T7, OP-130 m.6). Nothing is visible unless all of it commits.
///
/// # Errors
/// [`StoreError::HeadMoved`] when the head is no longer at `after` under `epoch`; the caller
/// steps down and sends no ack.
pub async fn commit_batch(
    sequencer: &PgPool,
    domain: &DomainId,
    tenant: [u8; 16],
    batch: &CommitBatch,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let id = domain.as_bytes().as_slice();
    let frontier: Vec<Vec<u8>> = batch.head.frontier.iter().map(|h| h.to_vec()).collect();
    let moved = sqlx::query!(
        "UPDATE access.domain_head SET pos = $3, leaf_hash = $4, recorded_at = $5, frontier = $6
          WHERE domain_id = $1 AND pos = $2 AND epoch = $7",
        id,
        signed(batch.after)?,
        signed(batch.head.pos)?,
        batch.head.leaf_hash.as_slice(),
        signed(batch.head.recorded_at)?,
        &frontier,
        signed(batch.epoch)?,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    if moved != 1 {
        return Err(StoreError::HeadMoved);
    }
    validate(&mut t, batch).await?;
    let mut pos = Vec::with_capacity(batch.records.len());
    let mut kinds = Vec::with_capacity(batch.records.len());
    let mut times = Vec::with_capacity(batch.records.len());
    let mut leaves = Vec::with_capacity(batch.records.len());
    let mut envelopes = Vec::with_capacity(batch.records.len());
    for r in &batch.records {
        pos.push(signed(r.pos)?);
        kinds.push(r.kind.to_owned());
        times.push(signed(r.recorded_at)?);
        leaves.push(r.leaf_hash.to_vec());
        envelopes.push(r.envelope.clone());
    }
    sqlx::query!(
        "INSERT INTO access.authority_log (domain_id, pos, kind, recorded_at, leaf_hash, envelope)
         SELECT $1, * FROM UNNEST($2::bigint[], $3::text[], $4::bigint[], $5::bytea[], $6::bytea[])",
        id,
        &pos,
        &kinds,
        &times,
        &leaves,
        &envelopes,
    )
    .execute(&mut *t.tx)
    .await?;
    let tenant = sqlx::types::Uuid::from_bytes(tenant);
    side_rows(&mut t, tenant, batch).await?;
    sync_derived(&mut t, tenant, batch).await?;
    t.commit().await
}

/// Nonces, outbox events and proof bytes of a batch.
async fn side_rows(
    t: &mut DomainTx,
    tenant: sqlx::types::Uuid,
    batch: &CommitBatch,
) -> Result<(), StoreError> {
    let id = t.domain.as_bytes().to_vec();
    let id = id.as_slice();
    for n in &batch.nonces {
        sqlx::query!(
            "INSERT INTO access.authority_nonce (domain_id, tenant_id, nonce, actor, intent_digest, decision_pos)
             VALUES ($1, $2, $3, $4, $5, $6)",
            id,
            tenant,
            n.nonce.as_slice(),
            n.actor.as_slice(),
            n.intent_digest.as_slice(),
            signed(n.decision_pos)?,
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for o in &batch.outbox {
        sqlx::query!(
            "INSERT INTO access.authority_outbox (domain_id, tenant_id, pos, idx, event_id, event)
             VALUES ($1, $2, $3, $4, $5, $6)",
            id,
            tenant,
            signed(o.pos)?,
            i32::try_from(o.idx).map_err(|_| StoreError::Range)?,
            o.event_id.as_slice(),
            o.event.as_slice(),
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for p in &batch.proofs {
        sqlx::query!(
            "INSERT INTO access.proof_store (domain_id, digest, bytes) VALUES ($1, $2, $3)
             ON CONFLICT (domain_id, digest) DO NOTHING",
            id,
            p.digest.as_slice(),
            p.bytes.as_slice(),
        )
        .execute(&mut *t.tx)
        .await?;
    }
    Ok(())
}

/// SYNC-DERIVED state of a batch (T9): versions of the keys it writes, counter draws within
/// their limits and single-use flags.
async fn sync_derived(
    t: &mut DomainTx,
    tenant: sqlx::types::Uuid,
    batch: &CommitBatch,
) -> Result<(), StoreError> {
    let id = t.domain.as_bytes().to_vec();
    let id = id.as_slice();
    let tenant_id = tenant;
    for (key, at) in &batch.writes {
        sqlx::query!(
            "INSERT INTO access.authority_version (domain_id, tenant_id, key, version) VALUES ($1, $2, $3, $4)
             ON CONFLICT (domain_id, key) DO UPDATE SET version = EXCLUDED.version",
            id,
            tenant_id,
            key.as_slice(),
            signed(*at)?,
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for d in &batch.draws {
        if d.draw > d.limit {
            return Err(StoreError::Exhausted);
        }
        let used = sqlx::query_scalar!(
            "INSERT INTO access.authority_counter AS c (domain_id, tenant_id, key, used) VALUES ($1, $2, $3, $4)
             ON CONFLICT (domain_id, key) DO UPDATE SET used = c.used + EXCLUDED.used
              WHERE c.used + EXCLUDED.used <= $5
             RETURNING used",
            id,
            tenant_id,
            d.key.as_slice(),
            signed(d.draw)?,
            signed(d.limit)?,
        )
        .fetch_optional(&mut *t.tx)
        .await?;
        if used.is_none() {
            return Err(StoreError::Exhausted);
        }
    }
    for (key, at) in &batch.single_use {
        let set = sqlx::query!(
            "INSERT INTO access.authority_single_use (domain_id, tenant_id, key, pos) VALUES ($1, $2, $3, $4)
             ON CONFLICT (domain_id, key) DO NOTHING",
            id,
            tenant_id,
            key.as_slice(),
            signed(*at)?,
        )
        .execute(&mut *t.tx)
        .await?
        .rows_affected();
        if set != 1 {
            return Err(StoreError::Consumed);
        }
    }
    Ok(())
}

/// TI-4: every key read still has the version the evaluation saw. The head compare-and-set
/// already holds the head row, so no other commit runs in between.
async fn validate(t: &mut DomainTx, batch: &CommitBatch) -> Result<(), StoreError> {
    if batch.reads.is_empty() {
        return Ok(());
    }
    let keys: Vec<Vec<u8>> = batch.reads.iter().map(|(k, _)| k.clone()).collect();
    let rows = sqlx::query!(
        "SELECT key, version FROM access.authority_version WHERE domain_id = $1 AND key = ANY($2)",
        t.domain.as_bytes().as_slice(),
        &keys,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    for (key, seen) in &batch.reads {
        let now = rows
            .iter()
            .find(|r| &r.key == key)
            .map_or(Ok(0), |r| unsigned(r.version))?;
        if now != *seen {
            return Err(StoreError::Stale);
        }
    }
    Ok(())
}

/// Current versions of `keys`; an absent key has version 0 (the `StateView` read side).
///
/// # Errors
/// [`StoreError`].
pub async fn versions(
    pool: &PgPool,
    domain: &DomainId,
    keys: &[Vec<u8>],
) -> Result<Vec<u64>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT key, version FROM access.authority_version WHERE domain_id = $1 AND key = ANY($2)",
        domain.as_bytes().as_slice(),
        keys,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    keys.iter()
        .map(|k| {
            rows.iter()
                .find(|r| &r.key == k)
                .map_or(Ok(0), |r| unsigned(r.version))
        })
        .collect()
}

/// A counter's used amount; 0 when never drawn.
///
/// # Errors
/// [`StoreError`].
pub async fn counter(pool: &PgPool, domain: &DomainId, key: &[u8]) -> Result<u64, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let used = sqlx::query_scalar!(
        "SELECT used FROM access.authority_counter WHERE domain_id = $1 AND key = $2",
        domain.as_bytes().as_slice(),
        key,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    used.map_or(Ok(0), unsigned)
}

/// Reads records `from..=to`.
///
/// # Errors
/// [`StoreError`].
pub async fn read_log(
    pool: &PgPool,
    domain: &DomainId,
    from: u64,
    to: u64,
) -> Result<Vec<LogRecord>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT pos, kind, recorded_at, leaf_hash, envelope FROM access.authority_log
          WHERE domain_id = $1 AND pos BETWEEN $2 AND $3 ORDER BY pos",
        domain.as_bytes().as_slice(),
        signed(from)?,
        signed(to)?,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(LogRecord {
                pos: unsigned(r.pos)?,
                kind: kind(&r.kind)?,
                recorded_at: unsigned(r.recorded_at)?,
                leaf_hash: hash(r.leaf_hash)?,
                envelope: r.envelope,
            })
        })
        .collect()
}

/// Looks a nonce up (TI-8).
///
/// # Errors
/// [`StoreError`].
pub async fn find_nonce(
    pool: &PgPool,
    domain: &DomainId,
    nonce: &[u8],
) -> Result<Option<NonceRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT nonce, actor, intent_digest, decision_pos FROM access.authority_nonce
          WHERE domain_id = $1 AND nonce = $2",
        domain.as_bytes().as_slice(),
        nonce,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        Ok(NonceRow {
            nonce: r.nonce,
            actor: r.actor,
            intent_digest: hash(r.intent_digest)?,
            decision_pos: unsigned(r.decision_pos)?,
        })
    })
    .transpose()
}

/// Outbox events after `(pos, idx)`, in order, up to `limit`. The authority cursor is
/// `(domain_id, pos, idx)`: positions are gapless and in commit order (OP-20, T26).
///
/// # Errors
/// [`StoreError`].
pub async fn read_outbox(
    pool: &PgPool,
    domain: &DomainId,
    after: (u64, u32),
    limit: u32,
) -> Result<Vec<OutboxRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT pos, idx, event_id, event FROM access.authority_outbox
          WHERE domain_id = $1 AND (pos, idx) > ($2, $3) ORDER BY pos, idx LIMIT $4",
        domain.as_bytes().as_slice(),
        signed(after.0)?,
        i32::try_from(after.1).map_err(|_| StoreError::Range)?,
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(OutboxRow {
                pos: unsigned(r.pos)?,
                idx: u32::try_from(r.idx).map_err(|_| StoreError::Corrupt)?,
                event_id: hash(r.event_id)?,
                event: r.event,
            })
        })
        .collect()
}

/// The canonical server's clock in Unix milliseconds, one of the trusted time sources
/// (OP-129 m.1 (b)).
///
/// # Errors
/// [`StoreError`].
pub async fn server_time(pool: &PgPool) -> Result<u64, StoreError> {
    let ms = sqlx::query_scalar!(
        r#"SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint AS "ms!""#
    )
    .fetch_one(pool)
    .await?;
    unsigned(ms)
}
