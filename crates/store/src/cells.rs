//! Cell moves of a domain (§17.4.1, TI-2, EI-20, FA-2, FA-13, OP-158 m.3 (n)): the source cell
//! seals the head at position q under epoch e and refuses every later append; the target cell
//! takes the whole domain image, replays it, and accepts the head at (q, e + 1). There is no
//! compare-and-set between two clusters, so the seal and the acceptance are the only hand-over.
//! An unplanned continuation (region loss) is accepted only with a fence proof and the old
//! head covered. Every seal and acceptance is one row of `access.cell_moves`, kept (OP-73).

use sqlx::PgPool;

use crate::StoreError;
use crate::authority::{HeadRow, LogRecord, NonceRow, OutboxRow, ProofRow, StateRow};
use crate::scope::{DomainId, DomainTx};

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn hash(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn kind(k: &str) -> Result<&'static str, StoreError> {
    ["genesis", "opening", "decision", "claim"]
        .into_iter()
        .find(|known| *known == k)
        .ok_or(StoreError::Corrupt)
}

/// A domain head as a cell move reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellHead {
    /// The head.
    pub head: HeadRow,
    /// The position it is sealed at, once sealed.
    pub sealed_at: Option<u64>,
    /// The epoch this cell accepted the domain at, when it came by a move.
    pub accepted_epoch: Option<u64>,
}

/// The head with its seal and acceptance.
///
/// # Errors
/// [`StoreError`].
pub async fn cell_head(pool: &PgPool, domain: &DomainId) -> Result<Option<CellHead>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT pos, epoch, leaf_hash, recorded_at, frontier, sealed_at, accepted_epoch
           FROM access.domain_head WHERE domain_id = $1",
        domain.as_bytes().as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        Ok(CellHead {
            head: HeadRow {
                pos: unsigned(r.pos)?,
                epoch: unsigned(r.epoch)?,
                leaf_hash: hash(r.leaf_hash)?,
                recorded_at: unsigned(r.recorded_at)?,
                frontier: r.frontier.into_iter().map(hash).collect::<Result<_, _>>()?,
            },
            sealed_at: r.sealed_at.map(unsigned).transpose()?,
            accepted_epoch: r.accepted_epoch.map(unsigned).transpose()?,
        })
    })
    .transpose()
}

/// Seals the head under `epoch` (§17.4.1 item 1): a compare-and-set on the epoch, so only the
/// lease holder seals, and only once. From then on the head never moves.
///
/// # Errors
/// [`StoreError::HeadMoved`] when the epoch moved or the head is already sealed.
pub async fn seal(
    sequencer: &PgPool,
    domain: &DomainId,
    epoch: u64,
    root: [u8; 32],
) -> Result<HeadRow, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let id = domain.as_bytes().as_slice();
    let row = sqlx::query!(
        "UPDATE access.domain_head SET sealed_at = pos
          WHERE domain_id = $1 AND epoch = $2 AND sealed_at IS NULL AND frozen_at IS NULL
          RETURNING pos, epoch, leaf_hash, recorded_at, frontier",
        id,
        signed(epoch)?,
    )
    .fetch_optional(&mut *t.tx)
    .await?
    .ok_or(StoreError::HeadMoved)?;
    let head = HeadRow {
        pos: unsigned(row.pos)?,
        epoch: unsigned(row.epoch)?,
        leaf_hash: hash(row.leaf_hash)?,
        recorded_at: unsigned(row.recorded_at)?,
        frontier: row
            .frontier
            .into_iter()
            .map(hash)
            .collect::<Result<_, _>>()?,
    };
    sqlx::query!(
        "INSERT INTO access.cell_moves (domain_id, kind, epoch, pos, leaf_hash, root)
         VALUES ($1, 'seal', $2, $3, $4, $5)",
        id,
        row.epoch,
        row.pos,
        head.leaf_hash.as_slice(),
        root.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(head)
}

/// Everything the commit path of a domain reads: its authoritative rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The head with its seal.
    pub head: CellHead,
    /// The log from Genesis to the head.
    pub records: Vec<LogRecord>,
    /// The state, in key order.
    pub state: Vec<StateRow>,
    /// Read-set versions, as (key, version).
    pub versions: Vec<(Vec<u8>, u64)>,
    /// Consumption counters, as (key, used).
    pub counters: Vec<(Vec<u8>, u64)>,
    /// Single-use flags, as (key, position).
    pub single_use: Vec<(Vec<u8>, u64)>,
    /// Consumed nonces.
    pub nonces: Vec<NonceRow>,
    /// Outbox events.
    pub outbox: Vec<OutboxRow>,
    /// Cited proof bytes.
    pub proofs: Vec<ProofRow>,
}

/// Reads the whole image of `domain` in one snapshot (§17.4.1 item 1).
///
/// # Errors
/// [`StoreError`]; `Corrupt` when the domain has no head.
#[expect(
    clippy::too_many_lines,
    reason = "one read per authoritative table, in one snapshot"
)]
pub async fn image(sequencer: &PgPool, domain: &DomainId) -> Result<Image, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *t.tx)
        .await?;
    let id = domain.as_bytes().as_slice();
    let tenant = sqlx::query_scalar!(
        "SELECT tenant_id FROM access.authority_domain WHERE domain_id = $1",
        id
    )
    .fetch_optional(&mut *t.tx)
    .await?
    .ok_or(StoreError::Corrupt)?
    .into_bytes();
    let h = sqlx::query!(
        "SELECT pos, epoch, leaf_hash, recorded_at, frontier, sealed_at, accepted_epoch
           FROM access.domain_head WHERE domain_id = $1",
        id,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    let head = CellHead {
        head: HeadRow {
            pos: unsigned(h.pos)?,
            epoch: unsigned(h.epoch)?,
            leaf_hash: hash(h.leaf_hash)?,
            recorded_at: unsigned(h.recorded_at)?,
            frontier: h.frontier.into_iter().map(hash).collect::<Result<_, _>>()?,
        },
        sealed_at: h.sealed_at.map(unsigned).transpose()?,
        accepted_epoch: h.accepted_epoch.map(unsigned).transpose()?,
    };
    let records = sqlx::query!(
        "SELECT pos, kind, recorded_at, leaf_hash, envelope FROM access.authority_log
          WHERE domain_id = $1 AND pos <= $2 ORDER BY pos",
        id,
        h.pos,
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| {
        Ok(LogRecord {
            pos: unsigned(r.pos)?,
            kind: kind(&r.kind)?,
            recorded_at: unsigned(r.recorded_at)?,
            leaf_hash: hash(r.leaf_hash)?,
            envelope: r.envelope,
        })
    })
    .collect::<Result<Vec<_>, StoreError>>()?;
    let state = sqlx::query!(
        "SELECT key, value, version FROM access.authority_state WHERE domain_id = $1 ORDER BY key",
        id,
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| {
        Ok(StateRow {
            key: r.key,
            value: r.value,
            version: unsigned(r.version)?,
        })
    })
    .collect::<Result<Vec<_>, StoreError>>()?;
    let versions = sqlx::query!(
        "SELECT key, version FROM access.authority_version WHERE domain_id = $1 ORDER BY key",
        id,
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| Ok((r.key, unsigned(r.version)?)))
    .collect::<Result<Vec<_>, StoreError>>()?;
    let counters = sqlx::query!(
        "SELECT key, used FROM access.authority_counter WHERE domain_id = $1 ORDER BY key",
        id,
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| Ok((r.key, unsigned(r.used)?)))
    .collect::<Result<Vec<_>, StoreError>>()?;
    let single_use = sqlx::query!(
        "SELECT key, pos FROM access.authority_single_use WHERE domain_id = $1 ORDER BY key",
        id,
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| Ok((r.key, unsigned(r.pos)?)))
    .collect::<Result<Vec<_>, StoreError>>()?;
    let nonces = sqlx::query!(
        "SELECT nonce, actor, intent_digest, decision_pos, outcome, render_digest, tier
           FROM access.authority_nonce WHERE domain_id = $1 ORDER BY decision_pos, nonce",
        id,
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| {
        Ok(NonceRow {
            nonce: r.nonce,
            actor: r.actor,
            intent_digest: hash(r.intent_digest)?,
            decision_pos: unsigned(r.decision_pos)?,
            outcome: r.outcome,
            render_digest: r.render_digest.map(hash).transpose()?,
            tier: r
                .tier
                .map(|v| u8::try_from(v).map_err(|_| StoreError::Corrupt))
                .transpose()?,
        })
    })
    .collect::<Result<Vec<_>, StoreError>>()?;
    let outbox = sqlx::query!(
        "SELECT pos, idx, event_id, event, trace_parent FROM access.authority_outbox
          WHERE domain_id = $1 ORDER BY pos, idx",
        id,
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| {
        Ok(OutboxRow {
            pos: unsigned(r.pos)?,
            idx: u32::try_from(r.idx).map_err(|_| StoreError::Corrupt)?,
            event_id: hash(r.event_id)?,
            event: r.event,
            trace_parent: r.trace_parent,
        })
    })
    .collect::<Result<Vec<_>, StoreError>>()?;
    let proofs = sqlx::query!(
        "SELECT digest, bytes FROM access.proof_store WHERE domain_id = $1 ORDER BY digest",
        id,
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| {
        Ok(ProofRow {
            digest: hash(r.digest)?,
            bytes: r.bytes,
        })
    })
    .collect::<Result<Vec<_>, StoreError>>()?;
    t.commit().await?;
    Ok(Image {
        tenant,
        head,
        records,
        state,
        versions,
        counters,
        single_use,
        nonces,
        outbox,
        proofs,
    })
}

/// How the target came to accept the domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acceptance<'a> {
    /// From a sealed source.
    Planned,
    /// From a copy, under a fence proof named by its digest text.
    Unplanned(&'a str),
}

/// Writes `image` into this cell and accepts its head under `epoch` (§17.4.1): the whole domain
/// in one transaction, the head at the image's position with `accepted_epoch = epoch`. The
/// caller has replayed and checked the image.
///
/// # Errors
/// [`StoreError`]; the domain already present here fails on its primary key.
#[expect(
    clippy::too_many_lines,
    reason = "one write per authoritative table, in one transaction"
)]
pub async fn accept(
    sequencer: &PgPool,
    domain: &DomainId,
    image: &Image,
    epoch: u64,
    root: [u8; 32],
    how: Acceptance<'_>,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let id = domain.as_bytes().as_slice();
    let tenant = sqlx::types::Uuid::from_bytes(image.tenant);
    sqlx::query!(
        "INSERT INTO access.authority_domain (domain_id, tenant_id) VALUES ($1, $2)",
        id,
        tenant,
    )
    .execute(&mut *t.tx)
    .await?;
    let mut pos = Vec::with_capacity(image.records.len());
    let mut kinds = Vec::with_capacity(image.records.len());
    let mut times = Vec::with_capacity(image.records.len());
    let mut leaves = Vec::with_capacity(image.records.len());
    let mut envelopes = Vec::with_capacity(image.records.len());
    for r in &image.records {
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
    for s in &image.state {
        sqlx::query!(
            "INSERT INTO access.authority_state (domain_id, tenant_id, key, value, version) VALUES ($1, $2, $3, $4, $5)",
            id,
            tenant,
            s.key.as_slice(),
            s.value.as_deref(),
            signed(s.version)?,
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for (key, version) in &image.versions {
        sqlx::query!(
            "INSERT INTO access.authority_version (domain_id, tenant_id, key, version) VALUES ($1, $2, $3, $4)",
            id,
            tenant,
            key.as_slice(),
            signed(*version)?,
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for (key, used) in &image.counters {
        sqlx::query!(
            "INSERT INTO access.authority_counter (domain_id, tenant_id, key, used) VALUES ($1, $2, $3, $4)",
            id,
            tenant,
            key.as_slice(),
            signed(*used)?,
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for (key, at) in &image.single_use {
        sqlx::query!(
            "INSERT INTO access.authority_single_use (domain_id, tenant_id, key, pos) VALUES ($1, $2, $3, $4)",
            id,
            tenant,
            key.as_slice(),
            signed(*at)?,
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for n in &image.nonces {
        sqlx::query!(
            "INSERT INTO access.authority_nonce
               (domain_id, tenant_id, nonce, actor, intent_digest, decision_pos, outcome, render_digest, tier)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            id,
            tenant,
            n.nonce.as_slice(),
            n.actor.as_slice(),
            n.intent_digest.as_slice(),
            signed(n.decision_pos)?,
            n.outcome.as_str(),
            n.render_digest.as_ref().map(<[u8; 32]>::as_slice),
            n.tier.map(i16::from),
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for o in &image.outbox {
        sqlx::query!(
            "INSERT INTO access.authority_outbox (domain_id, tenant_id, pos, idx, event_id, event, trace_parent)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            id,
            tenant,
            signed(o.pos)?,
            i32::try_from(o.idx).map_err(|_| StoreError::Range)?,
            o.event_id.as_slice(),
            o.event.as_slice(),
            o.trace_parent.as_deref(),
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for p in &image.proofs {
        sqlx::query!(
            "INSERT INTO access.proof_store (domain_id, digest, bytes) VALUES ($1, $2, $3)",
            id,
            p.digest.as_slice(),
            p.bytes.as_slice(),
        )
        .execute(&mut *t.tx)
        .await?;
    }
    let head = &image.head.head;
    let frontier: Vec<Vec<u8>> = head.frontier.iter().map(|h| h.to_vec()).collect();
    sqlx::query!(
        "INSERT INTO access.domain_head (domain_id, pos, epoch, leaf_hash, recorded_at, frontier, accepted_epoch)
         VALUES ($1, $2, $3, $4, $5, $6, $3)",
        id,
        signed(head.pos)?,
        signed(epoch)?,
        head.leaf_hash.as_slice(),
        signed(head.recorded_at)?,
        &frontier,
    )
    .execute(&mut *t.tx)
    .await?;
    let (kind, fence) = match how {
        Acceptance::Planned => ("accept", ""),
        Acceptance::Unplanned(f) => ("accept_unplanned", f),
    };
    sqlx::query!(
        "INSERT INTO access.cell_moves (domain_id, kind, epoch, pos, leaf_hash, root, fence)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        id,
        kind,
        signed(epoch)?,
        signed(head.pos)?,
        head.leaf_hash.as_slice(),
        root.as_slice(),
        fence,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await
}

/// Continues a domain of a promoted copy in place under `epoch` once its fence proof and head
/// coverage are checked (§17.4.1 item 2, OP-29): the epoch moves past every earlier lease, so no
/// leader of the lost cell can write here, and the continuation is recorded.
///
/// # Errors
/// [`StoreError::HeadMoved`] when the head is not at `pos` with `leaf_hash` any more.
pub async fn continue_in_place(
    sequencer: &PgPool,
    domain: &DomainId,
    head: (u64, [u8; 32]),
    epoch: u64,
    root: [u8; 32],
    fence: &str,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let id = domain.as_bytes().as_slice();
    let moved = sqlx::query!(
        "UPDATE access.domain_head SET epoch = $4
          WHERE domain_id = $1 AND pos = $2 AND leaf_hash = $3 AND epoch < $4 AND sealed_at IS NULL",
        id,
        signed(head.0)?,
        head.1.as_slice(),
        signed(epoch)?,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    if moved != 1 {
        return Err(StoreError::HeadMoved);
    }
    sqlx::query!(
        "UPDATE access.sequencer_lease SET epoch = $2, released_at = now()
          WHERE domain_id = $1 AND epoch < $2",
        id,
        signed(epoch)?,
    )
    .execute(&mut *t.tx)
    .await?;
    sqlx::query!(
        "INSERT INTO access.cell_moves (domain_id, kind, epoch, pos, leaf_hash, root, fence)
         VALUES ($1, 'accept_unplanned', $2, $3, $4, $5, $6)",
        id,
        signed(epoch)?,
        signed(head.0)?,
        head.1.as_slice(),
        root.as_slice(),
        fence,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await
}

/// Why a process may not lead a domain of this cell now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// Sealed for a cell move at this position (§17.4.1 item 1).
    Sealed(u64),
    /// The cell was promoted from an async copy and the domain has not continued under a fence
    /// proof since (§17.4.1 item 2, FA-13).
    PromotedCopy,
}

/// The cell side of the leader gate: a sealed head or an unanswered async DR promote keeps the
/// domain from being led here.
///
/// # Errors
/// [`StoreError`].
pub async fn closed(sequencer: &PgPool, domain: &DomainId) -> Result<Option<Closed>, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let row = sqlx::query!(
        r#"SELECT h.sealed_at,
                  EXISTS (SELECT FROM access_ops.dr_promotions p
                           WHERE NOT EXISTS (SELECT FROM access.cell_moves m
                                              WHERE m.domain_id = h.domain_id AND m.kind = 'accept_unplanned'
                                                AND m.at > p.at)) AS "promoted!"
             FROM access.domain_head h WHERE h.domain_id = $1"#,
        domain.as_bytes().as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(match row {
        Some(r) => match r.sealed_at {
            Some(q) => Some(Closed::Sealed(unsigned(q)?)),
            None if r.promoted => Some(Closed::PromotedCopy),
            None => None,
        },
        None => None,
    })
}

/// Records an async DR promote of this cell (OP-29) and returns its generation.
///
/// # Errors
/// [`StoreError`].
pub async fn mark_dr_promoted(app: &PgPool, realms: u32) -> Result<u64, StoreError> {
    let g = sqlx::query_scalar!(
        r#"INSERT INTO access_ops.dr_promotions (generation, realms)
           SELECT coalesce(max(generation), 0) + 1, $1 FROM access_ops.dr_promotions
           RETURNING generation"#,
        i32::try_from(realms).map_err(|_| StoreError::Range)?,
    )
    .fetch_one(app)
    .await?;
    unsigned(g)
}

/// The latest declared DR profile of every realm that ever declared one: (tenant, realm, RPO
/// seconds; `None` when closed) (OP-29).
///
/// # Errors
/// [`StoreError`].
pub async fn dr_profiles(
    app: &PgPool,
) -> Result<Vec<([u8; 16], [u8; 16], Option<u64>)>, StoreError> {
    sqlx::query!(r#"SELECT tenant_id AS "tenant!", realm_id AS "realm!", rpo_s FROM access.dr_profiled_realms()"#)
        .fetch_all(app)
        .await?
        .into_iter()
        .map(|r| {
            Ok((
                r.tenant.into_bytes(),
                r.realm.into_bytes(),
                r.rpo_s.map(unsigned).transpose()?,
            ))
        })
        .collect()
}

/// Writes the next version of the realm's declared DR profile (`idp.realm.dr_profile`, or
/// `dr_profile_close` with `None`) (OP-29, HL-31).
///
/// # Errors
/// [`StoreError`].
pub async fn put_dr_profile(
    t: &mut crate::identity::TenantTx,
    bound: &crate::idp::Bound,
    rpo_s: Option<u64>,
) -> Result<(), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    sqlx::query!(
        "INSERT INTO access.realm_dr_profiles (tenant_id, realm_id, version, rpo_s, domain_id, decision_pos)
         SELECT $1, $2,
                COALESCE((SELECT max(version) FROM access.realm_dr_profiles
                           WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                $3, $4, $5",
        sqlx::types::Uuid::from_bytes(*t.tenant.as_bytes()),
        sqlx::types::Uuid::from_bytes(*realm.as_bytes()),
        rpo_s.map(signed).transpose()?,
        bound.domain().as_bytes().as_slice(),
        bound.raw_position(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The realm's declared DR profile's RPO in seconds; `None` while none is declared or it is
/// closed (OP-29).
///
/// # Errors
/// [`StoreError`].
pub async fn dr_profile(t: &mut crate::identity::TenantTx) -> Result<Option<u64>, StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    let rpo = sqlx::query_scalar!(
        "SELECT rpo_s FROM access.realm_dr_profiles
          WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
        sqlx::types::Uuid::from_bytes(*t.tenant.as_bytes()),
        sqlx::types::Uuid::from_bytes(*realm.as_bytes()),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    rpo.flatten().map(unsigned).transpose()
}
