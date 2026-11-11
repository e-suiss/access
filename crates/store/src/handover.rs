//! Cooperative handover and binding re-anchor steps (OP-158 m.3 (l), §16.6 HO-1…HO-9, §16.6.1
//! RB-1…RB-6, U11, PI-15). A freeze sets `domain_head.frozen_at`; the head trigger then lets the
//! head move once, for the handover batch, and records that step itself. The outgoing provider's
//! domain stays frozen for good (the database fence); a re-anchor thaws it after its batch. The
//! incoming provider adopts the domain from the export package and the batch. Nothing is
//! removed (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::authority::{HeadRow, LogRecord};
use crate::scope::{DomainId, DomainTx};

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// Which side of a handover a run is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The outgoing provider of a handover to another provider.
    Outgoing,
    /// A binding re-anchor inside one provider (OP-60).
    Reanchor,
    /// The incoming provider.
    Incoming,
}

impl Role {
    const fn word(self) -> &'static str {
        match self {
            Self::Outgoing => "outgoing",
            Self::Reanchor => "reanchor",
            Self::Incoming => "incoming",
        }
    }

    fn of(word: &str) -> Result<Self, StoreError> {
        match word {
            "outgoing" => Ok(Self::Outgoing),
            "reanchor" => Ok(Self::Reanchor),
            "incoming" => Ok(Self::Incoming),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// One recorded step of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// The run.
    pub run: [u8; 16],
    /// `frozen`, `committed`, `thawed` or `adopted`.
    pub step: String,
    /// The run's side.
    pub role: Role,
    /// The batch's first position.
    pub k: u64,
    /// The batch's last position, once known.
    pub h: Option<u64>,
    /// `C_k`'s root, when the step names it.
    pub cited_root: Option<[u8; 32]>,
}

/// Whether the database refused the write because the domain is frozen or sealed (the head
/// triggers' SQLSTATE 55000).
#[must_use]
pub fn refused_frozen(e: &StoreError) -> bool {
    matches!(e, StoreError::Db(sqlx::Error::Database(d)) if d.code().as_deref() == Some("55000"))
}

/// HO-1, HO-2, RB-1: freezes `domain` at `now` (Unix ms) for the run `run`; `k`, the position
/// the batch starts at. From here the head trigger refuses every commit but the batch, so a
/// commit in flight fails and `k` stays the head plus one. A domain that is frozen or sealed is
/// not frozen again.
///
/// # Errors
/// [`StoreError::HeadMoved`] when the domain is frozen or sealed.
pub async fn freeze(
    sequencer: &PgPool,
    domain: &DomainId,
    run: [u8; 16],
    role: Role,
    now: u64,
) -> Result<u64, StoreError> {
    if role == Role::Incoming {
        return Err(StoreError::Range);
    }
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let id = domain.as_bytes().as_slice();
    let pos = sqlx::query_scalar!(
        "UPDATE access.domain_head SET frozen_at = $2
          WHERE domain_id = $1 AND frozen_at IS NULL AND sealed_at IS NULL
         RETURNING pos",
        id,
        signed(now)?,
    )
    .fetch_optional(&mut *t.tx)
    .await?
    .ok_or(StoreError::HeadMoved)?;
    let k = unsigned(pos)?.checked_add(1).ok_or(StoreError::Range)?;
    sqlx::query!(
        "INSERT INTO access.handover_runs (domain_id, run, step, role, k) VALUES ($1, $2, 'frozen', $3, $4)",
        id,
        Uuid::from_bytes(run),
        role.word(),
        signed(k)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(k)
}

/// When `domain` was frozen, if it is (HO-1).
///
/// # Errors
/// [`StoreError::Db`].
pub async fn frozen_at(pool: &PgPool, domain: &DomainId) -> Result<Option<u64>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let at = sqlx::query_scalar!(
        "SELECT frozen_at FROM access.domain_head WHERE domain_id = $1",
        domain.as_bytes().as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?
    .flatten();
    t.commit().await?;
    at.map(unsigned).transpose()
}

/// Every recorded step of `domain`'s runs, oldest first.
///
/// # Errors
/// [`StoreError`].
pub async fn steps(pool: &PgPool, domain: &DomainId) -> Result<Vec<Step>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT run, step, role, k, h, cited_root FROM access.handover_runs
          WHERE domain_id = $1 ORDER BY at, k, step",
        domain.as_bytes().as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(Step {
                run: *r.run.as_bytes(),
                step: r.step,
                role: Role::of(&r.role)?,
                k: unsigned(r.k)?,
                h: r.h.map(unsigned).transpose()?,
                cited_root: r
                    .cited_root
                    .map(|b| <[u8; 32]>::try_from(b).map_err(|_| StoreError::Corrupt))
                    .transpose()?,
            })
        })
        .collect()
}

/// RB-6: a committed re-anchor's provider writes again from `h + 1`; or a run that wrote no
/// batch gives the domain back (no `h`). An outgoing handover that committed never thaws (U11).
///
/// # Errors
/// [`StoreError::HeadMoved`] when the run is not one that may thaw; [`StoreError`].
pub async fn thaw(sequencer: &PgPool, domain: &DomainId, run: [u8; 16]) -> Result<(), StoreError> {
    let all = steps(sequencer, domain).await?;
    let of = |s: &str| all.iter().find(|x| x.run == run && x.step == s);
    let frozen = of("frozen").ok_or(StoreError::HeadMoved)?;
    let h = match (of("committed"), frozen.role) {
        (None, _) => None,
        (Some(c), Role::Reanchor) => c.h,
        (Some(_), _) => return Err(StoreError::HeadMoved),
    };
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let id = domain.as_bytes().as_slice();
    sqlx::query!(
        "INSERT INTO access.handover_runs (domain_id, run, step, role, k, h) VALUES ($1, $2, 'thawed', $3, $4, $5)",
        id,
        Uuid::from_bytes(run),
        frozen.role.word(),
        signed(frozen.k)?,
        h.map(signed).transpose()?,
    )
    .execute(&mut *t.tx)
    .await?;
    let n = sqlx::query!(
        "UPDATE access.domain_head SET frozen_at = NULL WHERE domain_id = $1 AND frozen_at IS NOT NULL",
        id,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    if n != 1 {
        return Err(StoreError::HeadMoved);
    }
    t.commit().await
}

/// A nonce the adopted log consumed (TI-2): it stays used on the incoming provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdoptedNonce {
    /// The nonce.
    pub nonce: Vec<u8>,
    /// The actor reference its opening recorded.
    pub actor: Vec<u8>,
    /// The intent digest.
    pub intent_digest: [u8; 32],
    /// The decision's position.
    pub decision_pos: u64,
    /// `allow`, `deny` or `require_action`.
    pub outcome: String,
}

/// What the incoming provider writes when it takes the domain over (HO-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adoption {
    /// The run.
    pub run: [u8; 16],
    /// The batch's first position.
    pub k: u64,
    /// `C_k`'s root.
    pub cited_root: [u8; 32],
    /// Every record from Genesis to `h`, as committed.
    pub records: Vec<LogRecord>,
    /// The head at `h`.
    pub head: HeadRow,
    /// The folded state: key, canonical value (none once removed) and version.
    pub state: Vec<(Vec<u8>, Option<Vec<u8>>, u64)>,
    /// The consumed nonces.
    pub nonces: Vec<AdoptedNonce>,
    /// SYNC-DERIVED counters: key and the amount drawn.
    pub counters: Vec<(Vec<u8>, u64)>,
    /// Single-use flags: key and the position that set it.
    pub single_use: Vec<(Vec<u8>, u64)>,
}

/// HO-8: creates `domain` on this install from the outgoing provider's log as `tenant`'s, in one
/// transaction: the records as committed, the state the fold holds, the nonces, counters and
/// single-use flags the records consumed, and the head at `h`. The new leader starts at epoch 0.
///
/// # Errors
/// [`StoreError`]; an install that already holds the domain fails on its primary key.
pub async fn adopt(
    sequencer: &PgPool,
    domain: &DomainId,
    tenant: [u8; 16],
    a: &Adoption,
) -> Result<(), StoreError> {
    let first = a.records.first().ok_or(StoreError::Range)?;
    if first.pos != 0 || first.kind != "genesis" || a.head.pos.checked_add(1) != Some(len(a)?) {
        return Err(StoreError::Range);
    }
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let id = domain.as_bytes().as_slice();
    let tenant = Uuid::from_bytes(tenant);
    sqlx::query!(
        "INSERT INTO access.authority_domain (domain_id, tenant_id) VALUES ($1, $2)",
        id,
        tenant,
    )
    .execute(&mut *t.tx)
    .await?;
    let mut pos = Vec::with_capacity(a.records.len());
    let mut kinds = Vec::with_capacity(a.records.len());
    let mut times = Vec::with_capacity(a.records.len());
    let mut leaves = Vec::with_capacity(a.records.len());
    let mut envelopes = Vec::with_capacity(a.records.len());
    for (i, r) in a.records.iter().enumerate() {
        if u64::try_from(i).ok() != Some(r.pos) {
            return Err(StoreError::Range);
        }
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
    for (key, value, version) in &a.state {
        let version = signed(*version)?;
        sqlx::query!(
            "INSERT INTO access.authority_state (domain_id, tenant_id, key, value, version) VALUES ($1, $2, $3, $4, $5)",
            id,
            tenant,
            key.as_slice(),
            value.as_deref(),
            version,
        )
        .execute(&mut *t.tx)
        .await?;
        sqlx::query!(
            "INSERT INTO access.authority_version (domain_id, tenant_id, key, version) VALUES ($1, $2, $3, $4)",
            id,
            tenant,
            key.as_slice(),
            version,
        )
        .execute(&mut *t.tx)
        .await?;
    }
    consumed(&mut t, tenant, a).await?;
    let frontier: Vec<Vec<u8>> = a.head.frontier.iter().map(|h| h.to_vec()).collect();
    sqlx::query!(
        "INSERT INTO access.domain_head (domain_id, pos, epoch, leaf_hash, recorded_at, frontier)
         VALUES ($1, $2, 0, $3, $4, $5)",
        id,
        signed(a.head.pos)?,
        a.head.leaf_hash.as_slice(),
        signed(a.head.recorded_at)?,
        &frontier,
    )
    .execute(&mut *t.tx)
    .await?;
    sqlx::query!(
        "INSERT INTO access.handover_runs (domain_id, run, step, role, k, h, cited_root)
         VALUES ($1, $2, 'adopted', 'incoming', $3, $4, $5)",
        id,
        Uuid::from_bytes(a.run),
        signed(a.k)?,
        signed(a.head.pos)?,
        a.cited_root.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await
}

/// The nonces, counters and single-use flags an adopted log consumed (TI-2, T9).
async fn consumed(t: &mut DomainTx, tenant: Uuid, a: &Adoption) -> Result<(), StoreError> {
    let id = t.domain.as_bytes().to_vec();
    let id = id.as_slice();
    for n in &a.nonces {
        sqlx::query!(
            "INSERT INTO access.authority_nonce
               (domain_id, tenant_id, nonce, actor, intent_digest, decision_pos, outcome)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            id,
            tenant,
            n.nonce.as_slice(),
            n.actor.as_slice(),
            n.intent_digest.as_slice(),
            signed(n.decision_pos)?,
            n.outcome.as_str(),
        )
        .execute(&mut *t.tx)
        .await?;
    }
    for (key, used) in &a.counters {
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
    for (key, at) in &a.single_use {
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
    Ok(())
}

fn len(a: &Adoption) -> Result<u64, StoreError> {
    u64::try_from(a.records.len()).map_err(|_| StoreError::Range)
}
