//! Offline verification records (§9.12.1, §9.12.2, §7.9.4.1): recorded Offline Exercise
//! Reports with their chain, so the next report of a projection can be checked against the
//! last head (L2-RPT-2); recorded Verifier Profile bodies by digest and by verifier; the
//! `ValidityContract` of each allowed `projection.issue`; and what each report came to against its
//! projection. Everything here is appended once and never changes a budget (OP-73, PI-22).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn count(n: i64) -> Result<u32, StoreError> {
    u32::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn bytes<const N: usize>(v: &[u8]) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// One recorded report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportRow {
    /// Position of its `claim` record.
    pub pos: u64,
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// The projection's `ExerciseID`.
    pub exercise: [u8; 32],
    /// The head it continues; `None` for the first.
    pub previous: Option<[u8; 32]>,
    /// Its first sequence number.
    pub first_seq: u64,
    /// The next report's first sequence number.
    pub next_seq: u64,
    /// Its chain head.
    pub head: [u8; 32],
    /// Period start, milliseconds.
    pub period_from_ms: u64,
    /// Period end, milliseconds.
    pub period_until_ms: u64,
    /// The report body.
    pub body: Vec<u8>,
}

/// Records a report (sequencer role, after its Claim record committed).
///
/// # Errors
/// [`StoreError`].
pub async fn insert_report(
    sequencer: &PgPool,
    domain: &DomainId,
    r: &ReportRow,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.offline_report
           (domain_id, pos, claim_id, exercise_id, previous, first_seq, next_seq, head,
            period_from_ms, period_until_ms, body)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(r.pos)?,
        r.claim.as_slice(),
        r.exercise.as_slice(),
        r.previous.as_ref().map(<[u8; 32]>::as_slice),
        signed(r.first_seq)?,
        signed(r.next_seq)?,
        r.head.as_slice(),
        signed(r.period_from_ms)?,
        signed(r.period_until_ms)?,
        r.body,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}

struct RawReport {
    pos: i64,
    claim_id: Vec<u8>,
    exercise_id: Vec<u8>,
    previous: Option<Vec<u8>>,
    first_seq: i64,
    next_seq: i64,
    head: Vec<u8>,
    period_from_ms: i64,
    period_until_ms: i64,
    body: Vec<u8>,
}

fn report_row(r: RawReport) -> Result<ReportRow, StoreError> {
    Ok(ReportRow {
        pos: unsigned(r.pos)?,
        claim: bytes(&r.claim_id)?,
        exercise: bytes(&r.exercise_id)?,
        previous: r.previous.as_deref().map(bytes).transpose()?,
        first_seq: unsigned(r.first_seq)?,
        next_seq: unsigned(r.next_seq)?,
        head: bytes(&r.head)?,
        period_from_ms: unsigned(r.period_from_ms)?,
        period_until_ms: unsigned(r.period_until_ms)?,
        body: r.body,
    })
}

/// The report of the projection `exercise` with the highest first sequence number.
///
/// # Errors
/// [`StoreError`].
pub async fn last_report(
    pool: &PgPool,
    domain: &DomainId,
    exercise: &[u8; 32],
) -> Result<Option<ReportRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query_as!(
        RawReport,
        "SELECT pos, claim_id, exercise_id, previous, first_seq, next_seq, head, period_from_ms,
                period_until_ms, body
           FROM access.offline_report
          WHERE domain_id = $1 AND exercise_id = $2 ORDER BY first_seq DESC, pos DESC LIMIT 1",
        domain.as_bytes().as_slice(),
        exercise.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(report_row).transpose()
}

/// Every recorded report of the projection `exercise`, in record order.
///
/// # Errors
/// [`StoreError`].
pub async fn reports(
    pool: &PgPool,
    domain: &DomainId,
    exercise: &[u8; 32],
) -> Result<Vec<ReportRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query_as!(
        RawReport,
        "SELECT pos, claim_id, exercise_id, previous, first_seq, next_seq, head, period_from_ms,
                period_until_ms, body
           FROM access.offline_report
          WHERE domain_id = $1 AND exercise_id = $2 ORDER BY pos",
        domain.as_bytes().as_slice(),
        exercise.as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter().map(report_row).collect()
}

/// One recorded Verifier Profile body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRow {
    /// Position of its `claim` record.
    pub pos: u64,
    /// The body digest, the Claim's `value` and the contracts' `verifier_profile_ref`.
    pub digest: [u8; 32],
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// The body.
    pub body: Vec<u8>,
    /// The verifier it names, as the audience of a contract names it (§9.12.1).
    pub verifier: Option<String>,
    /// The Claim's validity end, milliseconds.
    pub valid_until_ms: Option<u64>,
}

/// Records a Verifier Profile body (sequencer role, after its Claim record committed).
///
/// # Errors
/// [`StoreError`].
pub async fn insert_profile(
    sequencer: &PgPool,
    domain: &DomainId,
    p: &ProfileRow,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.verifier_profile
           (domain_id, pos, profile_digest, claim_id, body, verifier, valid_until_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(p.pos)?,
        p.digest.as_slice(),
        p.claim.as_slice(),
        p.body,
        p.verifier.as_deref(),
        p.valid_until_ms.map(signed).transpose()?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}

/// The body of the profile whose digest a contract names (`verifier_profile_ref`).
///
/// # Errors
/// [`StoreError`].
pub async fn profile(
    pool: &PgPool,
    domain: &DomainId,
    digest: &[u8; 32],
) -> Result<Option<Vec<u8>>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let body = sqlx::query_scalar!(
        "SELECT body FROM access.verifier_profile
          WHERE domain_id = $1 AND profile_digest = $2 ORDER BY pos LIMIT 1",
        domain.as_bytes().as_slice(),
        digest.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(body)
}

/// The newest recorded profile of `verifier` still valid at `now`: its digest and body
/// (§9.12.1, PI-12).
///
/// # Errors
/// [`StoreError`].
pub async fn profile_for(
    pool: &PgPool,
    domain: &DomainId,
    verifier: &str,
    now: u64,
) -> Result<Option<([u8; 32], Vec<u8>)>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT profile_digest, body FROM access.verifier_profile
          WHERE domain_id = $1 AND verifier = $2 AND valid_until_ms >= $3
          ORDER BY pos DESC LIMIT 1",
        domain.as_bytes().as_slice(),
        verifier,
        signed(now)?,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| Ok((bytes(&r.profile_digest)?, r.body)))
        .transpose()
}

/// The `ValidityContract` of one allowed `projection.issue` (§9.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractRow {
    /// The projection's `ExerciseID`.
    pub exercise: [u8; 32],
    /// Position of its decision record.
    pub pos: u64,
    /// The holder Instance.
    pub holder: [u8; 16],
    /// The PEP that asked.
    pub pep: String,
    /// Profile class word.
    pub class: String,
    /// Profile variant word.
    pub variant: String,
    /// The PAP's `iat`, milliseconds.
    pub iat_ms: u64,
    /// The contract's horizon, milliseconds.
    pub horizon_ms: u64,
    /// The audience.
    pub audiences: Vec<String>,
    /// The action namespaces of the bounds.
    pub namespaces: Vec<String>,
    /// Whether the contract carries an offline slice.
    pub slice: bool,
    /// The contract digest under `access/validity/v1`.
    pub contract_digest: [u8; 32],
    /// The contract's canonical bytes.
    pub contract: Vec<u8>,
}

/// Records the contract of an allowed projection (sequencer role, after its decision record
/// committed).
///
/// # Errors
/// [`StoreError`].
pub async fn insert_contract(
    sequencer: &PgPool,
    domain: &DomainId,
    c: &ContractRow,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.projection_contract
           (domain_id, exercise_id, pos, holder_id, pep, class, variant, iat_ms, horizon_ms,
            audiences, namespaces, slice, contract_digest, contract)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        c.exercise.as_slice(),
        signed(c.pos)?,
        c.holder.as_slice(),
        c.pep,
        c.class,
        c.variant,
        signed(c.iat_ms)?,
        signed(c.horizon_ms)?,
        &c.audiences,
        &c.namespaces,
        c.slice,
        c.contract_digest.as_slice(),
        c.contract,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}

/// The contract of the projection `exercise`.
///
/// # Errors
/// [`StoreError`].
pub async fn contract_of(
    pool: &PgPool,
    domain: &DomainId,
    exercise: &[u8; 32],
) -> Result<Option<ContractRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT exercise_id, pos, holder_id, pep, class, variant, iat_ms, horizon_ms, audiences,
                namespaces, slice, contract_digest, contract
           FROM access.projection_contract WHERE domain_id = $1 AND exercise_id = $2",
        domain.as_bytes().as_slice(),
        exercise.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        Ok(ContractRow {
            exercise: bytes(&r.exercise_id)?,
            pos: unsigned(r.pos)?,
            holder: bytes(&r.holder_id)?,
            pep: r.pep,
            class: r.class,
            variant: r.variant,
            iat_ms: unsigned(r.iat_ms)?,
            horizon_ms: unsigned(r.horizon_ms)?,
            audiences: r.audiences,
            namespaces: r.namespaces,
            slice: r.slice,
            contract_digest: bytes(&r.contract_digest)?,
            contract: r.contract,
        })
    })
    .transpose()
}

/// How many offline-class projections of `holder` are open at `now`: their horizon has not
/// passed and their family is not revoked (§13.7.4 "açık offline PAP").
///
/// # Errors
/// [`StoreError`].
pub async fn open_offline(
    pool: &PgPool,
    domain: &DomainId,
    holder: &[u8; 16],
    now: u64,
) -> Result<u64, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let n = sqlx::query_scalar!(
        "SELECT count(*) AS \"n!\" FROM access.projection_contract c
          WHERE c.domain_id = $1 AND c.holder_id = $2 AND c.class = 'offline'
            AND c.horizon_ms > $3
            AND NOT EXISTS (SELECT 1 FROM access.projection_family f
                             WHERE f.domain_id = c.domain_id
                               AND f.family_id = substring(c.exercise_id from 1 for 16)
                               AND f.revoked_at IS NOT NULL)",
        domain.as_bytes().as_slice(),
        holder.as_slice(),
        signed(now)?,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    unsigned(n)
}

/// Most contracts one exposure read returns (§5.4).
pub const MAX_OPEN: i64 = 1_000;

/// One projection contract still open at a time: who holds it, its class and its horizon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenContract {
    /// The projection's `ExerciseID`.
    pub exercise: [u8; 32],
    /// The holder Instance.
    pub holder: [u8; 16],
    /// Profile class word.
    pub class: String,
    /// The contract's horizon, milliseconds.
    pub horizon_ms: u64,
    /// The PEP that asked for the projection.
    pub pep: String,
}

/// The projections whose horizon is after `at` and whose family is not revoked, in
/// `ExerciseID` order, at most [`MAX_OPEN`] (§5.4 revocation impact, staleness exposure).
///
/// # Errors
/// [`StoreError`].
pub async fn open_at(
    pool: &PgPool,
    domain: &DomainId,
    at: u64,
) -> Result<Vec<OpenContract>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT c.exercise_id, c.holder_id, c.class, c.horizon_ms, c.pep
           FROM access.projection_contract c
          WHERE c.domain_id = $1 AND c.horizon_ms > $2
            AND NOT EXISTS (SELECT 1 FROM access.projection_family f
                             WHERE f.domain_id = c.domain_id
                               AND f.family_id = substring(c.exercise_id from 1 for 16)
                               AND f.revoked_at IS NOT NULL)
          ORDER BY c.exercise_id LIMIT $3",
        domain.as_bytes().as_slice(),
        signed(at)?,
        MAX_OPEN,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(OpenContract {
                exercise: bytes(&r.exercise_id)?,
                holder: bytes(&r.holder_id)?,
                class: r.class,
                horizon_ms: unsigned(r.horizon_ms)?,
                pep: r.pep,
            })
        })
        .collect()
}

/// How many projections `holder` was issued since `since_ms` whose bounds touch one of
/// `namespaces` (§13.7.4 "`projection.issue` per Instance × action class").
///
/// # Errors
/// [`StoreError`].
pub async fn issued_since(
    pool: &PgPool,
    domain: &DomainId,
    holder: &[u8; 16],
    since_ms: u64,
    namespaces: &[String],
) -> Result<u64, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let n = sqlx::query_scalar!(
        "SELECT count(*) AS \"n!\" FROM access.projection_contract
          WHERE domain_id = $1 AND holder_id = $2 AND iat_ms >= $3 AND namespaces && $4",
        domain.as_bytes().as_slice(),
        holder.as_slice(),
        signed(since_ms)?,
        namespaces,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    unsigned(n)
}

/// Whether `audience` holds a `checkpointed-offline` projection whose report deadline,
/// `horizon + grace`, passed before `now` without any report of it (§13.7.2, SEC14): such a
/// verifier gets no new contract.
///
/// # Errors
/// [`StoreError`].
pub async fn unreported_overdue(
    pool: &PgPool,
    domain: &DomainId,
    audience: &str,
    now: u64,
    grace_ms: u64,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let found = sqlx::query_scalar!(
        "SELECT 1 AS \"one!\" FROM access.projection_contract c
          WHERE c.domain_id = $1 AND $2 = ANY(c.audiences) AND c.variant = 'checkpointed-offline'
            AND c.horizon_ms + $4 < $3
            AND NOT EXISTS (SELECT 1 FROM access.offline_report r
                             WHERE r.domain_id = c.domain_id AND r.exercise_id = c.exercise_id)
          LIMIT 1",
        domain.as_bytes().as_slice(),
        audience,
        signed(now)?,
        signed(grace_ms)?,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(found.is_some())
}

/// What one report came to against its projection (§7.9.4.1, §9.12.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationRow {
    /// Position of the report's `claim` record.
    pub pos: u64,
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// The projection's `ExerciseID`.
    pub exercise: [u8; 32],
    /// The report names the contract this domain issued for the projection.
    pub bound: bool,
    /// The report continues the last recorded head (L2-RPT-2).
    pub continuous: bool,
    /// The report arrived after `horizon + 24 h` (SEC14).
    pub late: bool,
    /// Entries inside the contract.
    pub in_contract: u32,
    /// Entries outside the contract: after the horizon, before issuance, or drawing beyond the
    /// slice.
    pub out_of_contract: u32,
    /// The unused slice the report declares, dCBOR; it changes nothing until a grounded release
    /// cites it.
    pub slice_unused: Vec<u8>,
}

/// Records a reconciliation (sequencer role, after the report's Claim record committed).
///
/// # Errors
/// [`StoreError`].
pub async fn insert_reconciliation(
    sequencer: &PgPool,
    domain: &DomainId,
    r: &ReconciliationRow,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.offline_reconciliation
           (domain_id, pos, claim_id, exercise_id, bound, continuous, late, in_contract,
            out_of_contract, slice_unused)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(r.pos)?,
        r.claim.as_slice(),
        r.exercise.as_slice(),
        r.bound,
        r.continuous,
        r.late,
        i32::try_from(r.in_contract).map_err(|_| StoreError::Range)?,
        i32::try_from(r.out_of_contract).map_err(|_| StoreError::Range)?,
        r.slice_unused,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}

/// The reconciliations of the projection `exercise`, in record order.
///
/// # Errors
/// [`StoreError`].
pub async fn reconciliations(
    pool: &PgPool,
    domain: &DomainId,
    exercise: &[u8; 32],
) -> Result<Vec<ReconciliationRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT pos, claim_id, exercise_id, bound, continuous, late, in_contract, out_of_contract,
                slice_unused
           FROM access.offline_reconciliation
          WHERE domain_id = $1 AND exercise_id = $2 ORDER BY pos",
        domain.as_bytes().as_slice(),
        exercise.as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(ReconciliationRow {
                pos: unsigned(r.pos)?,
                claim: bytes(&r.claim_id)?,
                exercise: bytes(&r.exercise_id)?,
                bound: r.bound,
                continuous: r.continuous,
                late: r.late,
                in_contract: count(i64::from(r.in_contract))?,
                out_of_contract: count(i64::from(r.out_of_contract))?,
                slice_unused: r.slice_unused,
            })
        })
        .collect()
}
