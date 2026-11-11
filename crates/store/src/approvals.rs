//! Pushed authority requests on the realm's Approval Surface (OP-150 L6, OP-149 m.9, §9.14.1):
//! a coordinator's typed request with the approver's pre-signed contribution, bound to the
//! session that opens it, the statement it signs and the Exercise it becomes. Nothing is
//! deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
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

/// A request to push.
#[derive(Clone, Debug)]
pub struct NewApproval<'a> {
    /// Digest the coordinator names it by.
    pub digest: [u8; 32],
    /// The `request_uri` the surface names it by.
    pub request_uri: &'a str,
    /// The authority request as pushed.
    pub request: &'a [u8],
    /// The pre-signed contribution envelope as pushed.
    pub contribution: &'a [u8],
    /// When it stops being shown, Unix milliseconds.
    pub expires_ms: u64,
}

/// A pushed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRow {
    /// Internal id: the flow handle.
    pub id: [u8; 16],
    /// Digest the coordinator names it by.
    pub digest: [u8; 32],
    /// Its `request_uri`.
    pub request_uri: String,
    /// The authority request as pushed.
    pub request: Vec<u8>,
    /// The contribution envelope as pushed.
    pub contribution: Vec<u8>,
    /// Expiry, Unix milliseconds.
    pub expires_ms: u64,
    /// The session that opened it.
    pub session: Option<[u8; 16]>,
    /// H(AAS) of the statement built for it.
    pub statement: Option<[u8; 32]>,
    /// The statement, dCBOR.
    pub aas: Option<Vec<u8>>,
    /// When the ceremony started.
    pub started_ms: Option<u64>,
    /// When the approval was committed.
    pub finished_ms: Option<u64>,
    /// The contribution Exercise.
    pub exercise: Option<[u8; 32]>,
}

struct Raw {
    request_id: Uuid,
    digest: Vec<u8>,
    request_uri: String,
    request: Vec<u8>,
    contribution: Vec<u8>,
    expires_ms: i64,
    session_id: Option<Uuid>,
    statement: Option<Vec<u8>>,
    aas: Option<Vec<u8>>,
    started_ms: Option<i64>,
    finished_ms: Option<i64>,
    exercise: Option<Vec<u8>>,
}

fn row(r: Raw) -> Result<ApprovalRow, StoreError> {
    Ok(ApprovalRow {
        id: *r.request_id.as_bytes(),
        digest: hash(r.digest)?,
        request_uri: r.request_uri,
        request: r.request,
        contribution: r.contribution,
        expires_ms: unsigned(r.expires_ms)?,
        session: r.session_id.map(|u| *u.as_bytes()),
        statement: r.statement.map(hash).transpose()?,
        aas: r.aas,
        started_ms: r.started_ms.map(unsigned).transpose()?,
        finished_ms: r.finished_ms.map(unsigned).transpose()?,
        exercise: r.exercise.map(hash).transpose()?,
    })
}

/// Stores a pushed request; returns its id.
///
/// # Errors
/// [`StoreError`].
pub async fn push_approval(t: &mut TenantTx, a: &NewApproval<'_>) -> Result<[u8; 16], StoreError> {
    let (tenant, realm) = scope(t)?;
    let id = sqlx::query_scalar!(
        "INSERT INTO access.approval_requests
           (tenant_id, realm_id, digest, request_uri, request, contribution, expires_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING request_id",
        tenant,
        realm,
        a.digest.as_slice(),
        a.request_uri,
        a.request,
        a.contribution,
        signed(a.expires_ms)?,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok(*id.as_bytes())
}

/// The pushed request with this `request_uri`.
///
/// # Errors
/// [`StoreError`].
pub async fn approval_by_uri(
    t: &mut TenantTx,
    request_uri: &str,
) -> Result<Option<ApprovalRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let r = sqlx::query_as!(
        Raw,
        "SELECT request_id, digest, request_uri, request, contribution, expires_ms, session_id,
                statement, aas, started_ms, finished_ms, exercise
           FROM access.approval_requests
          WHERE tenant_id = $1 AND realm_id = $2 AND request_uri = $3
          ORDER BY created_at DESC LIMIT 1",
        tenant,
        realm,
        request_uri,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    r.map(row).transpose()
}

/// The latest pushed request with this digest.
///
/// # Errors
/// [`StoreError`].
pub async fn approval_by_digest(
    t: &mut TenantTx,
    digest: &[u8; 32],
) -> Result<Option<ApprovalRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let r = sqlx::query_as!(
        Raw,
        "SELECT request_id, digest, request_uri, request, contribution, expires_ms, session_id,
                statement, aas, started_ms, finished_ms, exercise
           FROM access.approval_requests
          WHERE tenant_id = $1 AND realm_id = $2 AND digest = $3
          ORDER BY created_at DESC LIMIT 1",
        tenant,
        realm,
        digest.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    r.map(row).transpose()
}

/// The pushed request by id.
///
/// # Errors
/// [`StoreError`].
pub async fn approval(t: &mut TenantTx, id: &[u8; 16]) -> Result<Option<ApprovalRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let r = sqlx::query_as!(
        Raw,
        "SELECT request_id, digest, request_uri, request, contribution, expires_ms, session_id,
                statement, aas, started_ms, finished_ms, exercise
           FROM access.approval_requests
          WHERE tenant_id = $1 AND realm_id = $2 AND request_id = $3
          ORDER BY created_at DESC LIMIT 1",
        tenant,
        realm,
        Uuid::from_bytes(*id),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    r.map(row).transpose()
}

/// Binds a pushed request to the session that opened it and the statement built for it; `false`
/// when it was started already.
///
/// # Errors
/// [`StoreError`].
pub async fn start_approval(
    t: &mut TenantTx,
    id: &[u8; 16],
    session: &[u8; 16],
    statement: &[u8; 32],
    aas: &[u8],
    now_ms: u64,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.approval_requests
            SET session_id = $4, statement = $5, aas = $6, started_ms = $7
          WHERE tenant_id = $1 AND realm_id = $2 AND request_id = $3 AND started_ms IS NULL",
        tenant,
        realm,
        Uuid::from_bytes(*id),
        Uuid::from_bytes(*session),
        statement.as_slice(),
        aas,
        signed(now_ms)?,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Records the Exercise a started approval became; `false` when it was finished already or
/// never started.
///
/// # Errors
/// [`StoreError`].
pub async fn finish_approval(
    t: &mut TenantTx,
    id: &[u8; 16],
    exercise: &[u8; 32],
    now_ms: u64,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.approval_requests SET finished_ms = $4, exercise = $5
          WHERE tenant_id = $1 AND realm_id = $2 AND request_id = $3
            AND started_ms IS NOT NULL AND finished_ms IS NULL",
        tenant,
        realm,
        Uuid::from_bytes(*id),
        signed(now_ms)?,
        exercise.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The latest answer to whether the realm opened an approval channel (OP-157 m.3 (m)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalChannel {
    /// CT1 approval inside the approver notification (`idp.realm.approval_inline`).
    Inline,
    /// CT1 batch approval (`idp.realm.approval_batch`).
    Batch,
}

impl ApprovalChannel {
    const fn name(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Batch => "batch",
        }
    }
}

/// Whether the realm opened the channel; off by default.
///
/// # Errors
/// [`StoreError`].
pub async fn approval_channel_enabled(
    t: &mut TenantTx,
    channel: ApprovalChannel,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    Ok(sqlx::query_scalar!(
        "SELECT enabled FROM access.idp_approval_channels
          WHERE tenant_id = $1 AND realm_id = $2 AND channel = $3
          ORDER BY version DESC LIMIT 1",
        tenant,
        realm,
        channel.name(),
    )
    .fetch_optional(&mut *t.tx)
    .await?
    .unwrap_or(false))
}

/// Writes the channel's next setting under `bound` (`idp.realm.approval_inline`,
/// `approval_batch`, and their `_close` pair).
///
/// # Errors
/// [`StoreError`].
pub async fn put_approval_channel(
    t: &mut TenantTx,
    bound: &crate::idp::Bound,
    channel: ApprovalChannel,
    enabled: bool,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_approval_channels
           (tenant_id, realm_id, channel, version, enabled, domain_id, decision_pos)
         SELECT $1, $2, $3,
                COALESCE((SELECT max(version) FROM access.idp_approval_channels
                           WHERE tenant_id = $1 AND realm_id = $2 AND channel = $3), 0) + 1,
                $4, $5, $6",
        tenant,
        realm,
        channel.name(),
        enabled,
        bound.domain().as_bytes().as_slice(),
        bound.raw_position(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// One invitation for a pushed request (OP-157 m.3 (m)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteRow {
    /// Id.
    pub id: [u8; 16],
    /// The pushed request it invites to.
    pub request: [u8; 16],
    /// The requester's Party.
    pub requester: [u8; 16],
    /// The invited approver's subject.
    pub approver: [u8; 16],
    /// The intent digest.
    pub intent: [u8; 32],
    /// The tier the decision point held the intent to.
    pub tier: u8,
    /// When it was made, Unix ms.
    pub created_ms: u64,
    /// When it was answered.
    pub answered_ms: Option<u64>,
    /// `approved` or `denied`.
    pub outcome: Option<String>,
}

/// A new invitation.
#[derive(Clone, Copy, Debug)]
pub struct NewInvite {
    /// The pushed request.
    pub request: [u8; 16],
    /// The requester's Party.
    pub requester: [u8; 16],
    /// The approver's subject.
    pub approver: [u8; 16],
    /// The intent digest.
    pub intent: [u8; 32],
    /// The tier.
    pub tier: u8,
    /// Now, Unix ms.
    pub now_ms: u64,
}

/// `requester`'s invitations to `approver` since `since_ms`, and the oldest one's time.
///
/// # Errors
/// [`StoreError`].
pub async fn invites_since(
    t: &mut TenantTx,
    requester: &[u8; 16],
    approver: &[u8; 16],
    since_ms: u64,
) -> Result<(u32, Option<u64>), StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        r#"SELECT count(*) AS "count!", min(created_ms) AS oldest
             FROM access.approval_invites
            WHERE tenant_id = $1 AND realm_id = $2 AND requester = $3 AND approver = $4
              AND created_ms >= $5"#,
        tenant,
        realm,
        requester.as_slice(),
        Uuid::from_bytes(*approver),
        signed(since_ms)?,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok((
        u32::try_from(row.count).unwrap_or(u32::MAX),
        row.oldest.map(unsigned).transpose()?,
    ))
}

/// Records the invitation; `false` when this approver was already invited for this intent.
///
/// # Errors
/// [`StoreError`].
pub async fn insert_invite(t: &mut TenantTx, i: &NewInvite) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "INSERT INTO access.approval_invites
           (tenant_id, realm_id, request_id, requester, approver, intent, tier, created_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (tenant_id, realm_id, approver, intent) DO NOTHING",
        tenant,
        realm,
        Uuid::from_bytes(i.request),
        i.requester.as_slice(),
        Uuid::from_bytes(i.approver),
        i.intent.as_slice(),
        i16::from(i.tier),
        signed(i.now_ms)?,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The approver's invitation for the intent, locked for its answer.
///
/// # Errors
/// [`StoreError`].
pub async fn invite(
    t: &mut TenantTx,
    approver: &[u8; 16],
    intent: &[u8; 32],
) -> Result<Option<InviteRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT invite_id, request_id, requester, approver, intent, tier, created_ms,
                answered_ms, outcome
           FROM access.approval_invites
          WHERE tenant_id = $1 AND realm_id = $2 AND approver = $3 AND intent = $4
          FOR UPDATE",
        tenant,
        realm,
        Uuid::from_bytes(*approver),
        intent.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(InviteRow {
            id: *r.invite_id.as_bytes(),
            request: *r.request_id.as_bytes(),
            requester: <[u8; 16]>::try_from(r.requester.as_slice())
                .map_err(|_| StoreError::Corrupt)?,
            approver: *r.approver.as_bytes(),
            intent: hash(r.intent)?,
            tier: u8::try_from(r.tier).map_err(|_| StoreError::Corrupt)?,
            created_ms: unsigned(r.created_ms)?,
            answered_ms: r.answered_ms.map(unsigned).transpose()?,
            outcome: r.outcome,
        })
    })
    .transpose()
}

/// Records the answer; `false` when the invitation was answered already.
///
/// # Errors
/// [`StoreError`].
pub async fn answer_invite(
    t: &mut TenantTx,
    id: &[u8; 16],
    outcome: &str,
    now_ms: u64,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.approval_invites SET answered_ms = $4, outcome = $5
          WHERE tenant_id = $1 AND realm_id = $2 AND invite_id = $3 AND answered_ms IS NULL",
        tenant,
        realm,
        Uuid::from_bytes(*id),
        signed(now_ms)?,
        outcome,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}
