//! The console BFF's sessions (TN-128, TN-129, OP-151 m.3 (e), (f), m.12 (b)) in
//! `access_ops.console_sessions`: found by the digest of the cookie, never by the cookie; bound
//! to the realm subject and login session the sign-in came back with; ended softly (OP-73). The
//! device Instance the browser registers is attached once (INV-13), and at most one registration
//! challenge is pending. Times are Unix milliseconds of the caller's clock.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{RealmId, TenantId};

/// A session to open.
#[derive(Clone, PartialEq, Eq)]
pub struct NewConsoleSession<'a> {
    /// SHA-256 of the cookie value.
    pub cookie_digest: &'a [u8; 32],
    /// The realm's tenant.
    pub tenant: TenantId,
    /// The realm.
    pub realm: RealmId,
    /// The signed-in subject.
    pub subject: [u8; 16],
    /// The realm login session the sign-in came back with.
    pub login_session: [u8; 16],
    /// The realm's slug.
    pub slug: &'a str,
    /// The realm's governing domain.
    pub domain: &'a [u8; 32],
    /// The account's opaque external id.
    pub account: &'a str,
    /// The encoded network binding.
    pub binding: &'a [u8],
    /// When the user authenticated.
    pub auth_time_ms: u64,
    /// Now.
    pub now_ms: u64,
}

/// A registration challenge pending on a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The challenge.
    pub challenge: [u8; 32],
    /// The device key's `COSE_Key`.
    pub key: Vec<u8>,
    /// The Party the registration names.
    pub party: [u8; 16],
    /// The intents' validity start.
    pub from_ms: u64,
    /// The intents' validity end; the challenge lapses with it.
    pub until_ms: u64,
}

/// A console session as stored.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsoleSessionRow {
    /// Its id.
    pub id: [u8; 16],
    /// The realm's tenant.
    pub tenant: TenantId,
    /// The realm.
    pub realm: RealmId,
    /// The subject.
    pub subject: [u8; 16],
    /// The realm login session.
    pub login_session: [u8; 16],
    /// The slug.
    pub slug: String,
    /// The governing domain.
    pub domain: [u8; 32],
    /// The account's external id.
    pub account: String,
    /// The encoded network binding.
    pub binding: Vec<u8>,
    /// When the user authenticated.
    pub auth_time_ms: u64,
    /// Opened.
    pub created_ms: u64,
    /// Last use.
    pub last_seen_ms: u64,
    /// Ended, if it has.
    pub ended_ms: Option<u64>,
    /// The device Instance's key thumbprint and `COSE_Key`, once registered.
    pub instance: Option<([u8; 32], Vec<u8>)>,
    /// The pending registration challenge.
    pub pending: Option<Pending>,
    /// The DBSC key slot (TN-33).
    pub dbsc: Option<[u8; 32]>,
}

/// Why a session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// The user signed out.
    SignedOut,
    /// The user ended it from another session.
    Revoked,
    /// The console policy ended it (TN-129).
    Policy,
}

impl EndReason {
    const fn text(self) -> &'static str {
        match self {
            Self::SignedOut => "signed_out",
            Self::Revoked => "revoked",
            Self::Policy => "policy",
        }
    }
}

fn ms(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn fixed<const N: usize>(v: Vec<u8>) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

struct Record {
    session_id: Uuid,
    tenant_id: Uuid,
    realm_id: Uuid,
    subject_id: Uuid,
    login_session_id: Uuid,
    slug: String,
    domain_id: Vec<u8>,
    account: String,
    binding: Vec<u8>,
    auth_time_ms: i64,
    created_ms: i64,
    last_seen_ms: i64,
    ended_ms: Option<i64>,
    instance_kid: Option<Vec<u8>>,
    instance_key: Option<Vec<u8>>,
    pending_challenge: Option<Vec<u8>>,
    pending_key: Option<Vec<u8>>,
    pending_party: Option<Vec<u8>>,
    pending_from_ms: Option<i64>,
    pending_until_ms: Option<i64>,
    dbsc_key: Option<Vec<u8>>,
}

impl Record {
    fn into_row(self) -> Result<ConsoleSessionRow, StoreError> {
        let instance = match (self.instance_kid, self.instance_key) {
            (Some(kid), Some(key)) => Some((fixed(kid)?, key)),
            (None, None) => None,
            _ => return Err(StoreError::Corrupt),
        };
        let pending = match (
            self.pending_challenge,
            self.pending_key,
            self.pending_party,
            self.pending_from_ms,
            self.pending_until_ms,
        ) {
            (Some(c), Some(key), Some(p), Some(from), Some(until)) => Some(Pending {
                challenge: fixed(c)?,
                key,
                party: fixed(p)?,
                from_ms: unsigned(from)?,
                until_ms: unsigned(until)?,
            }),
            (None, None, None, None, None) => None,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(ConsoleSessionRow {
            id: *self.session_id.as_bytes(),
            tenant: TenantId::from_bytes(*self.tenant_id.as_bytes()),
            realm: RealmId::from_bytes(*self.realm_id.as_bytes()),
            subject: *self.subject_id.as_bytes(),
            login_session: *self.login_session_id.as_bytes(),
            slug: self.slug,
            domain: fixed(self.domain_id)?,
            account: self.account,
            binding: self.binding,
            auth_time_ms: unsigned(self.auth_time_ms)?,
            created_ms: unsigned(self.created_ms)?,
            last_seen_ms: unsigned(self.last_seen_ms)?,
            ended_ms: self.ended_ms.map(unsigned).transpose()?,
            instance,
            pending,
            dbsc: self.dbsc_key.map(fixed).transpose()?,
        })
    }
}

/// Opens a session; its id.
///
/// # Errors
/// [`StoreError`]; a cookie digest used before fails.
pub async fn open(app: &PgPool, s: &NewConsoleSession<'_>) -> Result<[u8; 16], StoreError> {
    let now = ms(s.now_ms)?;
    let id = sqlx::query_scalar!(
        r#"INSERT INTO access_ops.console_sessions
             (cookie_digest, tenant_id, realm_id, subject_id, login_session_id, slug, domain_id,
              account, binding, auth_time_ms, created_ms, last_seen_ms)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
           RETURNING session_id"#,
        s.cookie_digest.as_slice(),
        Uuid::from_bytes(*s.tenant.as_bytes()),
        Uuid::from_bytes(*s.realm.as_bytes()),
        Uuid::from_bytes(s.subject),
        Uuid::from_bytes(s.login_session),
        s.slug,
        s.domain.as_slice(),
        s.account,
        s.binding,
        ms(s.auth_time_ms)?,
        now,
    )
    .fetch_one(app)
    .await?;
    Ok(*id.as_bytes())
}

/// The session whose cookie has `cookie_digest`, ended or not.
///
/// # Errors
/// [`StoreError`].
pub async fn by_cookie(
    app: &PgPool,
    cookie_digest: &[u8; 32],
) -> Result<Option<ConsoleSessionRow>, StoreError> {
    let r = sqlx::query_as!(
        Record,
        "SELECT session_id, tenant_id, realm_id, subject_id, login_session_id, slug, domain_id,
                account, binding, auth_time_ms, created_ms, last_seen_ms, ended_ms, instance_kid,
                instance_key, pending_challenge, pending_key, pending_party, pending_from_ms,
                pending_until_ms, dbsc_key
           FROM access_ops.console_sessions WHERE cookie_digest = $1",
        cookie_digest.as_slice(),
    )
    .fetch_optional(app)
    .await?;
    r.map(Record::into_row).transpose()
}

/// The session `id`, ended or not.
///
/// # Errors
/// [`StoreError`].
pub async fn by_id(app: &PgPool, id: &[u8; 16]) -> Result<Option<ConsoleSessionRow>, StoreError> {
    let r = sqlx::query_as!(
        Record,
        "SELECT session_id, tenant_id, realm_id, subject_id, login_session_id, slug, domain_id,
                account, binding, auth_time_ms, created_ms, last_seen_ms, ended_ms, instance_kid,
                instance_key, pending_challenge, pending_key, pending_party, pending_from_ms,
                pending_until_ms, dbsc_key
           FROM access_ops.console_sessions WHERE session_id = $1",
        Uuid::from_bytes(*id),
    )
    .fetch_optional(app)
    .await?;
    r.map(Record::into_row).transpose()
}

/// The live sessions of `subject` in `realm`, oldest first, at most `limit`.
///
/// # Errors
/// [`StoreError`].
pub async fn live_of(
    app: &PgPool,
    tenant: TenantId,
    realm: RealmId,
    subject: &[u8; 16],
    limit: u32,
) -> Result<Vec<ConsoleSessionRow>, StoreError> {
    let rows = sqlx::query_as!(
        Record,
        "SELECT session_id, tenant_id, realm_id, subject_id, login_session_id, slug, domain_id,
                account, binding, auth_time_ms, created_ms, last_seen_ms, ended_ms, instance_kid,
                instance_key, pending_challenge, pending_key, pending_party, pending_from_ms,
                pending_until_ms, dbsc_key
           FROM access_ops.console_sessions
          WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND ended_ms IS NULL
          ORDER BY session_id LIMIT $4",
        Uuid::from_bytes(*tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        Uuid::from_bytes(*subject),
        i64::from(limit),
    )
    .fetch_all(app)
    .await?;
    rows.into_iter().map(Record::into_row).collect()
}

/// Records a use of a live session; `false` when it has ended.
///
/// # Errors
/// [`StoreError`].
pub async fn touch(app: &PgPool, id: &[u8; 16], now_ms: u64) -> Result<bool, StoreError> {
    let n = sqlx::query!(
        "UPDATE access_ops.console_sessions SET last_seen_ms = GREATEST(last_seen_ms, $2)
          WHERE session_id = $1 AND ended_ms IS NULL",
        Uuid::from_bytes(*id),
        ms(now_ms)?,
    )
    .execute(app)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Ends a session; `false` when it already had.
///
/// # Errors
/// [`StoreError`].
pub async fn end(
    app: &PgPool,
    id: &[u8; 16],
    now_ms: u64,
    reason: EndReason,
) -> Result<bool, StoreError> {
    let n = sqlx::query!(
        "UPDATE access_ops.console_sessions SET ended_ms = $2, end_reason = $3,
                pending_challenge = NULL, pending_key = NULL, pending_party = NULL,
                pending_from_ms = NULL, pending_until_ms = NULL
          WHERE session_id = $1 AND ended_ms IS NULL",
        Uuid::from_bytes(*id),
        ms(now_ms)?,
        reason.text(),
    )
    .execute(app)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Records the registration challenge of a live session without a device Instance, replacing
/// any pending one; `false` when the session has ended or has its Instance.
///
/// # Errors
/// [`StoreError`].
pub async fn set_pending(app: &PgPool, id: &[u8; 16], p: &Pending) -> Result<bool, StoreError> {
    let n = sqlx::query!(
        "UPDATE access_ops.console_sessions
            SET pending_challenge = $2, pending_key = $3, pending_party = $4,
                pending_from_ms = $5, pending_until_ms = $6
          WHERE session_id = $1 AND ended_ms IS NULL AND instance_kid IS NULL",
        Uuid::from_bytes(*id),
        p.challenge.as_slice(),
        p.key,
        p.party.as_slice(),
        ms(p.from_ms)?,
        ms(p.until_ms)?,
    )
    .execute(app)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Takes the pending challenge `challenge` of a live session, once: it is cleared, and returned
/// when it was the session's and not past its end.
///
/// # Errors
/// [`StoreError`].
pub async fn take_pending(
    app: &PgPool,
    id: &[u8; 16],
    challenge: &[u8; 32],
    now_ms: u64,
) -> Result<Option<Pending>, StoreError> {
    let r = sqlx::query!(
        r#"UPDATE access_ops.console_sessions AS s
              SET pending_challenge = NULL, pending_key = NULL, pending_party = NULL,
                  pending_from_ms = NULL, pending_until_ms = NULL
             FROM (SELECT session_id, pending_challenge, pending_key, pending_party,
                          pending_from_ms, pending_until_ms
                     FROM access_ops.console_sessions
                    WHERE session_id = $1 AND pending_challenge = $2 AND ended_ms IS NULL
                      AND instance_kid IS NULL
                    FOR UPDATE) AS old
            WHERE s.session_id = old.session_id
        RETURNING old.pending_key AS "key!", old.pending_party AS "party!",
                  old.pending_from_ms AS "from_ms!", old.pending_until_ms AS "until_ms!""#,
        Uuid::from_bytes(*id),
        challenge.as_slice(),
    )
    .fetch_optional(app)
    .await?;
    let Some(r) = r else {
        return Ok(None);
    };
    let until = unsigned(r.until_ms)?;
    if until < now_ms {
        return Ok(None);
    }
    Ok(Some(Pending {
        challenge: *challenge,
        key: r.key,
        party: fixed(r.party)?,
        from_ms: unsigned(r.from_ms)?,
        until_ms: until,
    }))
}

/// Attaches the device Instance to a live session that has none (INV-13); `false` otherwise.
///
/// # Errors
/// [`StoreError`].
pub async fn attach(
    app: &PgPool,
    id: &[u8; 16],
    kid: &[u8; 32],
    key: &[u8],
) -> Result<bool, StoreError> {
    let n = sqlx::query!(
        "UPDATE access_ops.console_sessions SET instance_kid = $2, instance_key = $3
          WHERE session_id = $1 AND ended_ms IS NULL AND instance_kid IS NULL",
        Uuid::from_bytes(*id),
        kid.as_slice(),
        key,
    )
    .execute(app)
    .await?
    .rows_affected();
    Ok(n == 1)
}
