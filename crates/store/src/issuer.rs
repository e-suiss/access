//! The identity plane as Claim issuer (§10.1.3, §10.1.7, OP-150 L2): the realm's issuer Party,
//! the Instances its issuer key holds in domains, its users' device keys and the Claims it has
//! issued, each by line. Ids and digests only; nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::scope::DomainId;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn id16(b: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

/// Records the transaction realm's issuer Party; `false` when the realm has one already. Never
/// changed afterwards.
///
/// # Errors
/// [`StoreError`].
pub async fn set_realm_issuer(t: &mut TenantTx, party: &[u8; 16]) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "INSERT INTO access.realm_claim_issuer (tenant_id, realm_id, party_id) VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, realm_id) DO NOTHING",
        tenant,
        realm,
        party.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The transaction realm's issuer Party.
///
/// # Errors
/// [`StoreError`].
pub async fn realm_issuer(t: &mut TenantTx) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query_scalar!(
        "SELECT party_id FROM access.realm_claim_issuer WHERE tenant_id = $1 AND realm_id = $2",
        tenant,
        realm,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.as_deref().map(id16).transpose()
}

/// The Instance the realm issuer's key `kid` holds in `domain`.
///
/// # Errors
/// [`StoreError`].
pub async fn issuer_instance(
    t: &mut TenantTx,
    domain: &DomainId,
    kid: &[u8; 32],
) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query_scalar!(
        "SELECT instance_id FROM access.claim_issuer_instance
          WHERE tenant_id = $1 AND realm_id = $2 AND domain_id = $3 AND kid = $4",
        tenant,
        realm,
        domain.as_bytes().as_slice(),
        kid.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.as_deref().map(id16).transpose()
}

/// Whether the realm issuer holds any Instance in `domain`, so its Party is registered there.
///
/// # Errors
/// [`StoreError`].
pub async fn has_issuer_instance(t: &mut TenantTx, domain: &DomainId) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let found = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM access.claim_issuer_instance
          WHERE tenant_id = $1 AND realm_id = $2 AND domain_id = $3) AS "found!""#,
        tenant,
        realm,
        domain.as_bytes().as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok(found)
}

/// Records the Instance the realm issuer's key `kid` opened in `domain`; `false` when it was
/// recorded already.
///
/// # Errors
/// [`StoreError`].
pub async fn record_issuer_instance(
    t: &mut TenantTx,
    domain: &DomainId,
    kid: &[u8; 32],
    instance: &[u8; 16],
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "INSERT INTO access.claim_issuer_instance (tenant_id, realm_id, domain_id, kid, instance_id)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        tenant,
        realm,
        domain.as_bytes().as_slice(),
        kid.as_slice(),
        instance.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// A device key to record (§10.1.3 "Cihaz anahtarı kaydı").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDeviceKey<'a> {
    /// The subject.
    pub subject: [u8; 16],
    /// The COSE public key.
    pub public_key: &'a [u8],
    /// `OKP` or `EC2`.
    pub key_type: &'a str,
    /// `Ed25519` or `ES256`.
    pub algorithm: &'a str,
    /// The Instance the key is.
    pub instance: [u8; 16],
    /// The session that registered it.
    pub session: Option<[u8; 16]>,
}

/// Records a device key; `None` when its Instance has one already.
///
/// # Errors
/// [`StoreError`].
pub async fn insert_device_key(
    t: &mut TenantTx,
    k: &NewDeviceKey<'_>,
) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query_scalar!(
        "INSERT INTO access.device_keys
           (tenant_id, realm_id, subject_id, public_key, key_type, algorithm, instance_id, session_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (tenant_id, realm_id, instance_id) DO NOTHING
         RETURNING device_id",
        tenant,
        realm,
        Uuid::from_bytes(k.subject),
        k.public_key,
        k.key_type,
        k.algorithm,
        k.instance.as_slice(),
        k.session.map(Uuid::from_bytes),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(row.map(|d| *d.as_bytes()))
}

/// Retires the subject's active device key of a terminated Instance (§10.1.3 `status`); `false`
/// when there is none. The row stays (OP-73).
///
/// # Errors
/// [`StoreError`].
pub async fn retire_device_key(
    t: &mut TenantTx,
    subject: &[u8; 16],
    instance: &[u8; 16],
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.device_keys SET status = 'retired'
          WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND instance_id = $4
            AND status = 'active'",
        tenant,
        realm,
        Uuid::from_bytes(*subject),
        instance.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The active device Instance a session registered, the latest first (INV-13: at most one per
/// device and domain).
///
/// # Errors
/// [`StoreError`].
pub async fn session_instance(
    t: &mut TenantTx,
    session: &[u8; 16],
) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query_scalar!(
        "SELECT instance_id FROM access.device_keys
          WHERE tenant_id = $1 AND realm_id = $2 AND session_id = $3 AND status = 'active'
          ORDER BY created_at DESC, device_id DESC LIMIT 1",
        tenant,
        realm,
        Uuid::from_bytes(*session),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.as_deref().map(id16).transpose()
}

/// The subject's active device Instances.
///
/// # Errors
/// [`StoreError`].
pub async fn subject_instances(
    t: &mut TenantTx,
    subject: &[u8; 16],
) -> Result<Vec<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query_scalar!(
        "SELECT instance_id FROM access.device_keys
          WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'
          ORDER BY created_at, device_id",
        tenant,
        realm,
        Uuid::from_bytes(*subject),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.iter().map(|r| id16(r)).collect()
}

/// A Claim the realm issuer issued and Claim Ingest answered.
#[derive(Clone)]
pub struct IssuedClaim<'a> {
    /// The subject it is about.
    pub subject: [u8; 16],
    /// Its class.
    pub class: &'a str,
    /// Its line: a later Claim of the same line supersedes it.
    pub line: [u8; 32],
    /// The domain it is for.
    pub domain: DomainId,
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// `admitted`, `quarantined:<reason>` or `rejected:<code>`, as a word.
    pub disposition: &'a str,
}

/// Records an issued Claim.
///
/// # Errors
/// [`StoreError`].
pub async fn record_issued(t: &mut TenantTx, c: &IssuedClaim<'_>) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.issued_claims
           (tenant_id, realm_id, subject_id, class, line, domain_id, claim_id, disposition)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        tenant,
        realm,
        Uuid::from_bytes(c.subject),
        c.class,
        c.line.as_slice(),
        c.domain.as_bytes().as_slice(),
        c.claim.as_slice(),
        c.disposition,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The latest recorded Claim of `line` about `subject` in `domain` that was not rejected: the
/// one a new Claim of the line supersedes. Lines are per subject.
///
/// # Errors
/// [`StoreError`].
pub async fn last_in_line(
    t: &mut TenantTx,
    subject: &[u8; 16],
    domain: &DomainId,
    line: &[u8; 32],
) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query_scalar!(
        "SELECT claim_id FROM access.issued_claims
          WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND domain_id = $4
            AND line = $5 AND disposition NOT LIKE 'rejected%'
          ORDER BY id DESC LIMIT 1",
        tenant,
        realm,
        Uuid::from_bytes(*subject),
        domain.as_bytes().as_slice(),
        line.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.as_deref().map(id16).transpose()
}
