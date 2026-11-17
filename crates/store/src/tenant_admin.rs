//! Tenant administration (OP-159 m.47, TN-138 … TN-142): the invited founder of a tenant, its
//! administrators, their `tenant_administration` lines in the consuming domains and the console
//! session's device Instance in each domain it reads. Hashes and ids only; nothing is deleted
//! (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{EnvironmentId, TenantId, TenantTx};
use crate::scope::DomainId;

fn id16(b: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

fn id32(b: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn tenant_uuid(t: &TenantTx) -> Uuid {
    Uuid::from_bytes(*t.tenant.as_bytes())
}

/// A founding to record (TN-141).
#[derive(Clone, PartialEq, Eq)]
pub struct NewFounding<'a> {
    /// The slug the management environment will take.
    pub slug: &'a str,
    /// The management environment's id, drawn now so the founder's blind index is its own.
    pub environment: EnvironmentId,
    /// The management environment's blind index of the founder's identifier.
    pub founder_index: &'a [u8; 32],
    /// SHA-256 of the link token.
    pub token_hash: &'a [u8; 32],
    /// SHA-256 of the magic code.
    pub code_hash: &'a [u8; 32],
    /// The `idp.platform.tenant_create` Exercise.
    pub exercise: &'a [u8; 32],
    /// How long the link holds, seconds; at most 30 days.
    pub ttl_s: i64,
}

/// A founding as the tenant reads it.
#[derive(Clone, PartialEq, Eq)]
pub struct Founding {
    /// The slug of the management environment.
    pub slug: String,
    /// The management environment's id.
    pub environment: EnvironmentId,
    /// The founder's blind index.
    pub founder_index: [u8; 32],
    /// SHA-256 of the magic code.
    pub code_hash: [u8; 32],
    /// The `idp.platform.tenant_create` Exercise.
    pub exercise: [u8; 32],
    /// When the link stops holding, Unix ms.
    pub expires_ms: u64,
    /// Reinvitations so far.
    pub reinvites: u32,
    /// Whether the founder proved the identifier.
    pub verified: bool,
    /// The founder's subject once completed.
    pub founder: Option<[u8; 16]>,
}

/// A founding found by its link token, across tenants (TN-141).
#[derive(Clone, PartialEq, Eq)]
pub struct FoundingRoute {
    /// The tenant.
    pub tenant: TenantId,
    /// The slug of the management environment.
    pub slug: String,
    /// The management environment's id.
    pub environment: EnvironmentId,
    /// When the link stops holding, Unix ms.
    pub expires_ms: u64,
    /// Whether the founder proved the identifier.
    pub verified: bool,
    /// Whether the founding completed.
    pub completed: bool,
}

/// Records the founding of the transaction's tenant and reserves its slug (TN-16, TN-141);
/// `false` when the tenant has one already.
///
/// # Errors
/// [`StoreError`]; a taken slug fails as a unique violation.
pub async fn insert_founding(t: &mut TenantTx, f: &NewFounding<'_>) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "INSERT INTO access.tenant_foundings (tenant_id, slug, management_environment_id, founder_index,
           token_hash, code_hash, created_exercise, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp() + $8::bigint * interval '1 second')
         ON CONFLICT (tenant_id) DO NOTHING",
        tenant_uuid(t),
        f.slug,
        Uuid::from_bytes(*f.environment.as_bytes()),
        f.founder_index.as_slice(),
        f.token_hash.as_slice(),
        f.code_hash.as_slice(),
        f.exercise.as_slice(),
        f.ttl_s,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The founding of the transaction's tenant.
///
/// # Errors
/// [`StoreError`].
pub async fn founding(t: &mut TenantTx) -> Result<Option<Founding>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT slug, management_environment_id, founder_index, code_hash, created_exercise,
                  (extract(epoch FROM expires_at) * 1000)::bigint AS "expires_ms!",
                  reinvites, verified_at IS NOT NULL AS "verified!", founder_subject
             FROM access.tenant_foundings WHERE tenant_id = $1"#,
        tenant_uuid(t),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(Founding {
            slug: r.slug,
            environment: EnvironmentId::from_bytes(*r.management_environment_id.as_bytes()),
            founder_index: id32(&r.founder_index)?,
            code_hash: id32(&r.code_hash)?,
            exercise: id32(&r.created_exercise)?,
            expires_ms: unsigned(r.expires_ms)?,
            reinvites: u32::try_from(r.reinvites).map_err(|_| StoreError::Corrupt)?,
            verified: r.verified,
            founder: r.founder_subject.map(|s| *s.as_bytes()),
        })
    })
    .transpose()
}

/// The founding whose link token hashes to `token_hash`, read across tenants through the one
/// function that exposes it (TN-141).
///
/// # Errors
/// [`StoreError`].
pub async fn founding_by_token(
    pool: &PgPool,
    token_hash: &[u8; 32],
) -> Result<Option<FoundingRoute>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT tenant_id AS "tenant_id!", management_slug AS "slug!",
                  management_environment_id AS "environment_id!",
                  (extract(epoch FROM expires_at) * 1000)::bigint AS "expires_ms!",
                  verified AS "verified!", completed AS "completed!"
             FROM access.founding_by_token($1)"#,
        token_hash.as_slice(),
    )
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(FoundingRoute {
            tenant: TenantId::from_bytes(*r.tenant_id.as_bytes()),
            slug: r.slug,
            environment: EnvironmentId::from_bytes(*r.environment_id.as_bytes()),
            expires_ms: unsigned(r.expires_ms)?,
            verified: r.verified,
            completed: r.completed,
        })
    })
    .transpose()
}

/// The tenant whose founding reserved `slug` (TN-141).
///
/// # Errors
/// [`StoreError`].
pub async fn founding_by_slug(pool: &PgPool, slug: &str) -> Result<Option<TenantId>, StoreError> {
    let t = sqlx::query_scalar!(r#"SELECT access.founding_tenant($1) AS "t""#, slug)
        .fetch_one(pool)
        .await?;
    Ok(t.map(|u| TenantId::from_bytes(*u.as_bytes())))
}

/// Whether `slug` is free across environments and foundings (TN-16).
///
/// # Errors
/// [`StoreError`].
pub async fn slug_free(pool: &PgPool, slug: &str) -> Result<bool, StoreError> {
    Ok(
        sqlx::query_scalar!(r#"SELECT access.slug_free($1) AS "free!""#, slug)
            .fetch_one(pool)
            .await?,
    )
}

/// Marks the founding verified: the founder proved the identifier with the magic code (TN-89
/// (5)); `false` when it was already, completed or expired.
///
/// # Errors
/// [`StoreError`].
pub async fn verify_founding(t: &mut TenantTx) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE access.tenant_foundings SET verified_at = clock_timestamp()
          WHERE tenant_id = $1 AND verified_at IS NULL AND completed_at IS NULL
            AND expires_at > clock_timestamp()",
        tenant_uuid(t),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Completes the founding with the founder's subject (TN-141); `false` when it was not verified,
/// already completed or expired.
///
/// # Errors
/// [`StoreError`].
pub async fn complete_founding(t: &mut TenantTx, founder: &[u8; 16]) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE access.tenant_foundings SET completed_at = clock_timestamp(), founder_subject = $2
          WHERE tenant_id = $1 AND verified_at IS NOT NULL AND completed_at IS NULL
            AND expires_at > clock_timestamp()",
        tenant_uuid(t),
        Uuid::from_bytes(*founder),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Replaces the secrets of a pending founding (`reinviteFounder`, TN-141): the old link and code
/// stop working; `false` when the founding completed.
///
/// # Errors
/// [`StoreError`].
pub async fn reinvite_founding(
    t: &mut TenantTx,
    token_hash: &[u8; 32],
    code_hash: &[u8; 32],
    ttl_s: i64,
) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE access.tenant_foundings SET token_hash = $2, code_hash = $3, reinvites = reinvites + 1,
                verified_at = NULL, issued_at = clock_timestamp(),
                expires_at = clock_timestamp() + $4::bigint * interval '1 second'
          WHERE tenant_id = $1 AND completed_at IS NULL",
        tenant_uuid(t),
        token_hash.as_slice(),
        code_hash.as_slice(),
        ttl_s,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Creates the transaction tenant's management environment with the id its founding drew
/// (TN-138, TN-141).
///
/// # Errors
/// [`StoreError`]; a second management environment fails.
pub async fn create_management_environment(
    t: &mut TenantTx,
    environment: EnvironmentId,
    domain: &DomainId,
    (slug, placement): (&str, &str),
) -> Result<EnvironmentId, StoreError> {
    let id = sqlx::query_scalar!(
        r#"INSERT INTO access.environments (tenant_id, environment_id, governing_domain_id, slug, placement_id, kind)
           VALUES ($1, $2, $3, $4, $5, 'management') RETURNING environment_id AS "id!""#,
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        domain.as_bytes().as_slice(),
        slug,
        placement,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok(EnvironmentId::from_bytes(*id.as_bytes()))
}

/// Sets the tenant's display name (TN-131: untrusted text, never authority).
///
/// # Errors
/// [`StoreError`].
pub async fn set_display_name(t: &mut TenantTx, name: &str) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE access.tenants SET display_name = $2 WHERE tenant_id = $1",
        tenant_uuid(t),
        name,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The tenant's display name and state.
///
/// # Errors
/// [`StoreError`].
pub async fn tenant_profile(
    t: &mut TenantTx,
) -> Result<Option<(Option<String>, String)>, StoreError> {
    let row = sqlx::query!(
        "SELECT display_name, status FROM access.tenants WHERE tenant_id = $1",
        tenant_uuid(t),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(row.map(|r| (r.display_name, r.status)))
}

/// Moves the tenant from `from` to `to` (`provisioning` → `active`, `active` ↔ `suspended`);
/// `false` when it was not in `from`.
///
/// # Errors
/// [`StoreError`].
pub async fn set_tenant_status(t: &mut TenantTx, from: &str, to: &str) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE access.tenants SET status = $3 WHERE tenant_id = $1 AND status = $2",
        tenant_uuid(t),
        from,
        to,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Sets the tenant's placement for its new environments (`idp.platform.tenant_placement`).
///
/// # Errors
/// [`StoreError`].
pub async fn set_tenant_placement(t: &mut TenantTx, placement: &str) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE access.tenants SET placement_id = $2 WHERE tenant_id = $1",
        tenant_uuid(t),
        placement,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The kind of the transaction's environment (TN-138): `management` or `standard`.
///
/// # Errors
/// [`StoreError`].
pub async fn environment_kind(t: &mut TenantTx) -> Result<Option<String>, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    Ok(sqlx::query_scalar!(
        "SELECT kind FROM access.environments WHERE tenant_id = $1 AND environment_id = $2",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
    )
    .fetch_optional(&mut *t.tx)
    .await?)
}

/// The tenant's management environment, read in tenant scope (TN-138).
///
/// # Errors
/// [`StoreError`].
pub async fn management_environment(
    t: &mut TenantTx,
) -> Result<Option<(EnvironmentId, String)>, StoreError> {
    let row = sqlx::query!(
        "SELECT environment_id, slug FROM access.environments
          WHERE tenant_id = $1 AND kind = 'management' AND status = 'active'",
        tenant_uuid(t),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(row.map(|r| {
        (
            EnvironmentId::from_bytes(*r.environment_id.as_bytes()),
            r.slug,
        )
    }))
}

/// One live environment of a tenant as its administrators see it.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantEnvironment {
    /// The environment.
    pub environment: EnvironmentId,
    /// Its slug.
    pub slug: String,
    /// `standard` or `management`.
    pub kind: String,
    /// Its governing domain.
    pub domain: DomainId,
    /// Its issuer.
    pub issuer: Option<String>,
    /// Creation time, Unix ms.
    pub created_ms: u64,
    /// Whether it is a sandbox (OP-151 m.3 (m)).
    pub sandbox: bool,
}

/// The tenant's live environments by slug, read in tenant scope.
///
/// # Errors
/// [`StoreError`].
pub async fn tenant_environments(t: &mut TenantTx) -> Result<Vec<TenantEnvironment>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT e.environment_id, e.slug, e.kind, e.governing_domain_id, e.issuer,
                  (extract(epoch FROM e.created_at) * 1000)::bigint AS "created_ms!",
                  EXISTS (SELECT 1 FROM access.sandbox_domains s
                           WHERE s.tenant_id = e.tenant_id AND s.domain_id = e.governing_domain_id)
                    AS "sandbox!"
             FROM access.environments e WHERE e.tenant_id = $1 AND e.status = 'active'
            ORDER BY e.slug"#,
        tenant_uuid(t),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(TenantEnvironment {
                environment: EnvironmentId::from_bytes(*r.environment_id.as_bytes()),
                slug: r.slug,
                kind: r.kind,
                domain: DomainId::from_bytes(id32(&r.governing_domain_id)?),
                issuer: r.issuer,
                created_ms: unsigned(r.created_ms)?,
                sandbox: r.sandbox,
            })
        })
        .collect()
}

/// One tenant administrator.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantAdmin {
    /// The subject in the management environment.
    pub subject: [u8; 16],
    /// Its device Party, once known.
    pub party: Option<[u8; 16]>,
    /// Whether it roots every environment (m.47 (e)).
    pub owner: bool,
    /// When it was added, Unix ms.
    pub added_ms: u64,
    /// Until when a cross-domain first acceptance waits, Unix ms (TN-109).
    pub cooling_until_ms: Option<u64>,
    /// When it was removed, Unix ms.
    pub ended_ms: Option<u64>,
}

/// A tenant administrator to add.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NewAdmin<'a> {
    /// Its device Party, once known: an owner's roots the tenant's environments (m.47 (e)).
    pub party: Option<&'a [u8; 16]>,
    /// Whether it is an owner.
    pub owner: bool,
    /// The Exercise that added it.
    pub exercise: Option<&'a [u8; 32]>,
    /// How long a cross-domain first acceptance waits, seconds (TN-109).
    pub cooling_s: Option<i64>,
}

/// Adds `subject` as an administrator of the transaction's management environment; `false` when
/// it is one already.
///
/// # Errors
/// [`StoreError`].
pub async fn add_admin(
    t: &mut TenantTx,
    subject: &[u8; 16],
    a: &NewAdmin<'_>,
) -> Result<bool, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "INSERT INTO access.tenant_admins (tenant_id, environment_id, subject_id, party_id, owner,
           owner_since, added_exercise, cooling_until)
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $5 THEN clock_timestamp() END, $6,
                 CASE WHEN $7::bigint IS NULL THEN NULL ELSE clock_timestamp() + $7::bigint * interval '1 second' END)
         ON CONFLICT DO NOTHING",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        Uuid::from_bytes(*subject),
        a.party.map(<[u8; 16]>::as_slice),
        a.owner,
        a.exercise.map(<[u8; 32]>::as_slice),
        a.cooling_s,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Records the device Party of an administrator that has none (m.47 (d)); `false` otherwise.
///
/// # Errors
/// [`StoreError`].
pub async fn set_admin_party(
    t: &mut TenantTx,
    subject: &[u8; 16],
    party: &[u8; 16],
) -> Result<bool, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.tenant_admins SET party_id = $4
          WHERE tenant_id = $1 AND environment_id = $2 AND subject_id = $3 AND party_id IS NULL
            AND ended_at IS NULL",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        Uuid::from_bytes(*subject),
        party.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The tenant's placement for its new environments (OP-40).
///
/// # Errors
/// [`StoreError`].
pub async fn tenant_placement(t: &mut TenantTx) -> Result<String, StoreError> {
    Ok(sqlx::query_scalar!(
        "SELECT placement_id FROM access.tenants WHERE tenant_id = $1",
        tenant_uuid(t),
    )
    .fetch_one(&mut *t.tx)
    .await?)
}

/// Makes a live administrator an owner (`idp.tenant.owner_add`); `false` when it is one, removed,
/// or not an administrator.
///
/// # Errors
/// [`StoreError`].
pub async fn make_owner(t: &mut TenantTx, subject: &[u8; 16]) -> Result<bool, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.tenant_admins SET owner = true, owner_since = clock_timestamp()
          WHERE tenant_id = $1 AND environment_id = $2 AND subject_id = $3 AND NOT owner
            AND ended_at IS NULL",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        Uuid::from_bytes(*subject),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Removes a live administrator (`idp.tenant.admin_remove`); `false` when it was not one.
///
/// # Errors
/// [`StoreError`].
pub async fn end_admin(
    t: &mut TenantTx,
    subject: &[u8; 16],
    exercise: Option<&[u8; 32]>,
) -> Result<bool, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.tenant_admins SET ended_at = clock_timestamp(), ended_exercise = $4
          WHERE tenant_id = $1 AND environment_id = $2 AND subject_id = $3 AND ended_at IS NULL",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        Uuid::from_bytes(*subject),
        exercise.map(<[u8; 32]>::as_slice),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The administrators of the transaction's management environment, live and removed, by when
/// they were added.
///
/// # Errors
/// [`StoreError`].
pub async fn admins(t: &mut TenantTx) -> Result<Vec<TenantAdmin>, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let rows = sqlx::query!(
        r#"SELECT subject_id, party_id, owner,
                  (extract(epoch FROM added_at) * 1000)::bigint AS "added_ms!",
                  (extract(epoch FROM cooling_until) * 1000)::bigint AS cooling_ms,
                  (extract(epoch FROM ended_at) * 1000)::bigint AS ended_ms
             FROM access.tenant_admins WHERE tenant_id = $1 AND environment_id = $2
            ORDER BY added_at, subject_id"#,
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(TenantAdmin {
                subject: *r.subject_id.as_bytes(),
                party: r.party_id.as_deref().map(id16).transpose()?,
                owner: r.owner,
                added_ms: unsigned(r.added_ms)?,
                cooling_until_ms: r.cooling_ms.map(unsigned).transpose()?,
                ended_ms: r.ended_ms.map(unsigned).transpose()?,
            })
        })
        .collect()
}

/// The administrator `subject` of the transaction's management environment.
///
/// # Errors
/// [`StoreError`].
pub async fn admin(
    t: &mut TenantTx,
    subject: &[u8; 16],
) -> Result<Option<TenantAdmin>, StoreError> {
    Ok(admins(t).await?.into_iter().find(|a| a.subject == *subject))
}

/// One `tenant_administration` line: an administrator's Party in a consuming domain (m.47 (f)).
#[derive(Clone, PartialEq, Eq)]
pub struct AdminLine {
    /// The management environment.
    pub environment: EnvironmentId,
    /// The administrator's subject there.
    pub subject: [u8; 16],
    /// The consuming domain.
    pub domain: DomainId,
    /// The administrator's Party in it.
    pub party: [u8; 16],
    /// The line's episode: a new one after an ended one (OP-159 m.48 (d)).
    pub episode: i32,
    /// The line's last Claim, when one was stated.
    pub claim: Option<[u8; 16]>,
    /// When it was stated, Unix ms.
    pub stated_ms: Option<u64>,
    /// Until when it holds, Unix ms.
    pub valid_until_ms: Option<u64>,
    /// When the line ended, Unix ms.
    pub ended_ms: Option<u64>,
    /// The ending Claim, once stated.
    pub ended_claim: Option<[u8; 16]>,
}

/// Opens the line of `subject` with `party` in `domain`: its first episode, or a new one after an
/// ended one (OP-159 m.48 (d)); `false` when a live one exists.
///
/// # Errors
/// [`StoreError`].
pub async fn open_line(
    t: &mut TenantTx,
    subject: &[u8; 16],
    domain: &DomainId,
    party: &[u8; 16],
) -> Result<bool, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "INSERT INTO access.tenant_admin_claims (tenant_id, environment_id, subject_id, domain_id, party_id, episode)
         SELECT $1::uuid, $2::uuid, $3::uuid, $4::bytea, $5::bytea, coalesce(max(c.episode), 0) + 1
           FROM access.tenant_admin_claims c
          WHERE c.tenant_id = $1 AND c.environment_id = $2 AND c.subject_id = $3 AND c.domain_id = $4
         HAVING NOT coalesce(bool_or(c.ended_ms IS NULL), false)
         ON CONFLICT DO NOTHING",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        Uuid::from_bytes(*subject),
        domain.as_bytes().as_slice(),
        party.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Records the line's new Claim (m.47 (f)); `false` when the line ended.
///
/// # Errors
/// [`StoreError`].
pub async fn stated(
    t: &mut TenantTx,
    (subject, domain, episode): (&[u8; 16], &DomainId, i32),
    claim: &[u8; 16],
    (stated_ms, until_ms): (u64, u64),
) -> Result<bool, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.tenant_admin_claims SET claim_id = $5, stated_ms = $6, valid_until_ms = $7
          WHERE tenant_id = $1 AND environment_id = $2 AND subject_id = $3 AND domain_id = $4
            AND episode = $8 AND ended_ms IS NULL",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        Uuid::from_bytes(*subject),
        domain.as_bytes().as_slice(),
        claim.as_slice(),
        signed(stated_ms)?,
        signed(until_ms)?,
        episode,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Ends the line at `at_ms`, with the ending Claim once stated; `false` when it ended already
/// with that Claim.
///
/// # Errors
/// [`StoreError`].
pub async fn end_line(
    t: &mut TenantTx,
    (subject, domain, episode): (&[u8; 16], &DomainId, i32),
    at_ms: u64,
    ended_claim: Option<&[u8; 16]>,
) -> Result<bool, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.tenant_admin_claims
            SET ended_ms = coalesce(ended_ms, $5), ended_claim_id = coalesce(ended_claim_id, $6)
          WHERE tenant_id = $1 AND environment_id = $2 AND subject_id = $3 AND domain_id = $4
            AND episode = $7
            AND (ended_ms IS NULL OR (ended_claim_id IS NULL AND $6::bytea IS NOT NULL))",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        Uuid::from_bytes(*subject),
        domain.as_bytes().as_slice(),
        signed(at_ms)?,
        ended_claim.map(<[u8; 16]>::as_slice),
        episode,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The lines of the transaction's management environment, of `subject` when named.
///
/// # Errors
/// [`StoreError`].
pub async fn lines(
    t: &mut TenantTx,
    subject: Option<&[u8; 16]>,
) -> Result<Vec<AdminLine>, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let rows = sqlx::query!(
        "SELECT subject_id, domain_id, party_id, episode, claim_id, stated_ms, valid_until_ms,
                ended_ms, ended_claim_id
           FROM access.tenant_admin_claims
          WHERE tenant_id = $1 AND environment_id = $2 AND ($3::uuid IS NULL OR subject_id = $3)
          ORDER BY subject_id, domain_id, episode",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        subject.map(|s| Uuid::from_bytes(*s)),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(AdminLine {
                environment,
                subject: *r.subject_id.as_bytes(),
                domain: DomainId::from_bytes(id32(&r.domain_id)?),
                party: id16(&r.party_id)?,
                episode: r.episode,
                claim: r.claim_id.as_deref().map(id16).transpose()?,
                stated_ms: r.stated_ms.map(unsigned).transpose()?,
                valid_until_ms: r.valid_until_ms.map(unsigned).transpose()?,
                ended_ms: r.ended_ms.map(unsigned).transpose()?,
                ended_claim: r.ended_claim_id.as_deref().map(id16).transpose()?,
            })
        })
        .collect()
}

/// What the extended standing reads of a line's administrator (OP-159 m.47 (f)).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LineAdmin {
    /// Whether it is still an administrator.
    pub live: bool,
    /// Until when its first acceptance cools, Unix ms (TN-109).
    pub cooling_until_ms: Option<u64>,
}

/// The line of the Party `party` in `domain`, with its administrator (OP-159 m.47 (f)): what the
/// extended standing reads.
///
/// # Errors
/// [`StoreError`].
pub async fn line_of_party(
    t: &mut TenantTx,
    domain: &DomainId,
    party: &[u8; 16],
) -> Result<Option<(AdminLine, LineAdmin)>, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let row = sqlx::query!(
        r#"SELECT c.subject_id, c.episode, c.claim_id, c.stated_ms, c.valid_until_ms, c.ended_ms,
                  c.ended_claim_id,
                  a.ended_at IS NULL AS "admin_live!",
                  (extract(epoch FROM a.cooling_until) * 1000)::bigint AS cooling_ms
             FROM access.tenant_admin_claims c
             JOIN access.tenant_admins a ON a.tenant_id = c.tenant_id
              AND a.environment_id = c.environment_id AND a.subject_id = c.subject_id
            WHERE c.tenant_id = $1 AND c.environment_id = $2 AND c.domain_id = $3 AND c.party_id = $4
            ORDER BY c.episode DESC LIMIT 1"#,
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        domain.as_bytes().as_slice(),
        party.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok((
            AdminLine {
                environment,
                subject: *r.subject_id.as_bytes(),
                domain: *domain,
                party: *party,
                episode: r.episode,
                claim: r.claim_id.as_deref().map(id16).transpose()?,
                stated_ms: r.stated_ms.map(unsigned).transpose()?,
                valid_until_ms: r.valid_until_ms.map(unsigned).transpose()?,
                ended_ms: r.ended_ms.map(unsigned).transpose()?,
                ended_claim: r.ended_claim_id.as_deref().map(id16).transpose()?,
            },
            LineAdmin {
                live: r.admin_live,
                cooling_until_ms: r.cooling_ms.map(unsigned).transpose()?,
            },
        ))
    })
    .transpose()
}

/// The tenants with a live line that is unstated or holds no later than `before_ms`, or an
/// ended line whose ending Claim is not stated, read across tenants by the job role (m.47
/// (f)): what the restate job visits.
///
/// # Errors
/// [`StoreError`].
pub async fn due_tenants(pool: &PgPool, before_ms: u64) -> Result<Vec<TenantId>, StoreError> {
    let rows = sqlx::query_scalar!(
        r#"SELECT t AS "t!" FROM access.tenant_admin_due($1) AS t"#,
        signed(before_ms)?,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|u| TenantId::from_bytes(*u.as_bytes()))
        .collect())
}

/// A tenant administrator invitation to record (OP-159 m.47 (f), TN-89).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NewInvitation<'a> {
    /// SHA-256 of the link token.
    pub token_hash: &'a [u8; 32],
    /// SHA-256 of the magic code.
    pub code_hash: &'a [u8; 32],
    /// The management environment's blind index of the invitee's folded address.
    pub invitee_index: &'a [u8; 32],
    /// The invitee's address domain.
    pub invitee_domain: &'a str,
    /// The inviter's subject.
    pub inviter: &'a [u8; 16],
    /// Whether the invitee's domain is not the inviter's (TN-109).
    pub cross_domain: bool,
    /// The `idp.tenant.admin_invite` Exercise.
    pub exercise: &'a [u8; 32],
    /// How long the link holds, seconds; at most 30 days.
    pub ttl_s: i64,
}

/// A tenant administrator invitation as the management environment keeps it: never its address.
#[derive(Clone, PartialEq, Eq)]
pub struct AdminInvitation {
    /// Its id.
    pub id: [u8; 16],
    /// SHA-256 of the magic code.
    pub code_hash: [u8; 32],
    /// The invitee's blind index.
    pub invitee_index: [u8; 32],
    /// The invitee's address domain.
    pub invitee_domain: String,
    /// The inviter's subject.
    pub inviter: [u8; 16],
    /// Whether the invitee's domain is not the inviter's (TN-109).
    pub cross_domain: bool,
    /// When it was made, Unix ms.
    pub created_ms: u64,
    /// Until when it holds, Unix ms.
    pub expires_ms: u64,
    /// Whether the address was proven.
    pub verified: bool,
    /// The account its acceptance made.
    pub accepted_subject: Option<[u8; 16]>,
    /// Whether a newer invitation to the same address replaced it.
    pub superseded: bool,
}

/// Records an invitation in the transaction's management environment and supersedes the pending
/// ones to the same address (OP-159 m.47 (f)); returns its id.
///
/// # Errors
/// [`StoreError`].
pub async fn insert_invitation(
    t: &mut TenantTx,
    i: &NewInvitation<'_>,
) -> Result<[u8; 16], StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    sqlx::query!(
        "UPDATE access.tenant_admin_invitations SET superseded_at = clock_timestamp()
          WHERE tenant_id = $1 AND environment_id = $2 AND invitee_index = $3
            AND accepted_at IS NULL AND superseded_at IS NULL",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        i.invitee_index.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    let id = sqlx::query_scalar!(
        "INSERT INTO access.tenant_admin_invitations
           (tenant_id, environment_id, token_hash, code_hash, invitee_index, invitee_domain,
            inviter_subject, cross_domain, created_exercise, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, clock_timestamp() + make_interval(secs => $10))
         RETURNING invitation_id",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        i.token_hash.as_slice(),
        i.code_hash.as_slice(),
        i.invitee_index.as_slice(),
        i.invitee_domain,
        Uuid::from_bytes(*i.inviter),
        i.cross_domain,
        i.exercise.as_slice(),
        f64::from(i32::try_from(i.ttl_s).map_err(|_| StoreError::Range)?),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok(*id.as_bytes())
}

/// The invitations of the transaction's management environment, newest first, or the one whose
/// link token hashes to `token_hash`.
///
/// # Errors
/// [`StoreError`].
pub async fn invitations(
    t: &mut TenantTx,
    token_hash: Option<&[u8; 32]>,
) -> Result<Vec<AdminInvitation>, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let rows = sqlx::query!(
        r#"SELECT invitation_id, code_hash, invitee_index, invitee_domain, inviter_subject,
                  cross_domain, verified_at IS NOT NULL AS "verified!", accepted_subject,
                  superseded_at IS NOT NULL AS "superseded!",
                  (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                  (extract(epoch FROM expires_at) * 1000)::bigint AS "expires_ms!"
             FROM access.tenant_admin_invitations
            WHERE tenant_id = $1 AND environment_id = $2
              AND ($3::bytea IS NULL OR token_hash = $3)
            ORDER BY created_at DESC, invitation_id"#,
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        token_hash.map(<[u8; 32]>::as_slice),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(AdminInvitation {
                id: *r.invitation_id.as_bytes(),
                code_hash: id32(&r.code_hash)?,
                invitee_index: id32(&r.invitee_index)?,
                invitee_domain: r.invitee_domain,
                inviter: *r.inviter_subject.as_bytes(),
                cross_domain: r.cross_domain,
                created_ms: unsigned(r.created_ms)?,
                expires_ms: unsigned(r.expires_ms)?,
                verified: r.verified,
                accepted_subject: r.accepted_subject.map(|u| *u.as_bytes()),
                superseded: r.superseded,
            })
        })
        .collect()
}

/// Marks the invitation `id` verified (TN-89 (5)); `false` when it was, or is closed.
///
/// # Errors
/// [`StoreError`].
pub async fn verify_invitation(t: &mut TenantTx, id: &[u8; 16]) -> Result<bool, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.tenant_admin_invitations SET verified_at = clock_timestamp()
          WHERE tenant_id = $1 AND environment_id = $2 AND invitation_id = $3
            AND verified_at IS NULL AND accepted_at IS NULL AND superseded_at IS NULL",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        Uuid::from_bytes(*id),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Closes the verified invitation `id` with the account its acceptance made; `false` when it was
/// not open.
///
/// # Errors
/// [`StoreError`].
pub async fn accept_invitation(
    t: &mut TenantTx,
    id: &[u8; 16],
    subject: &[u8; 16],
) -> Result<bool, StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.tenant_admin_invitations
            SET accepted_at = clock_timestamp(), accepted_subject = $4
          WHERE tenant_id = $1 AND environment_id = $2 AND invitation_id = $3
            AND verified_at IS NOT NULL AND accepted_at IS NULL AND superseded_at IS NULL",
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        Uuid::from_bytes(*id),
        Uuid::from_bytes(*subject),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Invitations the transaction's management environment made in the last `since_s` seconds, and
/// how many of them were accepted (TN-89 (11)).
///
/// # Errors
/// [`StoreError`].
pub async fn invitation_counts(t: &mut TenantTx, since_s: i64) -> Result<(i64, i64), StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    let r = sqlx::query!(
        r#"SELECT count(*) AS "sent!", count(accepted_at) AS "accepted!"
             FROM access.tenant_admin_invitations
            WHERE tenant_id = $1 AND environment_id = $2
              AND created_at > clock_timestamp() - make_interval(secs => $3)"#,
        tenant_uuid(t),
        Uuid::from_bytes(*environment.as_bytes()),
        f64::from(i32::try_from(since_s).map_err(|_| StoreError::Range)?),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok((r.sent, r.accepted))
}

/// The console session's device Instance in one domain (TN-142).
#[derive(Clone, PartialEq, Eq)]
pub struct SessionInstance {
    /// The domain.
    pub domain: DomainId,
    /// The environment the domain governs.
    pub slug: String,
    /// The Party.
    pub party: [u8; 16],
    /// RFC 7638 thumbprint of the key.
    pub kid: [u8; 32],
    /// The public key.
    pub key: Vec<u8>,
}

/// Attaches the session's Instance in `domain` (INV-13: once); `false` when it has one there.
///
/// # Errors
/// [`StoreError`].
pub async fn attach_instance(
    app: &PgPool,
    session: &[u8; 16],
    i: &SessionInstance,
    now_ms: u64,
) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "INSERT INTO access_ops.console_session_instances (session_id, domain_id, environment_slug,
           party_id, instance_kid, instance_key, created_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        Uuid::from_bytes(*session),
        i.domain.as_bytes().as_slice(),
        i.slug,
        i.party.as_slice(),
        i.kid.as_slice(),
        i.key.as_slice(),
        signed(now_ms)?,
    )
    .execute(app)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The session's Instances by domain.
///
/// # Errors
/// [`StoreError`].
pub async fn session_instances(
    app: &PgPool,
    session: &[u8; 16],
) -> Result<Vec<SessionInstance>, StoreError> {
    let rows = sqlx::query!(
        "SELECT domain_id, environment_slug, party_id, instance_kid, instance_key
           FROM access_ops.console_session_instances WHERE session_id = $1 ORDER BY domain_id",
        Uuid::from_bytes(*session),
    )
    .fetch_all(app)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(SessionInstance {
                domain: DomainId::from_bytes(id32(&r.domain_id)?),
                slug: r.environment_slug,
                party: id16(&r.party_id)?,
                kid: id32(&r.instance_kid)?,
                key: r.instance_key,
            })
        })
        .collect()
}

/// A registration challenge for the session's Instance in one more domain (TN-142).
#[derive(Clone, PartialEq, Eq)]
pub struct DomainChallenge {
    /// The challenge.
    pub challenge: [u8; 32],
    /// The domain.
    pub domain: DomainId,
    /// The environment the domain governs.
    pub slug: String,
    /// The COSE key the browser sent.
    pub key: Vec<u8>,
    /// The Party it registers for.
    pub party: [u8; 16],
    /// Its validity, Unix ms.
    pub from_ms: u64,
    /// Its end, Unix ms.
    pub until_ms: u64,
}

/// Records a registration challenge of `session` for one more domain.
///
/// # Errors
/// [`StoreError`].
pub async fn put_domain_challenge(
    app: &PgPool,
    session: &[u8; 16],
    c: &DomainChallenge,
) -> Result<(), StoreError> {
    sqlx::query!(
        "INSERT INTO access_ops.console_instance_challenges (challenge, session_id, domain_id,
           environment_slug, key, party_id, from_ms, until_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        c.challenge.as_slice(),
        Uuid::from_bytes(*session),
        c.domain.as_bytes().as_slice(),
        c.slug,
        c.key.as_slice(),
        c.party.as_slice(),
        signed(c.from_ms)?,
        signed(c.until_ms)?,
    )
    .execute(app)
    .await?;
    Ok(())
}

/// Takes `session`'s challenge `challenge` once, when it has not ended by `now_ms`.
///
/// # Errors
/// [`StoreError`].
pub async fn take_domain_challenge(
    app: &PgPool,
    session: &[u8; 16],
    challenge: &[u8; 32],
    now_ms: u64,
) -> Result<Option<DomainChallenge>, StoreError> {
    let r = sqlx::query!(
        "UPDATE access_ops.console_instance_challenges SET taken_ms = $3
          WHERE challenge = $1 AND session_id = $2 AND taken_ms IS NULL AND until_ms >= $3
        RETURNING domain_id, environment_slug, key, party_id, from_ms, until_ms",
        challenge.as_slice(),
        Uuid::from_bytes(*session),
        signed(now_ms)?,
    )
    .fetch_optional(app)
    .await?;
    r.map(|r| {
        Ok(DomainChallenge {
            challenge: *challenge,
            domain: DomainId::from_bytes(id32(&r.domain_id)?),
            slug: r.environment_slug,
            key: r.key,
            party: id16(&r.party_id)?,
            from_ms: unsigned(r.from_ms)?,
            until_ms: unsigned(r.until_ms)?,
        })
    })
    .transpose()
}
