//! The realm resources of the management API (OP-151 m.2 M1): groups and their members
//! (TN-117), upstream identity providers (OP-150 m.11 (j)), the sign-in and console session
//! policies (TN-132, TN-129), account suspension (§12.3.1) and client secret rotation (CR-38).
//! Every write names a decision bound in its transaction ([`Bound`]); every read is scoped to the
//! transaction's realm by row-level security, so a list holds only what the realm may see
//! (TN-113).

use sqlx::types::Uuid;

use super::{Bound, ClientRow, scope, signed};
use crate::StoreError;
use crate::identity::TenantTx;

/// A group as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRow {
    /// Natural key.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// `admin` or `upstream:<name>` (TN-117).
    pub membership_issuer: String,
    /// Whether it is active.
    pub active: bool,
    /// Position of the decision that last changed it: its `ETag`.
    pub position: u64,
}

/// An upstream identity provider as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamRow {
    /// Natural key.
    pub name: String,
    /// The provider's issuer.
    pub issuer: String,
    /// Access's client id at the provider.
    pub client_id: String,
    /// The secret's reference, never the secret.
    pub client_secret_ref: Option<String>,
    /// The provider's JWKS.
    pub jwks_uri: String,
    /// The provider's SSF transmitter configuration.
    pub ssf: Option<String>,
    /// Whether it is active.
    pub active: bool,
    /// Position of the decision that last changed it.
    pub position: u64,
}

/// The realm's policies as stored: deterministic CBOR, `None` for the default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoliciesRow {
    /// The sign-in requirements (TN-132).
    pub signin: Option<Vec<u8>>,
    /// The console session policy (TN-129).
    pub session: Option<Vec<u8>>,
    /// What the extension points may reach and receive (OP-151 m.10 (e)).
    pub extension: Option<Vec<u8>>,
    /// Position of the decision that last changed them; `None` while all are the default.
    pub position: Option<u64>,
}

/// An account as the management API reads it: no credential field (TN-61).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRow {
    /// Internal subject id.
    pub subject: [u8; 16],
    /// Its TN-49 status.
    pub status: String,
    /// When the status was last set, Unix milliseconds.
    pub status_at_ms: u64,
    /// When it was created, Unix milliseconds.
    pub created_at_ms: u64,
}

fn pos(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn ms(v: Option<f64>) -> Result<u64, StoreError> {
    let v = v.ok_or(StoreError::Corrupt)?;
    if v.is_finite() && (0.0..9.0e15).contains(&v) {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "checked finite, non-negative and below 2^53"
        )]
        Ok(v as u64)
    } else {
        Err(StoreError::Corrupt)
    }
}

/// The realm's group `name`, active or retired.
///
/// # Errors
/// [`StoreError`].
pub async fn group(t: &mut TenantTx, name: &str) -> Result<Option<GroupRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT name, display_name, membership_issuer, status, decision_pos
           FROM access.idp_groups WHERE tenant_id = $1 AND realm_id = $2 AND name = $3",
        tenant,
        realm,
        name,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(GroupRow {
            name: r.name,
            display_name: r.display_name,
            membership_issuer: r.membership_issuer,
            active: r.status == "active",
            position: pos(r.decision_pos)?,
        })
    })
    .transpose()
}

/// Up to `limit` of the realm's groups after the name `after`, in name order.
///
/// # Errors
/// [`StoreError`].
pub async fn groups(
    t: &mut TenantTx,
    after: &str,
    limit: u32,
) -> Result<Vec<GroupRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        "SELECT name, display_name, membership_issuer, status, decision_pos
           FROM access.idp_groups WHERE tenant_id = $1 AND realm_id = $2 AND name > $3
          ORDER BY name LIMIT $4",
        tenant,
        realm,
        after,
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(GroupRow {
                name: r.name,
                display_name: r.display_name,
                membership_issuer: r.membership_issuer,
                active: r.status == "active",
                position: pos(r.decision_pos)?,
            })
        })
        .collect()
}

/// Inserts a group under `bound`.
///
/// # Errors
/// [`StoreError`]; a name ever used before fails.
pub async fn insert_group(t: &mut TenantTx, bound: &Bound, g: &GroupRow) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_groups (tenant_id, realm_id, name, display_name, membership_issuer,
                domain_id, decision_pos)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        tenant,
        realm,
        g.name,
        g.display_name,
        g.membership_issuer,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Renames an active group under `bound`.
///
/// # Errors
/// [`StoreError`].
pub async fn rename_group(
    t: &mut TenantTx,
    bound: &Bound,
    name: &str,
    display_name: &str,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.idp_groups SET display_name = $4, domain_id = $5, decision_pos = $6
          WHERE tenant_id = $1 AND realm_id = $2 AND name = $3 AND status = 'active'",
        tenant,
        realm,
        name,
        display_name,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Retires an active group and ends its memberships under `bound`; the name stays taken.
///
/// # Errors
/// [`StoreError`].
pub async fn retire_group(t: &mut TenantTx, bound: &Bound, name: &str) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "UPDATE access.idp_group_members SET status = 'removed', removed_at = now(),
                domain_id = $4, decision_pos = $5
          WHERE tenant_id = $1 AND realm_id = $2 AND group_name = $3 AND status = 'active'",
        tenant,
        realm,
        name,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    let done = sqlx::query!(
        "UPDATE access.idp_groups SET status = 'retired', retired_at = now(), domain_id = $4,
                decision_pos = $5
          WHERE tenant_id = $1 AND realm_id = $2 AND name = $3 AND status = 'active'",
        tenant,
        realm,
        name,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Makes `subjects` active members of `group` under `bound` (TN-117: the database refuses a
/// group whose members are issued upstream).
///
/// # Errors
/// [`StoreError`].
pub async fn add_members(
    t: &mut TenantTx,
    bound: &Bound,
    group: &str,
    subjects: &[[u8; 16]],
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    let ids: Vec<Uuid> = subjects.iter().map(|s| Uuid::from_bytes(*s)).collect();
    sqlx::query!(
        "INSERT INTO access.idp_group_members (tenant_id, realm_id, group_name, subject_id,
                domain_id, decision_pos)
         SELECT $1, $2, $3, s, $5, $6 FROM unnest($4::uuid[]) AS s
         ON CONFLICT (tenant_id, realm_id, group_name, subject_id) DO UPDATE
            SET status = 'active', removed_at = NULL, domain_id = EXCLUDED.domain_id,
                decision_pos = EXCLUDED.decision_pos
          WHERE access.idp_group_members.status = 'removed'",
        tenant,
        realm,
        group,
        &ids,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Ends the active memberships of `subjects` in `group` under `bound`.
///
/// # Errors
/// [`StoreError`].
pub async fn remove_members(
    t: &mut TenantTx,
    bound: &Bound,
    group: &str,
    subjects: &[[u8; 16]],
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    let ids: Vec<Uuid> = subjects.iter().map(|s| Uuid::from_bytes(*s)).collect();
    sqlx::query!(
        "UPDATE access.idp_group_members SET status = 'removed', removed_at = now(),
                domain_id = $5, decision_pos = $6
          WHERE tenant_id = $1 AND realm_id = $2 AND group_name = $3
            AND subject_id = ANY ($4::uuid[]) AND status = 'active'",
        tenant,
        realm,
        group,
        &ids,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Up to `limit` active members of `group` after the subject `after`, in id order.
///
/// # Errors
/// [`StoreError`].
pub async fn members(
    t: &mut TenantTx,
    group: &str,
    after: [u8; 16],
    limit: u32,
) -> Result<Vec<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query_scalar!(
        "SELECT subject_id FROM access.idp_group_members
          WHERE tenant_id = $1 AND realm_id = $2 AND group_name = $3 AND status = 'active'
            AND subject_id > $4
          ORDER BY subject_id LIMIT $5",
        tenant,
        realm,
        group,
        Uuid::from_bytes(after),
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    Ok(rows.into_iter().map(|u| *u.as_bytes()).collect())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the columns of one row, shared by the single and the list read"
)]
fn upstream_row(
    name: String,
    issuer: String,
    client_id: String,
    client_secret_ref: Option<String>,
    jwks_uri: String,
    ssf: Option<String>,
    status: &str,
    position: i64,
) -> Result<UpstreamRow, StoreError> {
    Ok(UpstreamRow {
        name,
        issuer,
        client_id,
        client_secret_ref,
        jwks_uri,
        ssf,
        active: status == "active",
        position: pos(position)?,
    })
}

/// The realm's upstream provider `name`, active or retired.
///
/// # Errors
/// [`StoreError`].
pub async fn upstream(t: &mut TenantTx, name: &str) -> Result<Option<UpstreamRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT name, issuer, client_id, client_secret_ref, jwks_uri, ssf,
                status, decision_pos
           FROM access.idp_upstreams WHERE tenant_id = $1 AND realm_id = $2 AND name = $3",
        tenant,
        realm,
        name,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        upstream_row(
            r.name,
            r.issuer,
            r.client_id,
            r.client_secret_ref,
            r.jwks_uri,
            r.ssf,
            &r.status,
            r.decision_pos,
        )
    })
    .transpose()
}

/// Up to `limit` of the realm's upstream providers after the name `after`.
///
/// # Errors
/// [`StoreError`].
pub async fn upstreams(
    t: &mut TenantTx,
    after: &str,
    limit: u32,
) -> Result<Vec<UpstreamRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        "SELECT name, issuer, client_id, client_secret_ref, jwks_uri, ssf,
                status, decision_pos
           FROM access.idp_upstreams WHERE tenant_id = $1 AND realm_id = $2 AND name > $3
          ORDER BY name LIMIT $4",
        tenant,
        realm,
        after,
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            upstream_row(
                r.name,
                r.issuer,
                r.client_id,
                r.client_secret_ref,
                r.jwks_uri,
                r.ssf,
                &r.status,
                r.decision_pos,
            )
        })
        .collect()
}

/// Registers, or replaces the registration of an active, upstream provider under `bound`.
///
/// # Errors
/// [`StoreError`].
pub async fn put_upstream(
    t: &mut TenantTx,
    bound: &Bound,
    u: &UpstreamRow,
    insert: bool,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let domain = bound.domain.as_bytes().as_slice();
    let done = if insert {
        sqlx::query!(
            "INSERT INTO access.idp_upstreams (tenant_id, realm_id, name, issuer, client_id,
                    client_secret_ref, jwks_uri, ssf, domain_id, decision_pos)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            tenant,
            realm,
            u.name,
            u.issuer,
            u.client_id,
            u.client_secret_ref,
            u.jwks_uri,
            u.ssf,
            domain,
            bound.position,
        )
        .execute(&mut *t.tx)
        .await?
    } else {
        sqlx::query!(
            "UPDATE access.idp_upstreams SET issuer = $4, client_id = $5, client_secret_ref = $6,
                    jwks_uri = $7, ssf = $8, domain_id = $9, decision_pos = $10
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3 AND status = 'active'",
            tenant,
            realm,
            u.name,
            u.issuer,
            u.client_id,
            u.client_secret_ref,
            u.jwks_uri,
            u.ssf,
            domain,
            bound.position,
        )
        .execute(&mut *t.tx)
        .await?
    };
    Ok(done.rows_affected() == 1)
}

/// Retires an active upstream provider under `bound`.
///
/// # Errors
/// [`StoreError`].
pub async fn retire_upstream(
    t: &mut TenantTx,
    bound: &Bound,
    name: &str,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.idp_upstreams SET status = 'retired', retired_at = now(), domain_id = $4,
                decision_pos = $5
          WHERE tenant_id = $1 AND realm_id = $2 AND name = $3 AND status = 'active'",
        tenant,
        realm,
        name,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// The realm's policies.
///
/// # Errors
/// [`StoreError`].
pub async fn policies(t: &mut TenantTx) -> Result<PoliciesRow, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT signin_policy, session_policy, extension_policy, decision_pos
           FROM access.idp_realm_policies
          WHERE tenant_id = $1 AND realm_id = $2",
        tenant,
        realm,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map_or_else(
        || Ok(PoliciesRow::default()),
        |r| {
            Ok(PoliciesRow {
                signin: r.signin_policy,
                session: r.session_policy,
                extension: r.extension_policy,
                position: Some(pos(r.decision_pos)?),
            })
        },
    )
}

/// One of the realm's stored policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyKind {
    /// The sign-in requirements (`idp.realm.signin_policy`).
    Signin,
    /// The console session policy (`idp.realm.session_policy`).
    Session,
    /// The extension policy (`idp.realm.extension_policy`).
    Extension,
}

/// Sets one of the realm's policies under `bound`; the others stay as they are.
///
/// # Errors
/// [`StoreError`].
pub async fn set_policy(
    t: &mut TenantTx,
    bound: &Bound,
    kind: PolicyKind,
    value: &[u8],
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    let domain = bound.domain.as_bytes().as_slice();
    let q = match kind {
        PolicyKind::Signin => sqlx::query!(
            "INSERT INTO access.idp_realm_policies (tenant_id, realm_id, signin_policy, domain_id,
                    decision_pos)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, realm_id) DO UPDATE SET signin_policy = EXCLUDED.signin_policy,
                    domain_id = EXCLUDED.domain_id, decision_pos = EXCLUDED.decision_pos",
            tenant,
            realm,
            value,
            domain,
            bound.position,
        ),
        PolicyKind::Session => sqlx::query!(
            "INSERT INTO access.idp_realm_policies (tenant_id, realm_id, session_policy, domain_id,
                    decision_pos)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, realm_id) DO UPDATE SET session_policy = EXCLUDED.session_policy,
                    domain_id = EXCLUDED.domain_id, decision_pos = EXCLUDED.decision_pos",
            tenant,
            realm,
            value,
            domain,
            bound.position,
        ),
        PolicyKind::Extension => sqlx::query!(
            "INSERT INTO access.idp_realm_policies (tenant_id, realm_id, extension_policy,
                    domain_id, decision_pos)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, realm_id) DO UPDATE
                SET extension_policy = EXCLUDED.extension_policy,
                    domain_id = EXCLUDED.domain_id, decision_pos = EXCLUDED.decision_pos",
            tenant,
            realm,
            value,
            domain,
            bound.position,
        ),
    };
    q.execute(&mut *t.tx).await?;
    Ok(())
}

/// The account `subject`, without any credential field (TN-61).
///
/// # Errors
/// [`StoreError`].
pub async fn account(
    t: &mut TenantTx,
    subject: [u8; 16],
) -> Result<Option<AccountRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        r#"SELECT subject_id, status,
                  (extract(epoch FROM status_at) * 1000)::float8 AS "status_at_ms",
                  (extract(epoch FROM created_at) * 1000)::float8 AS "created_at_ms"
             FROM access.identity_subjects
            WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3"#,
        tenant,
        realm,
        Uuid::from_bytes(subject),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(AccountRow {
            subject: *r.subject_id.as_bytes(),
            status: r.status,
            status_at_ms: ms(r.status_at_ms)?,
            created_at_ms: ms(r.created_at_ms)?,
        })
    })
    .transpose()
}

/// Up to `limit` of the realm's accounts after `after`, in id order.
///
/// # Errors
/// [`StoreError`].
pub async fn accounts(
    t: &mut TenantTx,
    after: [u8; 16],
    limit: u32,
) -> Result<Vec<AccountRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        r#"SELECT subject_id, status,
                  (extract(epoch FROM status_at) * 1000)::float8 AS "status_at_ms",
                  (extract(epoch FROM created_at) * 1000)::float8 AS "created_at_ms"
             FROM access.identity_subjects
            WHERE tenant_id = $1 AND realm_id = $2 AND subject_id > $3
            ORDER BY subject_id LIMIT $4"#,
        tenant,
        realm,
        Uuid::from_bytes(after),
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(AccountRow {
                subject: *r.subject_id.as_bytes(),
                status: r.status,
                status_at_ms: ms(r.status_at_ms)?,
                created_at_ms: ms(r.created_at_ms)?,
            })
        })
        .collect()
}

/// Suspends (`suspend`) or reactivates the account `subject` under `bound` (§12.3.1, TN-49): a
/// suspension also ends its sessions by raising the session epoch. `false` when the account is
/// not in a state the change leaves.
///
/// # Errors
/// [`StoreError`].
pub async fn set_account_state(
    t: &mut TenantTx,
    bound: &Bound,
    subject: [u8; 16],
    suspend: bool,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let id = Uuid::from_bytes(subject);
    let (action, done) = if suspend {
        let done = sqlx::query!(
            "UPDATE access.identity_subjects SET status = 'suspended', status_at = now(),
                    session_epoch = session_epoch + 1
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                AND status IN ('active', 'locked')",
            tenant,
            realm,
            id,
        )
        .execute(&mut *t.tx)
        .await?;
        ("idp.account.suspend", done)
    } else {
        let done = sqlx::query!(
            "UPDATE access.identity_subjects SET status = 'active', status_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'suspended'",
            tenant,
            realm,
            id,
        )
        .execute(&mut *t.tx)
        .await?;
        ("idp.account.reactivate", done)
    };
    if done.rows_affected() != 1 {
        return Ok(false);
    }
    sqlx::query!(
        "INSERT INTO access.idp_account_changes (tenant_id, realm_id, subject_id, action, domain_id,
                decision_pos)
         VALUES ($1, $2, $3, $4, $5, $6)",
        tenant,
        realm,
        id,
        action,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(true)
}

/// How many passkeys the realm's accounts have registered (IDI-4).
///
/// # Errors
/// [`StoreError`].
pub async fn passkey_count(t: &mut TenantTx) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let n = sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM access.webauthn_credentials
            WHERE tenant_id = $1 AND realm_id = $2"#,
        tenant,
        realm,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    pos(n)
}

/// Up to `limit` of the realm's clients after `after`, in `client_id` order.
///
/// # Errors
/// [`StoreError`].
pub async fn clients(
    t: &mut TenantTx,
    after: &str,
    limit: u32,
) -> Result<Vec<(ClientRow, u64)>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let ids = sqlx::query_scalar!(
        "SELECT client_id FROM access.idp_clients
          WHERE tenant_id = $1 AND realm_id = $2 AND client_id > $3
          ORDER BY client_id LIMIT $4",
        tenant,
        realm,
        after,
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(c) = super::client(t, &id).await? {
            let at = client_position(t, &id).await?.ok_or(StoreError::Corrupt)?;
            out.push((c, at));
        }
    }
    Ok(out)
}

/// The position of the decision that last changed the client: its `ETag`.
///
/// # Errors
/// [`StoreError`].
pub async fn client_position(t: &mut TenantTx, client_id: &str) -> Result<Option<u64>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let p = sqlx::query_scalar!(
        "SELECT decision_pos FROM access.idp_clients
          WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3",
        tenant,
        realm,
        client_id,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    p.map(pos).transpose()
}

/// Replaces an active client's secret under `bound` (CR-38); the old one is kept, as a digest,
/// until `overlap_ms` from now.
///
/// # Errors
/// [`StoreError`].
pub async fn rotate_secret(
    t: &mut TenantTx,
    bound: &Bound,
    client_id: &str,
    secret_hash: &[u8; 32],
    overlap_ms: u64,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.idp_clients SET previous_secret_hash = secret_hash,
                previous_secret_until = now() + make_interval(secs => $4::bigint / 1000.0),
                secret_hash = $5, domain_id = $6, decision_pos = $7
          WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND status = 'active'
            AND auth_method = 'client_secret_basic'",
        tenant,
        realm,
        client_id,
        signed(overlap_ms)?,
        secret_hash.as_slice(),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// The digest of an active `client_secret_basic` client's previous secret while its rotation
/// overlap lasts (CR-38, OP-151 m.11 (g)); `None` once it has ended or when there is none.
///
/// # Errors
/// [`StoreError`].
pub async fn previous_secret(
    t: &mut TenantTx,
    client_id: &str,
) -> Result<Option<[u8; 32]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let hash = sqlx::query_scalar!(
        "SELECT previous_secret_hash FROM access.idp_clients
          WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND status = 'active'
            AND auth_method = 'client_secret_basic' AND previous_secret_until > now()",
        tenant,
        realm,
        client_id,
    )
    .fetch_optional(&mut *t.tx)
    .await?
    .flatten();
    hash.map(|h| <[u8; 32]>::try_from(h.as_slice()).map_err(|_| StoreError::Corrupt))
        .transpose()
}
