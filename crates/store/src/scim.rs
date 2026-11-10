//! The SCIM server's clients and resources and the outbound SCIM client's targets (OP-155 m.3 (g),
//! IDP-23, IDP-29). Clients and targets change only under `idp.scim.*` decisions and the newest
//! version is the one in force; resources change with their clients' requests and are deleted
//! softly: a deleted resource is never read again and its id is never used again (OP-73,
//! INV-32).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn version(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn bytes32(b: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

/// An inbound SCIM client, its newest version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRow {
    /// Its name.
    pub name: String,
    /// The version in force.
    pub version: u64,
    /// Whether it is live.
    pub live: bool,
    /// SHA-256 of its bearer secret.
    pub secret_sha256: [u8; 32],
    /// Its tolerance profile.
    pub profile: Option<String>,
    /// Its issuer Party.
    pub issuer: [u8; 16],
    /// The decision that wrote this version.
    pub decision_pos: i64,
}

/// Writes the next version of client `name` under `bound`; returns the version written.
///
/// # Errors
/// [`StoreError`].
pub async fn put_client(
    t: &mut TenantTx,
    bound: &Bound,
    name: &str,
    secret_sha256: &[u8; 32],
    profile: Option<&str>,
    issuer: &[u8; 16],
    live: bool,
) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let v = sqlx::query_scalar!(
        r#"INSERT INTO access.scim_clients (tenant_id, realm_id, name, version, state, secret_sha256,
                profile, issuer, domain_id, decision_pos)
         SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9
           FROM access.scim_clients WHERE tenant_id = $1 AND realm_id = $2 AND name = $3
         RETURNING version AS "version!""#,
        tenant,
        realm,
        name,
        if live { "live" } else { "retired" },
        secret_sha256.as_slice(),
        profile,
        Uuid::from_bytes(*issuer),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    version(v)
}

/// The realm's clients, newest version each, by name.
///
/// # Errors
/// [`StoreError`].
pub async fn clients(t: &mut TenantTx) -> Result<Vec<ClientRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        "SELECT DISTINCT ON (name) name, version, state, secret_sha256, profile, issuer, decision_pos
           FROM access.scim_clients WHERE tenant_id = $1 AND realm_id = $2
          ORDER BY name, version DESC",
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(ClientRow {
                name: r.name,
                version: version(r.version)?,
                live: r.state == "live",
                secret_sha256: bytes32(r.secret_sha256)?,
                profile: r.profile,
                issuer: *r.issuer.as_bytes(),
                decision_pos: r.decision_pos,
            })
        })
        .collect()
}

/// Client `name`, newest version; `None` when never registered.
///
/// # Errors
/// [`StoreError`].
pub async fn client(t: &mut TenantTx, name: &str) -> Result<Option<ClientRow>, StoreError> {
    Ok(clients(t).await?.into_iter().find(|c| c.name == name))
}

/// The live client whose newest version holds the secret with SHA-256 `secret`.
///
/// # Errors
/// [`StoreError`].
pub async fn client_by_secret(
    t: &mut TenantTx,
    secret: &[u8; 32],
) -> Result<Option<ClientRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let names = sqlx::query_scalar!(
        "SELECT DISTINCT name FROM access.scim_clients
          WHERE tenant_id = $1 AND realm_id = $2 AND secret_sha256 = $3",
        tenant,
        realm,
        secret.as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    let mut found = None;
    for name in names {
        if let Some(c) = client(t, &name).await?
            && c.live
            && c.secret_sha256 == *secret
        {
            if found.is_some() {
                return Ok(None);
            }
            found = Some(c);
        }
    }
    Ok(found)
}

/// One live resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRow {
    /// Its id.
    pub id: [u8; 16],
    /// The client that owns it.
    pub client: String,
    /// `user`, `group` or `device`.
    pub kind: String,
    /// A user's account.
    pub subject: Option<[u8; 16]>,
    /// The blind index of its `externalId`.
    pub external_index: Option<[u8; 32]>,
    /// A group's or device's display name.
    pub display_name: Option<String>,
    /// A group's or device's body.
    pub body: Option<String>,
    /// A user's sealed body: nonce and ciphertext.
    pub sealed: Option<([u8; 12], Vec<u8>)>,
    /// Its version.
    pub version: u64,
    /// Created, Unix ms.
    pub created_ms: i64,
    /// Last changed, Unix ms.
    pub modified_ms: i64,
}

/// What a write stores.
#[derive(Clone, Debug)]
pub struct ResourceWrite<'a> {
    /// The id.
    pub id: [u8; 16],
    /// The owning client.
    pub client: &'a str,
    /// `user`, `group` or `device`.
    pub kind: &'a str,
    /// A user's account.
    pub subject: Option<[u8; 16]>,
    /// The blind index of its `externalId`.
    pub external_index: Option<[u8; 32]>,
    /// A group's or device's display name.
    pub display_name: Option<&'a str>,
    /// A group's or device's body.
    pub body: Option<&'a str>,
    /// A user's sealed body.
    pub sealed: Option<(&'a [u8; 12], &'a [u8])>,
    /// The version written.
    pub version: u64,
}

#[expect(
    clippy::too_many_arguments,
    reason = "one column group each, from the three SELECTs that share it"
)]
fn row(
    id: Uuid,
    client: String,
    kind: String,
    subject: Option<Uuid>,
    external_index: Option<Vec<u8>>,
    display_name: Option<String>,
    body: Option<String>,
    sealed: (Option<Vec<u8>>, Option<Vec<u8>>),
    times: (i64, i64, i64),
) -> Result<ResourceRow, StoreError> {
    let sealed = match sealed {
        (Some(n), Some(c)) => Some((<[u8; 12]>::try_from(n).map_err(|_| StoreError::Corrupt)?, c)),
        _ => None,
    };
    Ok(ResourceRow {
        id: *id.as_bytes(),
        client,
        kind,
        subject: subject.map(|s| *s.as_bytes()),
        external_index: external_index.map(bytes32).transpose()?,
        display_name,
        body,
        sealed,
        version: version(times.0)?,
        created_ms: times.1,
        modified_ms: times.2,
    })
}

/// Stores a new resource; `false` when the client already has a live resource of the kind with
/// this `externalId`.
///
/// # Errors
/// [`StoreError`].
pub async fn insert_resource(t: &mut TenantTx, w: &ResourceWrite<'_>) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let n = sqlx::query!(
        "INSERT INTO access.scim_resources (tenant_id, realm_id, resource_id, client_name, kind,
                subject_id, external_index, display_name, body, body_nonce, body_ciphertext, version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb, $10, $11, $12)
         ON CONFLICT (tenant_id, realm_id, client_name, kind, external_index)
           WHERE deleted_at IS NULL AND external_index IS NOT NULL DO NOTHING",
        tenant,
        realm,
        Uuid::from_bytes(w.id),
        w.client,
        w.kind,
        w.subject.map(Uuid::from_bytes),
        w.external_index.as_ref().map(<[u8; 32]>::as_slice),
        w.display_name,
        w.body,
        w.sealed.map(|(n, _)| n.as_slice()),
        w.sealed.map(|(_, c)| c),
        signed(w.version)?,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Replaces a live resource's content if it is still at `expected`; `false` when it moved on,
/// another live resource of the client holds the `externalId`, or it is gone.
///
/// # Errors
/// [`StoreError`].
pub async fn update_resource(
    t: &mut TenantTx,
    w: &ResourceWrite<'_>,
    expected: u64,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    if let Some(index) = &w.external_index {
        let taken = sqlx::query_scalar!(
            "SELECT 1 AS \"one!\" FROM access.scim_resources
              WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND kind = $4
                AND external_index = $5 AND deleted_at IS NULL AND resource_id <> $6",
            tenant,
            realm,
            w.client,
            w.kind,
            index.as_slice(),
            Uuid::from_bytes(w.id),
        )
        .fetch_optional(&mut *t.tx)
        .await?;
        if taken.is_some() {
            return Ok(false);
        }
    }
    let n = sqlx::query!(
        "UPDATE access.scim_resources
            SET external_index = $5, display_name = $6, body = $7::text::jsonb, body_nonce = $8,
                body_ciphertext = $9, version = $10, modified_at = clock_timestamp()
          WHERE tenant_id = $1 AND realm_id = $2 AND resource_id = $3 AND client_name = $4
            AND deleted_at IS NULL AND version = $11",
        tenant,
        realm,
        Uuid::from_bytes(w.id),
        w.client,
        w.external_index.as_ref().map(<[u8; 32]>::as_slice),
        w.display_name,
        w.body,
        w.sealed.map(|(n, _)| n.as_slice()),
        w.sealed.map(|(_, c)| c),
        signed(w.version)?,
        signed(expected)?,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Soft-deletes a live resource at `expected`; `false` when it moved on or is gone.
///
/// # Errors
/// [`StoreError`].
pub async fn delete_resource(
    t: &mut TenantTx,
    client: &str,
    id: [u8; 16],
    expected: u64,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let n = sqlx::query!(
        "UPDATE access.scim_resources
            SET deleted_at = clock_timestamp(), modified_at = clock_timestamp(), version = version + 1
          WHERE tenant_id = $1 AND realm_id = $2 AND resource_id = $3 AND client_name = $4
            AND deleted_at IS NULL AND version = $5",
        tenant,
        realm,
        Uuid::from_bytes(id),
        client,
        signed(expected)?,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// The client's live resource `id` of `kind`, locked when `lock`.
///
/// # Errors
/// [`StoreError`].
pub async fn resource(
    t: &mut TenantTx,
    client: &str,
    kind: &str,
    id: [u8; 16],
    lock: bool,
) -> Result<Option<ResourceRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let r = if lock {
        sqlx::query!(
            r#"SELECT resource_id, client_name, kind, subject_id, external_index, display_name, body::text AS body,
                    body_nonce, body_ciphertext, version,
                    (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                    (extract(epoch FROM modified_at) * 1000)::bigint AS "modified_ms!"
               FROM access.scim_resources
              WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND kind = $4
                AND resource_id = $5 AND deleted_at IS NULL
              FOR UPDATE"#,
            tenant,
            realm,
            client,
            kind,
            Uuid::from_bytes(id),
        )
        .fetch_optional(&mut *t.tx)
        .await?
        .map(|r| {
            row(
                r.resource_id,
                r.client_name,
                r.kind,
                r.subject_id,
                r.external_index,
                r.display_name,
                r.body,
                (r.body_nonce, r.body_ciphertext),
                (r.version, r.created_ms, r.modified_ms),
            )
        })
    } else {
        sqlx::query!(
            r#"SELECT resource_id, client_name, kind, subject_id, external_index, display_name, body::text AS body,
                    body_nonce, body_ciphertext, version,
                    (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                    (extract(epoch FROM modified_at) * 1000)::bigint AS "modified_ms!"
               FROM access.scim_resources
              WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND kind = $4
                AND resource_id = $5 AND deleted_at IS NULL"#,
            tenant,
            realm,
            client,
            kind,
            Uuid::from_bytes(id),
        )
        .fetch_optional(&mut *t.tx)
        .await?
        .map(|r| {
            row(
                r.resource_id,
                r.client_name,
                r.kind,
                r.subject_id,
                r.external_index,
                r.display_name,
                r.body,
                (r.body_nonce, r.body_ciphertext),
                (r.version, r.created_ms, r.modified_ms),
            )
        })
    };
    r.transpose()
}

/// The client's live resources of `kind` after `after` by id, at most `limit`.
///
/// # Errors
/// [`StoreError`].
pub async fn page(
    t: &mut TenantTx,
    client: &str,
    kind: &str,
    after: Option<[u8; 16]>,
    limit: i64,
) -> Result<Vec<ResourceRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        r#"SELECT resource_id, client_name, kind, subject_id, external_index, display_name, body::text AS body,
                body_nonce, body_ciphertext, version,
                (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                (extract(epoch FROM modified_at) * 1000)::bigint AS "modified_ms!"
           FROM access.scim_resources
          WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND kind = $4
            AND deleted_at IS NULL AND resource_id > $5
          ORDER BY resource_id LIMIT $6"#,
        tenant,
        realm,
        client,
        kind,
        Uuid::from_bytes(after.unwrap_or([0; 16])),
        limit,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            row(
                r.resource_id,
                r.client_name,
                r.kind,
                r.subject_id,
                r.external_index,
                r.display_name,
                r.body,
                (r.body_nonce, r.body_ciphertext),
                (r.version, r.created_ms, r.modified_ms),
            )
        })
        .collect()
}

/// How many live resources of `kind` the client has.
///
/// # Errors
/// [`StoreError`].
pub async fn count(t: &mut TenantTx, client: &str, kind: &str) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let n = sqlx::query_scalar!(
        "SELECT count(*) AS \"n!\" FROM access.scim_resources
          WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND kind = $4
            AND deleted_at IS NULL",
        tenant,
        realm,
        client,
        kind,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    version(n)
}

/// The id of the client's live resource of `kind` with `externalId` index `index`.
///
/// # Errors
/// [`StoreError`].
pub async fn by_external(
    t: &mut TenantTx,
    client: &str,
    kind: &str,
    index: &[u8; 32],
) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let id = sqlx::query_scalar!(
        "SELECT resource_id FROM access.scim_resources
          WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND kind = $4
            AND external_index = $5 AND deleted_at IS NULL",
        tenant,
        realm,
        client,
        kind,
        index.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(id.map(|u| *u.as_bytes()))
}

/// The live user resource of the client on account `subject`.
///
/// # Errors
/// [`StoreError`].
pub async fn user_of_subject(
    t: &mut TenantTx,
    client: &str,
    subject: [u8; 16],
) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let id = sqlx::query_scalar!(
        "SELECT resource_id FROM access.scim_resources
          WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND kind = 'user'
            AND subject_id = $4 AND deleted_at IS NULL",
        tenant,
        realm,
        client,
        Uuid::from_bytes(subject),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(id.map(|u| *u.as_bytes()))
}

/// Whether any live SCIM resource, of any client, is on account `subject`.
///
/// # Errors
/// [`StoreError`].
pub async fn subject_provisioned(t: &mut TenantTx, subject: [u8; 16]) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let n = sqlx::query_scalar!(
        "SELECT count(*) AS \"n!\" FROM access.scim_resources
          WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND deleted_at IS NULL",
        tenant,
        realm,
        Uuid::from_bytes(subject),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok(n > 0)
}

/// The accounts of the client's live users among `ids`, as `(id, subject)`.
///
/// # Errors
/// [`StoreError`].
pub async fn user_subjects(
    t: &mut TenantTx,
    client: &str,
    ids: &[[u8; 16]],
) -> Result<Vec<([u8; 16], [u8; 16])>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let ids: Vec<Uuid> = ids.iter().map(|i| Uuid::from_bytes(*i)).collect();
    let rows = sqlx::query!(
        r#"SELECT resource_id, subject_id AS "subject_id!" FROM access.scim_resources
          WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND kind = 'user'
            AND deleted_at IS NULL AND resource_id = ANY($4) AND subject_id IS NOT NULL"#,
        tenant,
        realm,
        client,
        &ids,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (*r.resource_id.as_bytes(), *r.subject_id.as_bytes()))
        .collect())
}

/// The client's live groups whose members include `member`, as `(id, display name, version)`.
///
/// # Errors
/// [`StoreError`].
pub async fn groups_of(
    t: &mut TenantTx,
    client: &str,
    member: &str,
) -> Result<Vec<([u8; 16], String, u64)>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let safe = !member.is_empty()
        && member.len() <= 256
        && member
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !safe {
        return Ok(Vec::new());
    }
    let probe = format!(r#"{{"members":[{{"value":"{member}"}}]}}"#);
    let rows = sqlx::query!(
        "SELECT resource_id, display_name, version FROM access.scim_resources
          WHERE tenant_id = $1 AND realm_id = $2 AND client_name = $3 AND kind = 'group'
            AND deleted_at IS NULL AND body @> $4::text::jsonb
          ORDER BY resource_id",
        tenant,
        realm,
        client,
        probe,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok((
                *r.resource_id.as_bytes(),
                r.display_name.unwrap_or_default(),
                version(r.version)?,
            ))
        })
        .collect()
}

/// An outbound SCIM target, its newest version.
#[derive(Clone, Debug)]
pub struct TargetRow {
    /// Its name.
    pub name: String,
    /// Whether it is live.
    pub live: bool,
    /// Its SCIM base URL.
    pub base_url: String,
    /// Its sealed bearer secret.
    pub secret: crate::events::SealedKey,
}

/// What a target version stores.
#[derive(Clone, Copy, Debug)]
pub struct TargetWrite<'a> {
    /// Its name.
    pub name: &'a str,
    /// Its SCIM base URL.
    pub base_url: &'a str,
    /// Its sealed secret.
    pub secret: &'a crate::events::SealedKey,
    /// Whether it is live.
    pub live: bool,
}

/// Writes the next version of target `w.name` under `bound`.
///
/// # Errors
/// [`StoreError`].
pub async fn put_target(
    t: &mut TenantTx,
    bound: &Bound,
    w: &TargetWrite<'_>,
) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let v = sqlx::query_scalar!(
        r#"INSERT INTO access.scim_targets (tenant_id, realm_id, name, version, state, base_url,
                secret_wrapped_dek, secret_nonce, secret_sealed, kek_id, domain_id, decision_pos)
         SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9, $10, $11
           FROM access.scim_targets WHERE tenant_id = $1 AND realm_id = $2 AND name = $3
         RETURNING version AS "version!""#,
        tenant,
        realm,
        w.name,
        if w.live { "live" } else { "retired" },
        w.base_url,
        w.secret.wrapped_dek,
        w.secret.nonce.as_slice(),
        w.secret.ciphertext,
        w.secret.kek_id,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    version(v)
}

/// The realm's targets, newest version each.
///
/// # Errors
/// [`StoreError`].
pub async fn targets(t: &mut TenantTx) -> Result<Vec<TargetRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        "SELECT DISTINCT ON (name) name, state, base_url, secret_wrapped_dek, secret_nonce,
                secret_sealed, kek_id
           FROM access.scim_targets WHERE tenant_id = $1 AND realm_id = $2
          ORDER BY name, version DESC",
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(TargetRow {
                name: r.name,
                live: r.state == "live",
                base_url: r.base_url,
                secret: crate::events::SealedKey {
                    kek_id: r.kek_id,
                    wrapped_dek: r.secret_wrapped_dek,
                    nonce: <[u8; 12]>::try_from(r.secret_nonce).map_err(|_| StoreError::Corrupt)?,
                    ciphertext: r.secret_sealed,
                },
            })
        })
        .collect()
}

/// The remote id of local resource `local` of `kind` at `target`.
///
/// # Errors
/// [`StoreError`].
pub async fn link(
    t: &mut TenantTx,
    target: &str,
    kind: &str,
    local: [u8; 16],
) -> Result<Option<String>, StoreError> {
    let (tenant, realm) = scope(t)?;
    Ok(sqlx::query_scalar!(
        "SELECT remote_id FROM access.scim_target_links
          WHERE tenant_id = $1 AND realm_id = $2 AND target = $3 AND kind = $4 AND local_id = $5",
        tenant,
        realm,
        target,
        kind,
        Uuid::from_bytes(local),
    )
    .fetch_optional(&mut *t.tx)
    .await?)
}

/// Records where local resource `local` lives at `target`; the first record stays.
///
/// # Errors
/// [`StoreError`].
pub async fn put_link(
    t: &mut TenantTx,
    target: &str,
    kind: &str,
    local: [u8; 16],
    remote: &str,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.scim_target_links (tenant_id, realm_id, target, kind, local_id, remote_id)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        tenant,
        realm,
        target,
        kind,
        Uuid::from_bytes(local),
        remote,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// One push and the target's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushLog<'a> {
    /// The target.
    pub target: &'a str,
    /// `user` or `group`.
    pub kind: &'a str,
    /// The local resource.
    pub local: [u8; 16],
    /// `create`, `replace`, `deactivate` or `delete`.
    pub operation: &'a str,
    /// The HTTP status, when the target answered.
    pub status: Option<u16>,
    /// `done`, `retry` or `failed`.
    pub outcome: &'a str,
    /// Which attempt.
    pub attempt: u32,
}

/// Logs a push.
///
/// # Errors
/// [`StoreError`].
pub async fn log_push(t: &mut TenantTx, p: &PushLog<'_>) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.scim_outbound_log (tenant_id, realm_id, target, kind, local_id,
                operation, status, outcome, attempt)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        tenant,
        realm,
        p.target,
        p.kind,
        Uuid::from_bytes(p.local),
        p.operation,
        p.status.map(i32::from),
        p.outcome,
        i32::try_from(p.attempt).map_err(|_| StoreError::Range)?,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The target's pushes, newest first, as `(kind, local, operation, status, outcome, attempt)`.
///
/// # Errors
/// [`StoreError`].
pub async fn pushes(
    t: &mut TenantTx,
    target: &str,
    limit: i64,
) -> Result<Vec<(String, [u8; 16], String, Option<u16>, String, u32)>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        "SELECT kind, local_id, operation, status, outcome, attempt FROM access.scim_outbound_log
          WHERE tenant_id = $1 AND realm_id = $2 AND target = $3
          ORDER BY entry_id DESC LIMIT $4",
        tenant,
        realm,
        target,
        limit,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok((
                r.kind,
                *r.local_id.as_bytes(),
                r.operation,
                r.status.and_then(|s| u16::try_from(s).ok()),
                r.outcome,
                u32::try_from(r.attempt).map_err(|_| StoreError::Corrupt)?,
            ))
        })
        .collect()
}
