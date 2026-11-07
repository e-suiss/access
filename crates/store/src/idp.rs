//! Identity plane configuration (MD-14, E34, EI-25, OP-146 I10): clients, realm settings and
//! claim mappers. Every write names a committed ALLOW of an `idp.*` action that was bound in
//! the same transaction; the database refuses any other write.

pub mod realm;

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::scope::DomainId;

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn int(v: u32) -> Result<i32, StoreError> {
    i32::try_from(v).map_err(|_| StoreError::Range)
}

fn uint(v: i32) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

/// The Party a session subject's device Instances belong to, when its registration has
/// committed (OP-149 m.16 (a)).
///
/// # Errors
/// [`StoreError`].
pub async fn subject_party(
    t: &mut TenantTx,
    subject: &[u8; 16],
) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query_scalar!(
        "SELECT party_id FROM access.subject_party
          WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3",
        tenant,
        realm,
        Uuid::from_bytes(*subject),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|p| <[u8; 16]>::try_from(p.as_slice()).map_err(|_| StoreError::Corrupt))
        .transpose()
}

/// The session subject bound to `party` in this realm (OP-149 m.16 (a), A11).
///
/// # Errors
/// [`StoreError`].
pub async fn party_subject(
    t: &mut TenantTx,
    party: &[u8; 16],
) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query_scalar!(
        "SELECT subject_id FROM access.subject_party
          WHERE tenant_id = $1 AND realm_id = $2 AND party_id = $3",
        tenant,
        realm,
        party.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(row.map(|s| *s.as_bytes()))
}

/// Records that `subject`'s device Instances belong to `party`; `false` when the subject or the
/// Party is bound already. Never changed afterwards.
///
/// # Errors
/// [`StoreError`].
pub async fn bind_subject_party(
    t: &mut TenantTx,
    subject: &[u8; 16],
    party: &[u8; 16],
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "INSERT INTO access.subject_party (tenant_id, realm_id, subject_id, party_id)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        tenant,
        realm,
        Uuid::from_bytes(*subject),
        party.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// A committed ALLOW as the identity plane binds it (EI-25).
pub struct Decision<'a> {
    /// The realm's governing domain.
    pub domain: &'a DomainId,
    /// Position of the decision record.
    pub position: u64,
    /// The Exercise nonce.
    pub nonce: &'a [u8],
    /// The intent digest of the decision.
    pub intent: [u8; 32],
    /// The digest of the change the intent binds.
    pub change: [u8; 32],
    /// The `idp.*` action label.
    pub action: &'a str,
}

/// A decision bound in this transaction: the only way to write configuration. Deliberately
/// neither `Clone` nor constructible outside this module.
pub struct Bound {
    domain: DomainId,
    position: i64,
}

impl Bound {
    /// The decision's position.
    #[must_use]
    pub fn position(&self) -> u64 {
        u64::try_from(self.position).unwrap_or(0)
    }
}

/// A realm as its configuration is governed (MD-5a).
pub struct Governing {
    /// The governing domain.
    pub domain: DomainId,
    /// The slug.
    pub slug: String,
    /// The issuer, once set.
    pub issuer: Option<String>,
}

/// The transaction realm's governing domain, slug and issuer, when the realm is active.
///
/// # Errors
/// [`StoreError`]; [`StoreError::Range`] for a transaction without a realm.
pub async fn governance(t: &mut TenantTx) -> Result<Option<Governing>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT governing_domain_id, slug, issuer FROM access.realms
          WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active'",
        tenant,
        realm,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        let d = <[u8; 32]>::try_from(r.governing_domain_id.as_slice())
            .map_err(|_| StoreError::Corrupt)?;
        Ok(Governing {
            domain: DomainId::from_bytes(d),
            slug: r.slug,
            issuer: r.issuer,
        })
    })
    .transpose()
}

/// Binds a committed ALLOW to the transaction's realm. `None` when it is already bound: a
/// retry of a decision already applied.
///
/// # Errors
/// [`StoreError`]; a decision that is not an ALLOW of this intent in the realm's governing
/// domain fails in the database.
pub async fn bind(t: &mut TenantTx, d: &Decision<'_>) -> Result<Option<Bound>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let position = signed(d.position)?;
    let bound = sqlx::query_scalar!(
        r#"INSERT INTO access.idp_config_log
             (tenant_id, realm_id, domain_id, decision_pos, nonce, intent_digest, change_digest, action)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (tenant_id, domain_id, decision_pos) DO NOTHING
           RETURNING decision_pos"#,
        tenant,
        realm,
        d.domain.as_bytes().as_slice(),
        position,
        d.nonce,
        d.intent.as_slice(),
        d.change.as_slice(),
        d.action,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(bound.map(|position| Bound {
        domain: *d.domain,
        position,
    }))
}

/// A fresh `UUIDv7` from the database (MD-18).
///
/// # Errors
/// [`StoreError`].
pub async fn new_uuid(pool: &sqlx::PgPool) -> Result<[u8; 16], StoreError> {
    let id = sqlx::query_scalar!(r#"SELECT uuidv7() AS "id!""#)
        .fetch_one(pool)
        .await?;
    Ok(*id.as_bytes())
}

/// A client as stored (TN-15, IDP-7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRow {
    /// Internal id.
    pub client_uuid: [u8; 16],
    /// The opaque `client_id` (OP-137).
    pub client_id: String,
    /// Display name, apart from the id.
    pub display_name: String,
    /// `token_endpoint_auth_method`.
    pub auth_method: String,
    /// The client's JWKS for `private_key_jwt`.
    pub jwks_uri: Option<String>,
    /// Redirect URIs, exact strings.
    pub redirect_uris: Vec<String>,
    /// Whether it is active.
    pub active: bool,
    /// SHA-256 of the server-generated secret, for `client_secret_basic` (CR-38).
    pub secret_hash: Option<[u8; 32]>,
    /// Post-logout redirect URIs, exact strings (§10.4.6).
    pub post_logout_redirect_uris: Vec<String>,
    /// The back-channel logout endpoint (§10.4.6).
    pub backchannel_logout_uri: Option<String>,
    /// A one-key JWKS for `private_key_jwt`, instead of a JWKS URI (OP-149 m.4).
    pub jwks: Option<String>,
    /// The platform product the client pairs (OP-149 m.4).
    pub platform_product: Option<String>,
    /// The `COSE_Key` of the product's service Instance in each tenant (OP-149 m.4).
    pub service_key: Option<Vec<u8>>,
    /// Where the platform product receives Access events by SSF push (OP-149 m.4).
    pub event_receiver: Option<String>,
    /// Whether its authorization requests are accepted only from `/par` (RFC 9126 §6).
    pub require_par: bool,
}

/// Inserts a client under `bound`.
///
/// # Errors
/// [`StoreError`]; a `client_id` ever used before fails (TN-20, INV-32).
pub async fn insert_client(
    t: &mut TenantTx,
    bound: &Bound,
    c: &ClientRow,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_clients (tenant_id, realm_id, client_uuid, client_id, display_name,
                auth_method, jwks_uri, redirect_uris, domain_id, decision_pos, secret_hash,
                post_logout_redirect_uris, backchannel_logout_uri, jwks, platform_product,
                service_key, suiss_event_receiver, require_pushed_authorization_requests)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
        tenant,
        realm,
        Uuid::from_bytes(c.client_uuid),
        c.client_id,
        c.display_name,
        c.auth_method,
        c.jwks_uri,
        &c.redirect_uris,
        bound.domain.as_bytes().as_slice(),
        bound.position,
        c.secret_hash.as_ref().map(<[u8; 32]>::as_slice),
        &c.post_logout_redirect_uris,
        c.backchannel_logout_uri,
        c.jwks,
        c.platform_product,
        c.service_key.as_deref(),
        c.event_receiver,
        c.require_par,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Replaces an active client's name, method and redirect URIs under `bound`.
///
/// # Errors
/// [`StoreError`].
pub async fn update_client(
    t: &mut TenantTx,
    bound: &Bound,
    c: &ClientRow,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.idp_clients SET display_name = $4, auth_method = $5, jwks_uri = $6,
                redirect_uris = $7, domain_id = $8, decision_pos = $9, secret_hash = $10,
                post_logout_redirect_uris = $11, backchannel_logout_uri = $12, jwks = $13,
                platform_product = $14, service_key = $15, suiss_event_receiver = $16,
                require_pushed_authorization_requests = $17
          WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND status = 'active'",
        tenant,
        realm,
        c.client_id,
        c.display_name,
        c.auth_method,
        c.jwks_uri,
        &c.redirect_uris,
        bound.domain.as_bytes().as_slice(),
        bound.position,
        c.secret_hash.as_ref().map(<[u8; 32]>::as_slice),
        &c.post_logout_redirect_uris,
        c.backchannel_logout_uri,
        c.jwks,
        c.platform_product,
        c.service_key.as_deref(),
        c.event_receiver,
        c.require_par,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Retires an active client under `bound`; its id stays taken (OP-73, INV-32).
///
/// # Errors
/// [`StoreError`].
pub async fn retire_client(
    t: &mut TenantTx,
    bound: &Bound,
    client_id: &str,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.idp_clients SET status = 'retired', retired_at = now(), domain_id = $4,
                decision_pos = $5
          WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND status = 'active'",
        tenant,
        realm,
        client_id,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// The realm's client with `client_id`, active or retired.
///
/// # Errors
/// [`StoreError`].
pub async fn client(t: &mut TenantTx, client_id: &str) -> Result<Option<ClientRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT client_uuid, client_id, display_name, auth_method, jwks_uri, redirect_uris, status,
                secret_hash, post_logout_redirect_uris, backchannel_logout_uri, jwks,
                platform_product, service_key, suiss_event_receiver,
                require_pushed_authorization_requests
           FROM access.idp_clients WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3",
        tenant,
        realm,
        client_id,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(ClientRow {
            client_uuid: *r.client_uuid.as_bytes(),
            client_id: r.client_id,
            display_name: r.display_name,
            auth_method: r.auth_method,
            jwks_uri: r.jwks_uri,
            redirect_uris: r.redirect_uris,
            active: r.status == "active",
            secret_hash: r
                .secret_hash
                .map(|h| <[u8; 32]>::try_from(h.as_slice()).map_err(|_| StoreError::Corrupt))
                .transpose()?,
            post_logout_redirect_uris: r.post_logout_redirect_uris,
            backchannel_logout_uri: r.backchannel_logout_uri,
            jwks: r.jwks,
            platform_product: r.platform_product,
            service_key: r.service_key,
            event_receiver: r.suiss_event_receiver,
            require_par: r.require_pushed_authorization_requests,
        })
    })
    .transpose()
}

/// An active platform product client as the authorization server of any realm sees it (OP-149
/// m.26 (a), (f), m.34 (b)): its internal id, the pairwise sector of the `sub`s it reads, and its
/// product.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformClient {
    /// Internal id.
    pub client_uuid: [u8; 16],
    /// The product (`work`, `relay`, …).
    pub product: String,
}

/// The active platform product client `client_id`, in whichever tenant it is registered, as the
/// outbox reader sees it (OP-149 m.26 (a)); `None` for any other client id.
///
/// # Errors
/// [`StoreError`].
pub async fn platform_client_product(
    reader: &sqlx::PgPool,
    client_id: &str,
) -> Result<Option<PlatformClient>, StoreError> {
    let row = sqlx::query!(
        "SELECT client_uuid, platform_product FROM access.idp_clients
          WHERE client_id = $1 AND platform_product IS NOT NULL AND status = 'active'",
        client_id,
    )
    .fetch_optional(reader)
    .await?;
    Ok(row.and_then(|r| {
        r.platform_product.map(|product| PlatformClient {
            client_uuid: *r.client_uuid.as_bytes(),
            product,
        })
    }))
}

/// The active platform product clients, in whichever tenant they are registered, with
/// `redirect_uri` among their registered redirect URIs, exactly (RFC 6749 §3.1.2), as the
/// outbox reader sees them (OP-149 m.33 (d)): the products whose approval return address this
/// is; empty for any other address.
///
/// # Errors
/// [`StoreError`].
pub async fn platform_clients_with_redirect(
    reader: &sqlx::PgPool,
    redirect_uri: &str,
) -> Result<Vec<String>, StoreError> {
    Ok(sqlx::query_scalar!(
        "SELECT client_id FROM access.idp_clients
          WHERE platform_product IS NOT NULL AND status = 'active' AND $1 = ANY (redirect_uris)
          ORDER BY client_id",
        redirect_uri,
    )
    .fetch_all(reader)
    .await?)
}

/// The active clients of the realm that registered `redirect_uri` exactly (IDP-7).
///
/// # Errors
/// [`StoreError`].
pub async fn clients_with_redirect(
    t: &mut TenantTx,
    redirect_uri: &str,
) -> Result<Vec<String>, StoreError> {
    let (tenant, realm) = scope(t)?;
    Ok(sqlx::query_scalar!(
        "SELECT client_id FROM access.idp_clients
          WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active' AND $3 = ANY (redirect_uris)
          ORDER BY client_id",
        tenant,
        realm,
        redirect_uri,
    )
    .fetch_all(&mut *t.tx)
    .await?)
}

/// The realm's client with internal id `uuid`, active or retired.
///
/// # Errors
/// [`StoreError`].
pub async fn client_by_uuid(
    t: &mut TenantTx,
    uuid: [u8; 16],
) -> Result<Option<ClientRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let id = sqlx::query_scalar!(
        "SELECT client_id FROM access.idp_clients
          WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3",
        tenant,
        realm,
        Uuid::from_bytes(uuid),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    match id {
        Some(id) => client(t, &id).await,
        None => Ok(None),
    }
}

/// A realm's settings (OP-146 m.4 (f), m.8 (e), IDP-5, §11.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsRow {
    /// JOSE signing algorithm of the realm's tokens.
    pub jose_alg: String,
    /// Argon2id memory in KiB.
    pub argon2_m_kib: u32,
    /// Argon2id passes.
    pub argon2_t: u32,
    /// Argon2id lanes.
    pub argon2_p: u32,
    /// The pinned WebAuthn RP ID.
    pub rp_id: Option<String>,
    /// Whether CIMD clients are accepted.
    pub cimd_enabled: bool,
    /// Domains whose CIMD clients are accepted.
    pub cimd_domains: Vec<String>,
}

/// Writes the Genesis defaults of the transaction's realm.
///
/// # Errors
/// [`StoreError`].
pub async fn create_settings(t: &mut TenantTx) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_realm_settings (tenant_id, realm_id) VALUES ($1, $2)",
        tenant,
        realm,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The transaction realm's settings.
///
/// # Errors
/// [`StoreError`].
pub async fn settings(t: &mut TenantTx) -> Result<Option<SettingsRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT jose_alg, argon2_m_kib, argon2_t, argon2_p, rp_id, cimd_enabled, cimd_domains
           FROM access.idp_realm_settings WHERE tenant_id = $1 AND realm_id = $2",
        tenant,
        realm,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(SettingsRow {
            jose_alg: r.jose_alg,
            argon2_m_kib: uint(r.argon2_m_kib)?,
            argon2_t: uint(r.argon2_t)?,
            argon2_p: uint(r.argon2_p)?,
            rp_id: r.rp_id,
            cimd_enabled: r.cimd_enabled,
            cimd_domains: r.cimd_domains,
        })
    })
    .transpose()
}

/// Replaces the transaction realm's settings under `bound`.
///
/// # Errors
/// [`StoreError`]; lower Argon2 parameters fail (OP-33).
pub async fn update_settings(
    t: &mut TenantTx,
    bound: &Bound,
    s: &SettingsRow,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.idp_realm_settings SET jose_alg = $3, argon2_m_kib = $4, argon2_t = $5,
                argon2_p = $6, rp_id = $7, cimd_enabled = $8, cimd_domains = $9, domain_id = $10,
                decision_pos = $11
          WHERE tenant_id = $1 AND realm_id = $2",
        tenant,
        realm,
        s.jose_alg,
        int(s.argon2_m_kib)?,
        int(s.argon2_t)?,
        int(s.argon2_p)?,
        s.rp_id,
        s.cimd_enabled,
        &s.cimd_domains,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Sets the mapper of `claim` to `source` under `bound`; `None` removes it.
///
/// # Errors
/// [`StoreError`]; a reserved claim fails (must-never #18).
pub async fn set_mapper(
    t: &mut TenantTx,
    bound: &Bound,
    claim: &str,
    source: Option<&str>,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_claim_mappers (tenant_id, realm_id, claim, source, status,
                removed_at, domain_id, decision_pos)
         VALUES ($1, $2, $3, $4, CASE WHEN $4::text IS NULL THEN 'removed' ELSE 'active' END,
                 CASE WHEN $4::text IS NULL THEN now() END, $5, $6)
         ON CONFLICT (tenant_id, realm_id, claim) DO UPDATE
            SET source = EXCLUDED.source, status = EXCLUDED.status,
                removed_at = EXCLUDED.removed_at, domain_id = EXCLUDED.domain_id,
                decision_pos = EXCLUDED.decision_pos",
        tenant,
        realm,
        claim,
        source,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The realm's active mappers as `(claim, source)`, by claim.
///
/// # Errors
/// [`StoreError`].
pub async fn mappers(t: &mut TenantTx) -> Result<Vec<(String, String)>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        r#"SELECT claim, source AS "source!" FROM access.idp_claim_mappers
            WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active' ORDER BY claim"#,
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    Ok(rows.into_iter().map(|r| (r.claim, r.source)).collect())
}

/// Writes the realm's branding under `bound` (TN-106); `branding` is its deterministic CBOR.
///
/// # Errors
/// [`StoreError`].
pub async fn set_branding(
    t: &mut TenantTx,
    bound: &Bound,
    branding: &[u8],
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_realm_branding (tenant_id, realm_id, branding, domain_id,
                decision_pos)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (tenant_id, realm_id) DO UPDATE
            SET branding = EXCLUDED.branding, domain_id = EXCLUDED.domain_id,
                decision_pos = EXCLUDED.decision_pos",
        tenant,
        realm,
        branding,
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The realm's branding as its deterministic CBOR, once one was decided.
///
/// # Errors
/// [`StoreError`].
pub async fn branding(t: &mut TenantTx) -> Result<Option<Vec<u8>>, StoreError> {
    let (tenant, realm) = scope(t)?;
    Ok(sqlx::query_scalar!(
        "SELECT branding FROM access.idp_realm_branding WHERE tenant_id = $1 AND realm_id = $2",
        tenant,
        realm,
    )
    .fetch_optional(&mut *t.tx)
    .await?)
}

/// A decided change of the realm's JOSE keys (TN-118, §13.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyChange {
    /// `idp.realm.key_policy`, `idp.realm.key_rotate` or `idp.realm.key_drop`.
    pub action: String,
    /// The key rotated out or dropped.
    pub kid: Option<[u8; 32]>,
    /// The new policy, deterministic CBOR.
    pub policy: Option<Vec<u8>>,
    /// When the dropped key was compromised, if known, ms.
    pub compromised_at: Option<u64>,
    /// When the change was written, ms.
    pub declared_at: u64,
    /// The issuer cutoff a drop declares, ms (§13.7.7).
    pub cutoff_at: Option<u64>,
}

fn opt_signed(v: Option<u64>) -> Result<Option<i64>, StoreError> {
    v.map(signed).transpose()
}

fn opt_unsigned(v: Option<i64>) -> Result<Option<u64>, StoreError> {
    v.map(|n| u64::try_from(n).map_err(|_| StoreError::Corrupt))
        .transpose()
}

fn kid32(k: &[u8]) -> Result<[u8; 32], StoreError> {
    k.try_into().map_err(|_| StoreError::Corrupt)
}

/// Records a decided key change under `bound`.
///
/// # Errors
/// [`StoreError`].
pub async fn record_key_change(
    t: &mut TenantTx,
    bound: &Bound,
    c: &KeyChange,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_realm_key_changes (tenant_id, realm_id, domain_id, decision_pos,
                action, kid, policy, compromised_at_ms, declared_at_ms, cutoff_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        tenant,
        realm,
        bound.domain.as_bytes().as_slice(),
        bound.position,
        c.action,
        c.kid.as_ref().map(<[u8; 32]>::as_slice),
        c.policy.as_deref(),
        opt_signed(c.compromised_at)?,
        signed(c.declared_at)?,
        opt_signed(c.cutoff_at)?,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The realm's decided key changes, oldest first.
///
/// # Errors
/// [`StoreError`].
pub async fn key_changes(t: &mut TenantTx) -> Result<Vec<KeyChange>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        "SELECT action, kid, policy, compromised_at_ms, declared_at_ms, cutoff_at_ms
           FROM access.idp_realm_key_changes WHERE tenant_id = $1 AND realm_id = $2
          ORDER BY declared_at_ms, decision_pos",
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(KeyChange {
                action: r.action,
                kid: r.kid.as_deref().map(kid32).transpose()?,
                policy: r.policy,
                compromised_at: opt_unsigned(r.compromised_at_ms)?,
                declared_at: u64::try_from(r.declared_at_ms).map_err(|_| StoreError::Corrupt)?,
                cutoff_at: opt_unsigned(r.cutoff_at_ms)?,
            })
        })
        .collect()
}
