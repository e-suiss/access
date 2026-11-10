//! A realm's custom domains, their ACME orders and certificates (OP-156 m.3 (i), TN-16, TN-20).
//! A registration is written under a committed `idp.domain.register` ALLOW; the verification
//! check moves its state without a decision; retiring and binding it need their own ALLOWs. A
//! certificate's key is stored sealed and is crypto-shredded when the certificate ends (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::events::SealedKey;
use crate::identity::{RealmId, TenantId, TenantTx};
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

/// A new registration.
pub struct NewDomain<'a> {
    /// Its id.
    pub id: [u8; 16],
    /// The host.
    pub hostname: &'a str,
    /// The TXT challenge value.
    pub challenge: &'a str,
    /// The realm hostname its CNAME must name.
    pub cname_target: &'a str,
}

/// A registration as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainRow {
    /// Its id.
    pub id: [u8; 16],
    /// The host.
    pub hostname: String,
    /// The TXT challenge value.
    pub challenge: String,
    /// The realm hostname its CNAME must name.
    pub cname_target: String,
    /// `pending`, `verified`, `lapsed`, `expired` or `retired`.
    pub status: String,
    /// The last check's finding code.
    pub finding: Option<String>,
    /// Unix seconds.
    pub registered_at: i64,
    /// Unix seconds.
    pub checked_at: Option<i64>,
    /// Unix seconds.
    pub verified_at: Option<i64>,
    /// Unix seconds.
    pub reverify_by: Option<i64>,
    /// `issuer` or `rp_id` once bound.
    pub bound_as: Option<String>,
    /// Consecutive failed ACME orders.
    pub acme_failures: u32,
    /// No ACME order before this, Unix seconds.
    pub acme_next_at: Option<i64>,
    /// The last failed order's code.
    pub acme_error: Option<String>,
    /// The registering decision's position.
    pub decision_pos: u64,
}

macro_rules! row {
    ($r:expr) => {{
        let r = $r;
        DomainRow {
            id: *r.domain_uuid.as_bytes(),
            hostname: r.hostname,
            challenge: r.challenge,
            cname_target: r.cname_target,
            status: r.status,
            finding: r.finding,
            registered_at: r.registered_s,
            checked_at: r.checked_s,
            verified_at: r.verified_s,
            reverify_by: r.reverify_s,
            bound_as: r.bound_as,
            acme_failures: u32::try_from(r.acme_failures).map_err(|_| StoreError::Corrupt)?,
            acme_next_at: r.acme_next_s,
            acme_error: r.acme_error,
            decision_pos: u64::try_from(r.decision_pos).map_err(|_| StoreError::Corrupt)?,
        }
    }};
}

/// Registers a custom domain under `bound` (`idp.domain.register`).
///
/// # Errors
/// [`StoreError`]; a host already registered and live in the realm fails its integrity check.
pub async fn register(
    t: &mut TenantTx,
    bound: &Bound,
    d: &NewDomain<'_>,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.realm_domains (tenant_id, realm_id, domain_uuid, hostname, challenge,
                cname_target, domain_id, decision_pos)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        tenant,
        realm,
        Uuid::from_bytes(d.id),
        d.hostname,
        d.challenge,
        d.cname_target,
        bound.domain().as_bytes().as_slice(),
        bound.raw_position(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Every registration of the realm, newest first.
///
/// # Errors
/// [`StoreError`].
pub async fn domains(t: &mut TenantTx) -> Result<Vec<DomainRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        r#"SELECT domain_uuid, hostname, challenge, cname_target, status, finding,
                extract(epoch FROM registered_at)::bigint AS "registered_s!",
                extract(epoch FROM checked_at)::bigint AS checked_s,
                extract(epoch FROM verified_at)::bigint AS verified_s,
                extract(epoch FROM reverify_by)::bigint AS reverify_s, bound_as, acme_failures,
                extract(epoch FROM acme_next_at)::bigint AS acme_next_s, acme_error, decision_pos
           FROM access.realm_domains WHERE tenant_id = $1 AND realm_id = $2
          ORDER BY registered_at DESC, domain_uuid"#,
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter().map(|r| Ok(row!(r))).collect()
}

/// The registration `id`, read for update.
///
/// # Errors
/// [`StoreError`].
pub async fn domain(t: &mut TenantTx, id: [u8; 16]) -> Result<Option<DomainRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let r = sqlx::query!(
        r#"SELECT domain_uuid, hostname, challenge, cname_target, status, finding,
                extract(epoch FROM registered_at)::bigint AS "registered_s!",
                extract(epoch FROM checked_at)::bigint AS checked_s,
                extract(epoch FROM verified_at)::bigint AS verified_s,
                extract(epoch FROM reverify_by)::bigint AS reverify_s, bound_as, acme_failures,
                extract(epoch FROM acme_next_at)::bigint AS acme_next_s, acme_error, decision_pos
           FROM access.realm_domains WHERE tenant_id = $1 AND realm_id = $2 AND domain_uuid = $3
            FOR UPDATE"#,
        tenant,
        realm,
        Uuid::from_bytes(id),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    r.map(|r| Ok(row!(r))).transpose()
}

/// The live registration of `hostname` in the realm, if any.
///
/// # Errors
/// [`StoreError`].
pub async fn live_by_host(
    t: &mut TenantTx,
    hostname: &str,
) -> Result<Option<DomainRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let r = sqlx::query!(
        r#"SELECT domain_uuid, hostname, challenge, cname_target, status, finding,
                extract(epoch FROM registered_at)::bigint AS "registered_s!",
                extract(epoch FROM checked_at)::bigint AS checked_s,
                extract(epoch FROM verified_at)::bigint AS verified_s,
                extract(epoch FROM reverify_by)::bigint AS reverify_s, bound_as, acme_failures,
                extract(epoch FROM acme_next_at)::bigint AS acme_next_s, acme_error, decision_pos
           FROM access.realm_domains
          WHERE tenant_id = $1 AND realm_id = $2 AND hostname = $3
            AND status IN ('pending', 'verified', 'lapsed')"#,
        tenant,
        realm,
        hostname,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    r.map(|r| Ok(row!(r))).transpose()
}

/// The hosts the realm holds verified now (the RP ID rule, OP-156 m.3 (i)).
///
/// # Errors
/// [`StoreError`].
pub async fn verified_hosts(t: &mut TenantTx) -> Result<Vec<String>, StoreError> {
    let (tenant, realm) = scope(t)?;
    Ok(sqlx::query_scalar!(
        "SELECT hostname FROM access.realm_domains
          WHERE tenant_id = $1 AND realm_id = $2 AND status = 'verified'
            AND reverify_by > clock_timestamp()
          ORDER BY hostname",
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?)
}

/// What a verification check found.
pub struct Checked<'a> {
    /// The registration.
    pub id: [u8; 16],
    /// Its new status.
    pub status: &'a str,
    /// The finding code.
    pub finding: &'a str,
    /// Its new `reverify_by`, Unix seconds.
    pub reverify_by: Option<i64>,
    /// The check's time, Unix seconds.
    pub now: i64,
}

/// Records a check. A registration another realm holds verified fails the integrity check and
/// stays as it was (TN-20).
///
/// # Errors
/// [`StoreError`].
pub async fn record_check(t: &mut TenantTx, c: &Checked<'_>) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.realm_domains
            SET status = $4, finding = $5, checked_at = to_timestamp($6::bigint),
                reverify_by = to_timestamp($7::bigint),
                verified_at = CASE WHEN $4 = 'verified' AND status <> 'verified'
                                   THEN to_timestamp($6::bigint) ELSE verified_at END
          WHERE tenant_id = $1 AND realm_id = $2 AND domain_uuid = $3
            AND status IN ('pending', 'verified', 'lapsed')",
        tenant,
        realm,
        Uuid::from_bytes(c.id),
        c.status,
        c.finding,
        c.now,
        c.reverify_by,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Retires registration `id` under `bound` (`idp.domain.retire`) and withdraws its certificate.
///
/// # Errors
/// [`StoreError`].
pub async fn retire(t: &mut TenantTx, bound: &Bound, id: [u8; 16]) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.realm_domains
            SET status = 'retired', retire_pos = $4, retired_at = clock_timestamp()
          WHERE tenant_id = $1 AND realm_id = $2 AND domain_uuid = $3 AND domain_id = $5
            AND status IN ('pending', 'verified', 'lapsed') AND bound_as IS NULL",
        tenant,
        realm,
        Uuid::from_bytes(id),
        bound.raw_position(),
        bound.domain().as_bytes().as_slice(),
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    if done == 1 {
        end_certificates(t, id, "withdrawn").await?;
    }
    Ok(done == 1)
}

/// Binds verified registration `id` as the realm's `issuer` or `rp_id` under `bound`
/// (`idp.domain.issuer_bind`); a binding never comes undone.
///
/// # Errors
/// [`StoreError`].
pub async fn bind(
    t: &mut TenantTx,
    bound: &Bound,
    id: [u8; 16],
    as_: &str,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.realm_domains
            SET bound_as = $4, bind_pos = $5, bound_at = clock_timestamp()
          WHERE tenant_id = $1 AND realm_id = $2 AND domain_uuid = $3 AND domain_id = $6
            AND status = 'verified' AND reverify_by > clock_timestamp() AND bound_as IS NULL",
        tenant,
        realm,
        Uuid::from_bytes(id),
        as_,
        bound.raw_position(),
        bound.domain().as_bytes().as_slice(),
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Whether the realm was ever activated: it ever registered an OAuth client or a SAML service
/// provider (the issuer stays fixed from then on, TN-16, OP-156 m.3 (i)).
///
/// # Errors
/// [`StoreError`].
pub async fn activated(t: &mut TenantTx) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM access.idp_clients WHERE tenant_id = $1 AND realm_id = $2)
               OR EXISTS (SELECT 1 FROM access.saml_sps WHERE tenant_id = $1 AND realm_id = $2)
               AS "activated!""#,
        tenant,
        realm,
    )
    .fetch_one(&mut *t.tx)
    .await?)
}

/// Moves the realm's issuer from `from` to `to` (`idp.domain.issuer_bind` before the first
/// activation, OP-156 m.3 (i)); only the stored issuer `from` is replaced.
///
/// # Errors
/// [`StoreError`].
pub async fn rebind_issuer(t: &mut TenantTx, from: &str, to: &str) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.realms SET issuer = $4
          WHERE tenant_id = $1 AND realm_id = $2 AND issuer = $3 AND status = 'active'",
        tenant,
        realm,
        from,
        to,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Records the outcome of an ACME order for registration `id`.
///
/// # Errors
/// [`StoreError`].
pub async fn record_acme(
    t: &mut TenantTx,
    id: [u8; 16],
    failures: u32,
    next_at: Option<i64>,
    error: Option<&str>,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "UPDATE access.realm_domains
            SET acme_failures = $4, acme_next_at = to_timestamp($5::bigint), acme_error = $6
          WHERE tenant_id = $1 AND realm_id = $2 AND domain_uuid = $3",
        tenant,
        realm,
        Uuid::from_bytes(id),
        i32::try_from(failures).map_err(|_| StoreError::Range)?,
        next_at,
        error,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Opens an order whose TLS-ALPN-01 challenge for `hostname` is served while it is open.
///
/// # Errors
/// [`StoreError`]; another open order for the host fails its integrity check.
pub async fn open_order(
    t: &mut TenantTx,
    order: [u8; 16],
    domain: [u8; 16],
    hostname: &str,
    digest: &[u8; 32],
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.acme_orders (tenant_id, realm_id, order_uuid, domain_uuid, hostname,
                alpn_digest)
         VALUES ($1, $2, $3, $4, $5, $6)",
        tenant,
        realm,
        Uuid::from_bytes(order),
        Uuid::from_bytes(domain),
        hostname,
        digest.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Closes the open orders of `hostname` in the realm as `valid` or `failed`.
///
/// # Errors
/// [`StoreError`].
pub async fn close_orders(
    t: &mut TenantTx,
    hostname: &str,
    status: &str,
    error: Option<&str>,
) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    Ok(sqlx::query!(
        "UPDATE access.acme_orders SET status = $4, error = $5, ended_at = clock_timestamp()
          WHERE tenant_id = $1 AND realm_id = $2 AND hostname = $3 AND status = 'challenging'",
        tenant,
        realm,
        hostname,
        status,
        error,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected())
}

/// A certificate to store.
pub struct NewCertificate<'a> {
    /// Its id.
    pub id: [u8; 16],
    /// The registration.
    pub domain: [u8; 16],
    /// The host.
    pub hostname: &'a str,
    /// The chain, PEM.
    pub chain_pem: &'a str,
    /// Its key, sealed under the realm KEK.
    pub key: &'a SealedKey,
    /// Unix seconds.
    pub not_before: i64,
    /// Unix seconds.
    pub not_after: i64,
    /// Unix seconds.
    pub renew_after: i64,
}

async fn end_certificates(
    t: &mut TenantTx,
    domain: [u8; 16],
    status: &str,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "UPDATE access.domain_certificates
            SET status = $4, ended_at = clock_timestamp(), kek_id = NULL, wrapped_dek = NULL,
                key_nonce = NULL, key_sealed = NULL
          WHERE tenant_id = $1 AND realm_id = $2 AND domain_uuid = $3 AND status = 'active'",
        tenant,
        realm,
        Uuid::from_bytes(domain),
        status,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Stores the registration's new certificate; the one it replaces is superseded and its key
/// shredded (OP-73).
///
/// # Errors
/// [`StoreError`].
pub async fn put_certificate(t: &mut TenantTx, c: &NewCertificate<'_>) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    end_certificates(t, c.domain, "superseded").await?;
    sqlx::query!(
        "INSERT INTO access.domain_certificates (tenant_id, realm_id, cert_uuid, domain_uuid,
                hostname, chain_pem, kek_id, wrapped_dek, key_nonce, key_sealed, not_before,
                not_after, renew_after)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, to_timestamp($11::bigint),
                 to_timestamp($12::bigint), to_timestamp($13::bigint))",
        tenant,
        realm,
        Uuid::from_bytes(c.id),
        Uuid::from_bytes(c.domain),
        c.hostname,
        c.chain_pem,
        c.key.kek_id,
        c.key.wrapped_dek,
        c.key.nonce.as_slice(),
        c.key.ciphertext,
        c.not_before,
        c.not_after,
        c.renew_after,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// An active certificate.
pub struct CertificateRow {
    /// Its id.
    pub id: [u8; 16],
    /// The registration.
    pub domain: [u8; 16],
    /// The host.
    pub hostname: String,
    /// The chain, PEM.
    pub chain_pem: String,
    /// Its sealed key.
    pub key: SealedKey,
    /// Unix seconds.
    pub not_after: i64,
    /// Unix seconds.
    pub renew_after: i64,
}

impl core::fmt::Debug for CertificateRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CertificateRow")
            .field("hostname", &self.hostname)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

/// The realm's active certificates.
///
/// # Errors
/// [`StoreError`].
pub async fn active_certificates(t: &mut TenantTx) -> Result<Vec<CertificateRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        r#"SELECT cert_uuid, domain_uuid, hostname, chain_pem, kek_id AS "kek_id!",
                  wrapped_dek AS "wrapped_dek!", key_nonce AS "key_nonce!",
                  key_sealed AS "key_sealed!",
                  extract(epoch FROM not_after)::bigint AS "not_after_s!",
                  extract(epoch FROM renew_after)::bigint AS "renew_after_s!"
             FROM access.domain_certificates
            WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active'
            ORDER BY hostname"#,
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(CertificateRow {
                id: *r.cert_uuid.as_bytes(),
                domain: *r.domain_uuid.as_bytes(),
                hostname: r.hostname,
                chain_pem: r.chain_pem,
                key: SealedKey {
                    kek_id: r.kek_id,
                    wrapped_dek: r.wrapped_dek,
                    nonce: <[u8; 12]>::try_from(r.key_nonce).map_err(|_| StoreError::Corrupt)?,
                    ciphertext: r.key_sealed,
                },
                not_after: r.not_after_s,
                renew_after: r.renew_after_s,
            })
        })
        .collect()
}

/// The realm a request's `Host` names through a verified custom domain whose verification
/// holds, read by the router role (§17.9.6): the realm, and what the domain is bound as.
#[derive(Clone)]
pub struct CustomRoute {
    /// The tenant.
    pub tenant: TenantId,
    /// The realm.
    pub realm: RealmId,
    /// `issuer` or `rp_id` once bound.
    pub bound_as: Option<String>,
}

/// The realm serving the verified custom domain `hostname` (lower case), if any.
///
/// # Errors
/// [`StoreError`].
pub async fn route_by_custom_host(
    router: &PgPool,
    hostname: &str,
) -> Result<Option<CustomRoute>, StoreError> {
    let row = sqlx::query!(
        "SELECT d.tenant_id, d.realm_id, d.bound_as FROM access.realm_domains d
           JOIN access.realms r ON r.tenant_id = d.tenant_id AND r.realm_id = d.realm_id
          WHERE d.hostname = lower($1) AND d.status = 'verified'
            AND d.reverify_by > clock_timestamp() AND r.status = 'active'",
        hostname,
    )
    .fetch_optional(router)
    .await?;
    Ok(row.map(|r| CustomRoute {
        tenant: TenantId::from_bytes(*r.tenant_id.as_bytes()),
        realm: RealmId::from_bytes(*r.realm_id.as_bytes()),
        bound_as: r.bound_as,
    }))
}

/// Every verified custom domain whose verification holds, read by the router role: the TLS
/// listener serves a certificate only for these.
///
/// # Errors
/// [`StoreError`].
pub async fn served_hosts(router: &PgPool) -> Result<Vec<String>, StoreError> {
    Ok(sqlx::query_scalar!(
        "SELECT hostname FROM access.realm_domains
          WHERE status = 'verified' AND reverify_by > clock_timestamp() ORDER BY hostname",
    )
    .fetch_all(router)
    .await?)
}

/// Every open TLS-ALPN-01 challenge, read by the router role: `(hostname, digest)`.
///
/// # Errors
/// [`StoreError`].
pub async fn open_challenges(router: &PgPool) -> Result<Vec<(String, [u8; 32])>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT hostname, alpn_digest AS "alpn_digest!" FROM access.acme_orders
            WHERE status = 'challenging' AND alpn_digest IS NOT NULL ORDER BY hostname"#,
    )
    .fetch_all(router)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok((
                r.hostname,
                <[u8; 32]>::try_from(r.alpn_digest).map_err(|_| StoreError::Corrupt)?,
            ))
        })
        .collect()
}
