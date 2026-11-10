//! `idp.domain.*` changes against the realm and under their committed ALLOW (OP-156 m.3 (i),
//! §10.2.4, TN-16, TN-17): a registration names a host outside the base and gets its TXT
//! challenge and CNAME target; retiring withdraws its certificate; binding a verified domain as
//! the issuer is possible only before the realm's first activation, and binding it as the RP ID
//! pins the domain's registrable domain. Neither binding comes undone.

use access_identity_domain::domain::host::{Base, CustomHost};
use access_identity_domain::domain::verify::{self, Registration, Status};
use access_identity_oauth::domain::issuer::{Issuer, RealmBase};
use access_store::custom_domains::{self as store, DomainRow, NewDomain};
use access_store::identity::TenantTx;
use access_store::idp::{self, Bound, Governing};
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::Invalid;
use crate::domain::custom_domain::{Binding, DomainChange};

/// The deployment's base host of `base`.
#[must_use]
pub(crate) fn base_of(base: &RealmBase) -> Base {
    let authority = base.as_str().strip_prefix("https://").unwrap_or_default();
    Base::new(authority.rsplit_once(':').map_or(authority, |(h, _)| h))
}

/// The stable id of the registration of `host` that `exercise` made.
fn domain_id(host: &str, exercise: &[u8]) -> [u8; 16] {
    let mut input = b"access/custom-domain\0".to_vec();
    input.extend_from_slice(host.as_bytes());
    input.push(0);
    input.extend_from_slice(exercise);
    let d = suiss_crypto::digest::sha256(&input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    out
}

fn registration(d: &DomainRow) -> Option<Registration> {
    Some(Registration {
        host: CustomHost::stored(&d.hostname),
        status: Status::parse(&d.status)?,
        registered_at: d.registered_at,
        reverify_by: d.reverify_by,
        checked_at: d.checked_at,
    })
}

fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

async fn served(t: &mut TenantTx, host: &str) -> Result<DomainRow, AdminError> {
    let d = store::live_by_host(t, host)
        .await?
        .ok_or(Invalid::NoDomain)?;
    let ok = registration(&d).is_some_and(|r| verify::served(&r, now_s()));
    if ok {
        Ok(d)
    } else {
        Err(Invalid::DomainUnverified.into())
    }
}

/// Checks `change` against the realm (OP-156 m.3 (i)).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn current(
    t: &mut TenantTx,
    change: &DomainChange,
    g: &Governing,
    base: &RealmBase,
) -> Result<(), AdminError> {
    match change {
        DomainChange::Register(host) => {
            CustomHost::parse(host, &base_of(base)).map_err(|_| Invalid::CustomDomain)?;
            if store::live_by_host(t, host).await?.is_some() {
                return Err(AdminError::Conflict);
            }
        }
        DomainChange::Retire(host) => {
            let d = store::live_by_host(t, host)
                .await?
                .ok_or(Invalid::NoDomain)?;
            // TN-16
            if d.bound_as.is_some() {
                return Err(Invalid::CustomDomain.into());
            }
        }
        DomainChange::IssuerBind(host, bind) => {
            let d = served(t, host).await?;
            if d.bound_as.is_some() {
                return Err(AdminError::Conflict);
            }
            match bind {
                // TN-16, OP-156 m.3 (i)
                Binding::Issuer => {
                    let issuer = g.issuer.as_deref().and_then(|i| Issuer::parse(i).ok());
                    let path = issuer.as_ref().is_some_and(|i| !i.path().is_empty());
                    if path || store::activated(t).await? {
                        return Err(Invalid::IssuerFixed.into());
                    }
                }
                // §12.1.2, TN-17
                Binding::RpId => {
                    let rp = CustomHost::stored(host)
                        .registrable()
                        .map(String::from)
                        .ok_or(Invalid::RpId)?;
                    let issuer_host = g
                        .issuer
                        .as_deref()
                        .and_then(|i| Issuer::parse(i).ok())
                        .map(|i| {
                            let a = i.authority();
                            String::from(a.rsplit_once(':').map_or(a, |(h, _)| h))
                        })
                        .unwrap_or_default();
                    access_identity_domain::domain::rp::check(
                        &rp,
                        &base_of(base),
                        &issuer_host,
                        &[String::from(host)],
                    )
                    .map_err(|_| Invalid::RpId)?;
                }
            }
        }
    }
    Ok(())
}

/// Writes `change` under `bound`; `exercise` is the committing Exercise's digest.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &DomainChange,
    (g, base, exercise): (&Governing, &RealmBase, &[u8]),
) -> Result<bool, AdminError> {
    match change {
        DomainChange::Register(host) => {
            let challenge = access_kernel::json::b64url_encode(
                &access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?,
            );
            store::register(
                t,
                bound,
                &NewDomain {
                    id: domain_id(host, exercise),
                    hostname: host,
                    challenge: &challenge,
                    cname_target: &base_of(base).realm_host(&g.slug),
                },
            )
            .await?;
            Ok(true)
        }
        DomainChange::Retire(host) => {
            let d = store::live_by_host(t, host)
                .await?
                .ok_or(Invalid::NoDomain)?;
            Ok(store::retire(t, bound, d.id).await?)
        }
        DomainChange::IssuerBind(host, bind) => {
            let d = served(t, host).await?;
            if !store::bind(t, bound, d.id, bind.name()).await? {
                return Err(AdminError::Conflict);
            }
            match bind {
                Binding::Issuer => {
                    let from = g.issuer.as_deref().ok_or(AdminError::NoRealm)?;
                    let to = Issuer::parse(&format!("https://{host}"))
                        .map_err(|_| Invalid::CustomDomain)?;
                    if !store::rebind_issuer(t, from, to.as_str()).await? {
                        return Err(AdminError::Conflict);
                    }
                }
                Binding::RpId => {
                    let rp = CustomHost::stored(host)
                        .registrable()
                        .map(String::from)
                        .ok_or(Invalid::RpId)?;
                    let s = idp::settings(t).await?.ok_or(AdminError::NoRealm)?;
                    // RR-45, TN-17
                    if s.rp_id.as_deref() != Some(rp.as_str()) {
                        t.insert_rp_id_change(s.rp_id.as_deref(), &rp).await?;
                    }
                    let mut next = s;
                    next.rp_id = Some(rp);
                    idp::update_settings(t, bound, &next).await?;
                }
            }
            Ok(true)
        }
    }
}

fn rfc3339(s: Option<i64>) -> Json {
    s.and_then(|s| u64::try_from(s).ok())
        .and_then(|s| s.checked_mul(1000))
        .map_or(Json::Null, |ms| Json::from(super::rest::rfc3339(ms)))
}

/// The realm's custom domains as administrators read them, newest first: the records to
/// publish, the verification state and the certificate's expiry; with `key`, only that host's.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    let rows = store::domains(t).await?;
    let certs = store::active_certificates(t).await?;
    let now = now_s();
    Ok(rows
        .into_iter()
        .filter(|d| key.is_none_or(|k| k == d.hostname))
        .map(|d| {
            let cert = certs.iter().find(|c| c.domain == d.id);
            let served = registration(&d).is_some_and(|r| verify::served(&r, now));
            let v = json!({
                "host": d.hostname,
                "status": d.status,
                "served": served,
                "txt_name": CustomHost::stored(&d.hostname).challenge_name(),
                "txt_value": d.challenge,
                "cname_target": d.cname_target,
                "finding": d.finding,
                "checked_at": rfc3339(d.checked_at),
                "verified_at": rfc3339(d.verified_at),
                "reverify_by": rfc3339(d.reverify_by),
                "bound_as": d.bound_as,
                "certificate_expires_at": rfc3339(cert.map(|c| c.not_after)),
                "renews_at": rfc3339(cert.map(|c| c.renew_after)),
                "acme_error": d.acme_error,
            });
            (v, d.decision_pos)
        })
        .collect())
}
