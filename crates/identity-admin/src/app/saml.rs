//! `idp.saml.*` and `idp.gateway.*` changes written under their committed ALLOW (OP-155 m.3 (a),
//! (c), (e); m.6 (h)), and the service provider registrations as administrators read them. A
//! retired registration keeps its name and entity ID forever (OP-73).

use access_identity_saml::sp::Sp;
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use access_store::saml::{CertPolicy as StoredPolicy, NewSp, SpRow};
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::Invalid;
use crate::domain::saml::SamlChange;

/// The stable identifier of registration `name`.
#[must_use]
pub fn sp_id(name: &str) -> [u8; 16] {
    let mut input = b"access/saml-sp\0".to_vec();
    input.extend_from_slice(name.as_bytes());
    let d = suiss_crypto::digest::sha256(&input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    out
}

fn protocol(sp: &Sp) -> &'static str {
    use access_identity_saml::sp::Protocol;
    match sp.protocol {
        Protocol::Saml2 => "saml2",
        Protocol::WsfedSaml11 => "wsfed-saml11",
        Protocol::WsfedSaml2 => "wsfed-saml2",
    }
}

/// The stored document of a registration: its name and its checked registration.
#[must_use]
pub fn document(name: &str, sp: &Sp) -> Vec<u8> {
    serde_json::to_vec(&json!({ "name": name, "sp": sp.to_json() })).unwrap_or_default()
}

/// The name and registration of a stored document.
#[must_use]
pub fn read_document(bytes: &[u8]) -> Option<(String, Sp)> {
    let v: Json = serde_json::from_slice(bytes).ok()?;
    let name = v.get("name")?.as_str()?.to_owned();
    let sp = Sp::from_json(v.get("sp")?).ok()?;
    Some((name, sp))
}

async fn by_name(t: &mut TenantTx, name: &str) -> Result<Option<SpRow>, AdminError> {
    let id = sp_id(name);
    Ok(t.saml_sps().await?.into_iter().find(|r| r.sp_id == id))
}

/// What must hold now for `change`: a new registration's name and entity ID were never used;
/// an update or retirement names a live registration and keeps its entity ID.
///
/// # Errors
/// [`Invalid`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &SamlChange) -> Result<(), AdminError> {
    match change {
        SamlChange::Register(name, sp) => {
            let taken = by_name(t, name).await?.is_some()
                || t.saml_sp_by_entity(&sp.entity_id).await?.is_some();
            if taken {
                return Err(Invalid::SamlSpExists.into());
            }
        }
        SamlChange::Update(name, sp) => {
            let row = by_name(t, name)
                .await?
                .filter(|r| r.live)
                .ok_or(Invalid::NoSamlSp)?;
            if row.entity_id != sp.entity_id {
                return Err(Invalid::SamlSp.into());
            }
        }
        SamlChange::Retire(name) => {
            by_name(t, name)
                .await?
                .filter(|r| r.live)
                .ok_or(Invalid::NoSamlSp)?;
        }
        SamlChange::CertPolicy(_)
        | SamlChange::CertEmergency { .. }
        | SamlChange::GatewayRegister { .. }
        | SamlChange::GatewayRetire { .. } => {}
    }
    Ok(())
}

/// Writes `change` under `bound`.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &SamlChange,
) -> Result<bool, AdminError> {
    match change {
        SamlChange::Register(name, sp) | SamlChange::Update(name, sp) => {
            let doc = document(name, sp);
            t.put_saml_sp(
                bound,
                &NewSp {
                    sp_id: sp_id(name),
                    entity_id: &sp.entity_id,
                    protocol: protocol(sp),
                    live: true,
                    definition: &doc,
                },
            )
            .await?;
        }
        SamlChange::Retire(name) => {
            let row = by_name(t, name).await?.ok_or(Invalid::NoSamlSp)?;
            t.put_saml_sp(
                bound,
                &NewSp {
                    sp_id: row.sp_id,
                    entity_id: &row.entity_id,
                    protocol: &row.protocol,
                    live: false,
                    definition: &row.definition,
                },
            )
            .await?;
        }
        SamlChange::CertPolicy(p) => {
            t.put_saml_cert_policy(
                bound,
                &StoredPolicy {
                    rotate_days: p.rotate_days,
                    overlap_days: p.overlap_days,
                    p256: p.p256,
                    emergency: false,
                },
            )
            .await?;
        }
        SamlChange::CertEmergency { p256 } => {
            let (rotate_days, overlap_days) = match t.saml_cert_policy().await? {
                Some((p, _)) => (p.rotate_days, p.overlap_days),
                None => (365, 14),
            };
            t.put_saml_cert_policy(
                bound,
                &StoredPolicy {
                    rotate_days,
                    overlap_days,
                    p256: *p256,
                    emergency: true,
                },
            )
            .await?;
        }
        SamlChange::GatewayRegister { kind, name, cert } => {
            access_identity_edge::adapters::register(t, bound, *kind, name, cert)
                .await
                .map_err(|_| Invalid::Gateway)?;
        }
        SamlChange::GatewayRetire { kind, name } => {
            let retired = access_identity_edge::adapters::retire(t, bound, *kind, name)
                .await
                .map_err(|_| Invalid::Gateway)?;
            if !retired {
                return Err(Invalid::Gateway.into());
            }
        }
    }
    Ok(true)
}

/// The registrations as administrators read them, each with its decision position; a retired
/// one says so. Certificates are public; nothing secret is held.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    let rows = t.saml_sps().await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let (name, sp) = read_document(&r.definition)?;
            if key.is_some_and(|k| k != name) {
                return None;
            }
            let mut v = sp.to_json();
            if let Some(o) = v.as_object_mut() {
                o.insert(String::from("name"), Json::from(name));
                o.insert(
                    String::from("status"),
                    Json::from(if r.live { "live" } else { "retired" }),
                );
                o.insert(String::from("version"), Json::from(r.version));
            }
            Some((v, r.position))
        })
        .collect())
}
