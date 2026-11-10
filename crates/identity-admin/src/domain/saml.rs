//! `idp.saml.*` and `idp.gateway.register`/`retire` changes (OP-155 m.3 (a), (c), (e); m.6 (h);
//! m.7 (a)): a service provider registration is checked and its template's interop profile
//! applied before any decision; the certificate policy keeps at least 14 days per rotation
//! phase. Sans-I/O.

use access_identity_saml::profile;
use access_identity_saml::sp::Sp;
use access_internal_api::edge::{GatewayKind, valid_name};
use access_internal_api::idp::IdpAction;
use serde_json::Value as Json;
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// A registration's natural key: lower-case letters, digits and `-`, starting with a letter.
#[must_use]
pub fn sp_name_ok(name: &str) -> bool {
    valid_name(name)
}

/// The rotation policy of the realm's SAML signing certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertPolicy {
    /// Days between scheduled rotations.
    pub rotate_days: i32,
    /// Days of each phase (publish before use, keep after): at least 14.
    pub overlap_days: i32,
    /// P-256 rather than RSA-3072.
    pub p256: bool,
}

/// An `idp.saml.*` or `idp.gateway.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SamlChange {
    /// `idp.saml.sp_register` (CT2): a new registration under `name`.
    Register(String, Box<Sp>),
    /// `idp.saml.sp_update` (CT2): the registration's next version.
    Update(String, Box<Sp>),
    /// `idp.saml.sp_retire` (CT1): never answered again; its name and entity ID are not reused.
    Retire(String),
    /// `idp.saml.cert_policy` (CT2).
    CertPolicy(CertPolicy),
    /// `idp.saml.cert_emergency` (reserved, CT3): a new key signs at once.
    CertEmergency {
        /// P-256 rather than RSA-3072.
        p256: bool,
    },
    /// `idp.gateway.register` (CT2): `kind`/`name` live with the client certificate digest.
    GatewayRegister {
        /// Its kind.
        kind: GatewayKind,
        /// Its name.
        name: String,
        /// SHA-256 of its client certificate.
        cert: [u8; 32],
    },
    /// `idp.gateway.retire` (CT1).
    GatewayRetire {
        /// Its kind.
        kind: GatewayKind,
        /// Its name.
        name: String,
    },
}

fn obj(body: &Json) -> Result<&serde_json::Map<String, Json>, Invalid> {
    body.as_object().ok_or(Invalid::Body)
}

fn sp_of(body: &Json, name: &str) -> Result<Sp, Invalid> {
    let mut own = obj(body)?.clone();
    if own
        .remove("name")
        .and_then(|n| n.as_str().map(String::from))
        .is_some_and(|n| n != name)
    {
        return Err(Invalid::SamlSp);
    }
    let sp: Sp = serde_json::from_value(Json::Object(own)).map_err(|_| Invalid::SamlSp)?;
    profile::register(sp).map_err(|_| Invalid::SamlSp)
}

fn days(m: &serde_json::Map<String, Json>, key: &str, default: i32) -> Result<i32, Invalid> {
    match m.get(key) {
        None => Ok(default),
        Some(v) => v
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .ok_or(Invalid::SamlCertificate),
    }
}

fn alg(m: &serde_json::Map<String, Json>) -> Result<bool, Invalid> {
    match m.get("alg").and_then(Json::as_str) {
        None | Some("rsa-3072") => Ok(false),
        Some("p-256") => Ok(true),
        Some(_) => Err(Invalid::SamlCertificate),
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let pair = s.get(i.checked_mul(2)?..i.checked_mul(2)?.checked_add(2)?)?;
        *o = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

impl SamlChange {
    /// `registerSamlSp`: `{"name": …, …registration}`.
    ///
    /// # Errors
    /// [`Invalid::SamlSp`].
    pub fn register(body: &Json) -> Result<Self, Invalid> {
        let name = obj(body)?
            .get("name")
            .and_then(Json::as_str)
            .filter(|n| sp_name_ok(n))
            .ok_or(Invalid::SamlSp)?
            .to_owned();
        let sp = sp_of(body, &name)?;
        Ok(Self::Register(name, Box::new(sp)))
    }

    /// `putSamlSp` of `name`.
    ///
    /// # Errors
    /// [`Invalid::SamlSp`].
    pub fn update(name: &str, body: &Json) -> Result<Self, Invalid> {
        if !sp_name_ok(name) {
            return Err(Invalid::SamlSp);
        }
        Ok(Self::Update(
            String::from(name),
            Box::new(sp_of(body, name)?),
        ))
    }

    /// `retireSamlSp` of `name`.
    ///
    /// # Errors
    /// [`Invalid::SamlSp`].
    pub fn retire(name: &str, body: &Json) -> Result<Self, Invalid> {
        if !sp_name_ok(name) || !obj(body)?.is_empty() {
            return Err(Invalid::SamlSp);
        }
        Ok(Self::Retire(String::from(name)))
    }

    /// `putSamlCertificatePolicy`: `{"rotate_days", "overlap_days", "alg"}`.
    ///
    /// # Errors
    /// [`Invalid::SamlCertificate`].
    pub fn cert_policy(body: &Json) -> Result<Self, Invalid> {
        let m = obj(body)?;
        if m.keys()
            .any(|k| !matches!(k.as_str(), "rotate_days" | "overlap_days" | "alg"))
        {
            return Err(Invalid::SamlCertificate);
        }
        Ok(Self::CertPolicy(CertPolicy {
            rotate_days: days(m, "rotate_days", 365)?,
            overlap_days: days(m, "overlap_days", 14)?,
            p256: alg(m)?,
        }))
    }

    /// `replaceSamlCertificate`: `{"alg"}`.
    ///
    /// # Errors
    /// [`Invalid::SamlCertificate`].
    pub fn cert_emergency(body: &Json) -> Result<Self, Invalid> {
        let m = obj(body)?;
        if m.keys().any(|k| k != "alg") {
            return Err(Invalid::SamlCertificate);
        }
        Ok(Self::CertEmergency { p256: alg(m)? })
    }

    /// `registerGateway`: `{"kind", "name", "cert_sha256"}` (hex).
    ///
    /// # Errors
    /// [`Invalid::Gateway`].
    pub fn gateway_register(body: &Json) -> Result<Self, Invalid> {
        let m = obj(body)?;
        if m.keys()
            .any(|k| !matches!(k.as_str(), "kind" | "name" | "cert_sha256"))
        {
            return Err(Invalid::Gateway);
        }
        let get = |k: &str| m.get(k).and_then(Json::as_str).ok_or(Invalid::Gateway);
        let kind = GatewayKind::parse(get("kind")?).ok_or(Invalid::Gateway)?;
        let name = get("name")?;
        if !valid_name(name) {
            return Err(Invalid::Gateway);
        }
        Ok(Self::GatewayRegister {
            kind,
            name: String::from(name),
            cert: hex32(get("cert_sha256")?).ok_or(Invalid::Gateway)?,
        })
    }

    /// `retireGateway` of `key` (`<kind>:<name>`).
    ///
    /// # Errors
    /// [`Invalid::Gateway`].
    pub fn gateway_retire(key: &str, body: &Json) -> Result<Self, Invalid> {
        let (kind, name) = key.split_once(':').ok_or(Invalid::Gateway)?;
        let kind = GatewayKind::parse(kind).ok_or(Invalid::Gateway)?;
        if !valid_name(name) || !obj(body)?.is_empty() {
            return Err(Invalid::Gateway);
        }
        Ok(Self::GatewayRetire {
            kind,
            name: String::from(name),
        })
    }

    /// The action that authorizes it. A registration's attribute sources (e-mail, `NameID`,
    /// subject, fixed values) never select authority, so REST registers with `sp_register`
    /// (OP-155 m.7 (a)).
    #[must_use]
    pub fn action(&self) -> IdpAction {
        match self {
            // IDP-28, L6, OP-155 m.7 (a)
            Self::Register(_, sp)
                if sp
                    .template
                    .as_deref()
                    .is_some_and(access_identity_saml::catalog::selects_authority) =>
            {
                IdpAction::SamlSpMapping
            }
            Self::Register(..) => IdpAction::SamlSpRegister,
            Self::Update(..) => IdpAction::SamlSpUpdate,
            Self::Retire(_) => IdpAction::SamlSpRetire,
            Self::CertPolicy(_) => IdpAction::SamlCertPolicy,
            Self::CertEmergency { .. } => IdpAction::SamlCertEmergency,
            Self::GatewayRegister { .. } => IdpAction::GatewayRegister,
            Self::GatewayRetire { .. } => IdpAction::GatewayRetire,
        }
    }

    /// Whether it is inside the rules: each rotation phase lasts at least 14 days.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn check(&self) -> Result<(), Invalid> {
        match self {
            Self::Register(n, sp) | Self::Update(n, sp) => {
                if sp_name_ok(n) && sp.check().is_ok() {
                    Ok(())
                } else {
                    Err(Invalid::SamlSp)
                }
            }
            Self::Retire(n) if sp_name_ok(n) => Ok(()),
            Self::Retire(_) => Err(Invalid::SamlSp),
            Self::CertPolicy(p) => {
                let phases = p.overlap_days.checked_mul(2).unwrap_or(i32::MAX);
                if (14..=90).contains(&p.overlap_days)
                    && (30..=1825).contains(&p.rotate_days)
                    && p.rotate_days > phases
                {
                    Ok(())
                } else {
                    Err(Invalid::SamlCertificate)
                }
            }
            Self::CertEmergency { .. } => Ok(()),
            Self::GatewayRegister { name, .. } | Self::GatewayRetire { name, .. } => {
                if valid_name(name) {
                    Ok(())
                } else {
                    Err(Invalid::Gateway)
                }
            }
        }
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        let m = |e: Vec<(&str, Value)>| {
            Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
        };
        match self {
            Self::Register(n, sp) | Self::Update(n, sp) => m(vec![
                ("name", Value::text(n)),
                (
                    "sp",
                    Value::Bytes(serde_json::to_vec(&sp.to_json()).unwrap_or_default()),
                ),
            ]),
            Self::Retire(n) => m(vec![("retire", Value::text(n))]),
            Self::CertPolicy(p) => m(vec![
                (
                    "rotate_days",
                    Value::Unsigned(u64::try_from(p.rotate_days).unwrap_or(0)),
                ),
                (
                    "overlap_days",
                    Value::Unsigned(u64::try_from(p.overlap_days).unwrap_or(0)),
                ),
                (
                    "alg",
                    Value::text(if p.p256 { "p-256" } else { "rsa-3072" }),
                ),
            ]),
            Self::CertEmergency { p256 } => m(vec![(
                "emergency",
                Value::text(if *p256 { "p-256" } else { "rsa-3072" }),
            )]),
            Self::GatewayRegister { kind, name, cert } => m(vec![
                ("kind", Value::text(kind.name())),
                ("name", Value::text(name)),
                ("cert_sha256", Value::Bytes(cert.to_vec())),
            ]),
            Self::GatewayRetire { kind, name } => m(vec![
                ("retire", Value::text(kind.name())),
                ("name", Value::text(name)),
            ]),
        }
    }

    /// Its resource path below the realm's slug.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        match self {
            Self::Register(n, _) | Self::Update(n, _) | Self::Retire(n) => {
                vec![String::from("saml-sp"), n.clone()]
            }
            Self::CertPolicy(_) | Self::CertEmergency { .. } => {
                vec![String::from("saml-certificate")]
            }
            Self::GatewayRegister { kind, name, .. } | Self::GatewayRetire { kind, name } => {
                vec![String::from("gateway"), format!("{}:{name}", kind.name())]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    fn body() -> Json {
        json!({
            "name": "slack",
            "entity_id": "https://slack.com",
            "template": "slack",
            "acs": [{ "url": "https://acme.slack.com/sso/saml", "index": 0, "binding": "post" }],
            "attributes": [{ "name": "User.Email", "source": "email" }],
        })
    }

    // OP-155 m.3 (a)
    #[test]
    fn a_registration_compiles_with_its_profile() {
        let c = SamlChange::register(&body()).unwrap();
        assert_eq!(c.action(), IdpAction::SamlSpRegister);
        assert!(c.check().is_ok());
        let mut bad = body();
        bad["sign_response"] = json!(false);
        assert_eq!(SamlChange::register(&bad), Err(Invalid::SamlSp));
        assert_eq!(
            SamlChange::update("slack", &body()).unwrap().action(),
            IdpAction::SamlSpUpdate
        );
        assert_eq!(SamlChange::update("other", &body()), Err(Invalid::SamlSp));
        assert_eq!(
            SamlChange::retire("slack", &json!({})).unwrap().action(),
            IdpAction::SamlSpRetire
        );
    }

    // §10.6.1, Ek B 4778
    #[test]
    fn certificate_policies_keep_two_week_phases() {
        let ok = SamlChange::cert_policy(&json!({"rotate_days": 365, "overlap_days": 14})).unwrap();
        assert!(ok.check().is_ok());
        let short = SamlChange::cert_policy(&json!({"overlap_days": 7})).unwrap();
        assert_eq!(short.check(), Err(Invalid::SamlCertificate));
        assert_eq!(
            SamlChange::cert_emergency(&json!({"alg": "p-256"}))
                .unwrap()
                .action(),
            IdpAction::SamlCertEmergency
        );
        assert!(SamlChange::cert_policy(&json!({"alg": "rsa-1024"})).is_err());
    }
}
