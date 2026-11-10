//! A RADIUS gateway's `RadSec` clients (`idp.gateway.radius_client_register` CT2, OP-155
//! m.3 (f)) and a Kerberos gateway's keytab policy (`idp.gateway.keytab_policy` CT2,
//! `keytab_emergency` reserved CT3, m.3 (o)): settings of a gateway that
//! `idp.gateway.register` registered. Sans-I/O.

use access_internal_api::edge::{GatewayKind, valid_name};
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// Largest `RadSec` client certificate.
pub const MAX_CERTIFICATE: usize = 8 * 1024;

/// The gateway a REST path names: `<kind>:<name>`.
///
/// # Errors
/// [`Invalid::Gateway`].
pub fn key(path: &str) -> Result<(GatewayKind, String), Invalid> {
    let (kind, name) = path.split_once(':').ok_or(Invalid::Gateway)?;
    let kind = GatewayKind::parse(kind).ok_or(Invalid::Gateway)?;
    if valid_name(name) {
        Ok((kind, String::from(name)))
    } else {
        Err(Invalid::Gateway)
    }
}

/// The resource path of gateway `kind`/`name`, as `idp.gateway.register` names it.
#[must_use]
pub fn path(kind: GatewayKind, name: &str) -> [String; 2] {
    [String::from("gateway"), format!("{}:{name}", kind.name())]
}

/// The gateway of `kind` a REST path names, `<kind>:<name>`.
///
/// # Errors
/// [`Invalid::Gateway`] for another kind.
pub fn key_of_kind(path: &str, kind: GatewayKind) -> Result<String, Invalid> {
    match key(path)? {
        (k, name) if k == kind => Ok(name),
        _ => Err(Invalid::Gateway),
    }
}

/// `idp.gateway.radius_client_register` (OP-155 m.3 (f)): a `RadSec` client of a RADIUS gateway,
/// by the SHA-256 of its TLS certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadiusClient {
    /// The RADIUS gateway's name.
    pub gateway: String,
    /// The client's name.
    pub client: String,
    /// SHA-256 of its certificate.
    pub certificate: [u8; 32],
}

impl RadiusClient {
    /// The client `client` of RADIUS gateway `gateway` with `certificate` (DER).
    ///
    /// # Errors
    /// [`Invalid::Gateway`].
    pub fn new(gateway: String, client: &str, certificate: &[u8]) -> Result<Self, Invalid> {
        let parsed = !certificate.is_empty()
            && certificate.len() <= MAX_CERTIFICATE
            && access_identity_x509::domain::cert::Cert::parse(certificate).is_ok();
        if !valid_name(&gateway) || !valid_name(client) || !parsed {
            return Err(Invalid::Gateway);
        }
        Ok(Self {
            gateway,
            client: String::from(client),
            certificate: suiss_crypto::digest::sha256(certificate),
        })
    }

    /// Checks the shape again before the decision.
    ///
    /// # Errors
    /// [`Invalid::Gateway`].
    pub fn check(&self) -> Result<(), Invalid> {
        if valid_name(&self.gateway) && valid_name(&self.client) {
            Ok(())
        } else {
            Err(Invalid::Gateway)
        }
    }

    /// The decision body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("gateway"), Value::text(&self.gateway)),
            (Value::text("client"), Value::text(&self.client)),
            (
                Value::text("certificate_sha256"),
                Value::Bytes(self.certificate.to_vec()),
            ),
        ])
    }
}

/// `idp.gateway.keytab_emergency` (OP-155 m.3 (o)): a gateway name and a key version above 0.
///
/// # Errors
/// [`Invalid::Gateway`].
pub fn emergency(gateway: &str, kvno: u32) -> Result<(), Invalid> {
    if valid_name(gateway) && kvno > 0 {
        Ok(())
    } else {
        Err(Invalid::Gateway)
    }
}

/// `idp.gateway.keytab_policy` (OP-155 m.3 (o)): the one SPN a Kerberos gateway accepts and how
/// often its keytab rotates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeytabPolicy {
    /// The Kerberos gateway's name.
    pub gateway: String,
    /// `service/host@REALM`, matched exactly.
    pub spn: String,
    /// Days between rotations, 1 to 365.
    pub rotate_days: u16,
}

impl KeytabPolicy {
    /// Checks the shape.
    ///
    /// # Errors
    /// [`Invalid::Gateway`].
    pub fn check(&self) -> Result<(), Invalid> {
        let days = 1..=access_identity_edge::domain::kerberos::MAX_ROTATE_DAYS;
        if valid_name(&self.gateway)
            && access_identity_edge::domain::kerberos::valid_spn(&self.spn)
            && days.contains(&self.rotate_days)
        {
            Ok(())
        } else {
            Err(Invalid::Gateway)
        }
    }

    /// The decision body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("gateway"), Value::text(&self.gateway)),
            (Value::text("spn"), Value::text(&self.spn)),
            (
                Value::text("rotate_days"),
                Value::Unsigned(u64::from(self.rotate_days)),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn cert(uri: &str) -> Vec<u8> {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
        let key = rcgen::KeyPair::generate().unwrap();
        p.self_signed(&key).unwrap().der().to_vec()
    }

    // OP-155 m.3 (f), (o)
    #[test]
    fn gateway_settings_name_their_kind() {
        let der = cert("urn:suiss:access:gw:radius:nas-1");
        assert_eq!(
            key_of_kind("radius:corp-radius", GatewayKind::Radius).unwrap(),
            "corp-radius"
        );
        assert_eq!(
            key_of_kind("ldap:corp-radius", GatewayKind::Radius),
            Err(Invalid::Gateway)
        );
        let c = RadiusClient::new(String::from("corp-radius"), "vpn-1", &der).unwrap();
        assert_eq!(c.certificate, suiss_crypto::digest::sha256(&der));
        assert_eq!(
            RadiusClient::new(String::from("corp-radius"), "vpn-1", b"not a certificate"),
            Err(Invalid::Gateway)
        );
        let p = KeytabPolicy {
            gateway: String::from("corp-krb"),
            spn: String::from("HTTP/access.corp.example@CORP.EXAMPLE"),
            rotate_days: 30,
        };
        assert!(p.check().is_ok());
        for bad in [
            KeytabPolicy {
                rotate_days: 0,
                ..p.clone()
            },
            KeytabPolicy {
                rotate_days: 366,
                ..p.clone()
            },
            KeytabPolicy {
                spn: String::from("HTTP@CORP.EXAMPLE"),
                ..p.clone()
            },
        ] {
            assert_eq!(bad.check(), Err(Invalid::Gateway));
        }
    }
}
