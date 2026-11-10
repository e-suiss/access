//! Certificate, PIV and CAC sign-in of a realm (`idp.realm.certificate_login`, CT2, OP-155
//! m.3 (m), §10.2.5): whether it is on, how a certificate names the account, the CAs whose paths
//! are accepted, and the issuer policies mapped as hardware-bound PIV. A CA here is a candidate
//! only: it is trusted once the governing domain holds an actor-binding Acceptance of its issuer
//! id.

use std::collections::BTreeSet;

use access_identity_x509::domain::cert::Cert;
use access_identity_x509::domain::login::{Rule, ca_issuer, policy_oid};
use access_identity_x509::domain::path::MAX_CERT;
use access_kernel::claim::body::{BindingKind, Class};
use access_kernel::codec::Canonical as _;
use access_kernel::model::{Id, SubjectSelector};
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// Most CAs a realm names (PD).
pub const MAX_ANCHORS: usize = 16;

/// Most issuer policies a realm maps (PD).
pub const MAX_POLICIES: usize = 16;

/// A realm's certificate sign-in setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateLogin {
    /// Whether it is on.
    pub enabled: bool,
    /// How a certificate names the account.
    pub rule: Rule,
    /// The CAs, DER certificates.
    pub anchors: Vec<Vec<u8>>,
    /// Issuer policy OIDs mapped as hardware-bound PIV, dotted.
    pub piv_policies: BTreeSet<String>,
}

impl CertificateLogin {
    /// Checks the setting on its own.
    ///
    /// # Errors
    /// [`Invalid::CertificateLogin`]: no CA while on, too many CAs or policies, a CA that is not
    /// a readable certificate of at most 8 KB, the same CA twice, or a policy that is not a
    /// dotted OID.
    pub fn check(&self) -> Result<(), Invalid> {
        let distinct: BTreeSet<&Vec<u8>> = self.anchors.iter().collect();
        let ok = (!self.enabled || !self.anchors.is_empty())
            && self.anchors.len() <= MAX_ANCHORS
            && distinct.len() == self.anchors.len()
            && self
                .anchors
                .iter()
                .all(|a| a.len() <= MAX_CERT && Cert::parse(a).is_ok())
            && self.piv_policies.len() <= MAX_POLICIES
            && self.piv_policies.iter().all(|p| policy_oid(p));
        if ok {
            Ok(())
        } else {
            Err(Invalid::CertificateLogin)
        }
    }

    /// The signed body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("enabled"), Value::Bool(self.enabled)),
            (Value::text("rule"), Value::text(self.rule.name())),
            (
                Value::text("anchors"),
                Value::Array(
                    self.anchors
                        .iter()
                        .map(|a| Value::Bytes(a.clone()))
                        .collect(),
                ),
            ),
            (
                Value::text("piv_policies"),
                Value::Array(self.piv_policies.iter().map(|p| Value::text(p)).collect()),
            ),
        ])
    }
}

/// The governing domain root's actor-binding Acceptance of the CA `ca` (its certificate) for
/// person identity bindings: the content of its `acceptance_establish` (§10.2.5, OP-155 m.3 (m)).
///
/// # Errors
/// [`Invalid::CertificateLogin`] for a CA that is not a readable certificate.
pub fn ca_acceptance(ca: &[u8]) -> Result<Value, Invalid> {
    let issuer = ca_issuer(ca).map_err(|_| Invalid::CertificateLogin)?;
    Ok(Value::Map(vec![
        (Value::text("issuer"), Id(issuer).to_value()),
        (
            Value::text("use"),
            Value::text(access_kernel::claim::ACTOR_BINDING),
        ),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text(
                &Class::IdentityBinding(BindingKind::Person).name(),
            )]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_identity_x509::testing::Ca;

    use super::*;

    fn setting(anchors: Vec<Vec<u8>>, policies: &[&str]) -> CertificateLogin {
        CertificateLogin {
            enabled: true,
            rule: Rule::Email,
            anchors,
            piv_policies: policies.iter().map(|p| String::from(*p)).collect(),
        }
    }

    // OP-155 m.3 (m)
    #[test]
    fn a_setting_names_readable_cas_and_dotted_policies() {
        let ca = Ca::root("Admin Root").der;
        assert!(
            setting(vec![ca.clone()], &["2.16.840.1.101.3.2.1.3.13"])
                .check()
                .is_ok()
        );
        assert!(setting(Vec::new(), &[]).check().is_err());
        let off = CertificateLogin {
            enabled: false,
            ..setting(Vec::new(), &[])
        };
        assert!(off.check().is_ok());
        assert!(setting(vec![vec![0x30, 0x00]], &[]).check().is_err());
        assert!(setting(vec![ca.clone(), ca.clone()], &[]).check().is_err());
        assert!(setting(vec![ca], &["piv"]).check().is_err());
    }
}
