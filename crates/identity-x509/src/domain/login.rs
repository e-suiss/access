//! What a verified client certificate says for sign-in (§10.2.5, OP-155 m.3 (m)).
//!
//! - The realm's rule maps exactly one subjectAltName entry of one kind to the account's
//!   identifier; none or several refuse.
//! - Assurance: the issuer policy OIDs the realm mapped as hardware-bound PIV make the
//!   certificate a device-bound key activated by the card's PIN (AAL3, CT3); any other
//!   certificate is a software key and never reaches CT3.
//! - The CA a path ends at is trusted only through the governing domain's actor-binding
//!   Acceptance of its issuer id, [`ca_issuer`].

use suiss_crypto::digest::context_digest;

use super::cert::Cert;
use crate::X509Error;

/// The domain separation of a CA's issuer id.
pub const CA_ISSUER_CONTEXT: &str = "access/x509-ca/v1";

/// How a certificate names the account it signs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rule {
    /// The subjectAltName `rfc822Name`.
    Email,
    /// The subjectAltName user principal name.
    Upn,
}

impl Rule {
    /// The rule's name in realm settings.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Email => "san_email",
            Self::Upn => "san_upn",
        }
    }

    /// The rule named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "san_email" => Some(Self::Email),
            "san_upn" => Some(Self::Upn),
            _ => None,
        }
    }
}

/// The identifier `rule` maps the certificate to.
///
/// # Errors
/// [`X509Error::Identifier`] unless exactly one entry of the rule's kind is present;
/// [`X509Error::Malformed`].
pub fn identifier(leaf: &Cert<'_>, rule: Rule) -> Result<String, X509Error> {
    let found = match rule {
        Rule::Email => leaf.san_emails()?,
        Rule::Upn => leaf.san_upns()?,
    };
    match found.as_slice() {
        [one] if !one.is_empty() && one.len() <= 254 && !one.chars().any(char::is_control) => {
            Ok(one.to_lowercase())
        }
        _ => Err(X509Error::Identifier),
    }
}

/// Whether one of the leaf's certificate policies is mapped as hardware-bound PIV.
///
/// # Errors
/// [`X509Error::Malformed`].
pub fn hardware_bound(leaf: &Cert<'_>, piv_policies: &[String]) -> Result<bool, X509Error> {
    Ok(leaf.policies()?.iter().any(|p| piv_policies.contains(p)))
}

/// The certificate's SHA-256 thumbprint (RFC 8705 `x5t#S256`).
#[must_use]
pub fn thumbprint(der: &[u8]) -> [u8; 32] {
    suiss_crypto::digest::sha256(der)
}

/// The issuer id of the CA `ca` (its certificate), which an actor-binding Acceptance names.
///
/// # Errors
/// [`X509Error::Malformed`].
pub fn ca_issuer(ca: &[u8]) -> Result<[u8; 16], X509Error> {
    let c = Cert::parse(ca)?;
    let mut input = Vec::with_capacity(c.subject.len().saturating_add(c.public_key.len()));
    input.extend_from_slice(c.subject);
    input.extend_from_slice(c.public_key);
    let d = context_digest(CA_ISSUER_CONTEXT, &input).0;
    let mut id = [0; 16];
    for (o, b) in id.iter_mut().zip(d) {
        *o = b;
    }
    Ok(id)
}

/// Whether `oid` is a dotted OID a realm may map.
#[must_use]
pub fn policy_oid(oid: &str) -> bool {
    let arcs: Vec<&str> = oid.split('.').collect();
    oid.len() <= 128
        && arcs.len() >= 2
        && arcs
            .iter()
            .all(|a| !a.is_empty() && a.len() <= 19 && a.bytes().all(|c| c.is_ascii_digit()))
        && arcs.iter().all(|a| a.len() == 1 || !a.starts_with('0'))
        && matches!(arcs.first(), Some(&("0" | "1" | "2")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::testing::{Ca, LeafSpec};

    const PIV_AUTH: &str = "2.16.840.1.101.3.2.1.3.13";

    // §10.2.5, OP-155 m.3 (m)
    #[test]
    fn the_rule_maps_exactly_one_entry() {
        let ca = Ca::root("Login Root");
        let leaf = ca.leaf(&LeafSpec {
            email: Some("Ada@Example.org"),
            ..LeafSpec::default()
        });
        let c = Cert::parse(&leaf.der).unwrap();
        assert_eq!(identifier(&c, Rule::Email).unwrap(), "ada@example.org");
        assert_eq!(identifier(&c, Rule::Upn), Err(X509Error::Identifier));
        assert_eq!(Rule::parse(Rule::Upn.name()), Some(Rule::Upn));
        assert_eq!(Rule::parse("subject_cn"), None);
    }

    // OP-155 m.3 (m), §10.3.1
    #[test]
    fn only_a_mapped_piv_policy_is_hardware_bound() {
        let ca = Ca::root("Policy Root");
        let piv = ca.leaf(&LeafSpec {
            policies: &[PIV_AUTH],
            ..LeafSpec::default()
        });
        let software = ca.leaf(&LeafSpec {
            policies: &["2.16.840.1.101.3.2.1.3.7"],
            ..LeafSpec::default()
        });
        let mapped = vec![String::from(PIV_AUTH)];
        assert!(hardware_bound(&Cert::parse(&piv.der).unwrap(), &mapped).unwrap());
        assert!(!hardware_bound(&Cert::parse(&software.der).unwrap(), &mapped).unwrap());
        assert!(!hardware_bound(&Cert::parse(&piv.der).unwrap(), &[]).unwrap());
        assert!(policy_oid(PIV_AUTH));
        assert!(!policy_oid("3.1"));
        assert!(!policy_oid("2.01"));
        assert!(!policy_oid("2"));
    }

    #[test]
    fn a_ca_issuer_id_is_its_subject_and_key() {
        let a = Ca::root("Issuer A");
        let b = Ca::root("Issuer A");
        assert_ne!(ca_issuer(&a.der).unwrap(), ca_issuer(&b.der).unwrap());
        assert_eq!(ca_issuer(&a.der).unwrap(), ca_issuer(&a.der).unwrap());
    }
}
