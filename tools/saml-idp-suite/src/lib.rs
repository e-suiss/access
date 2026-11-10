//! A neutral test suite for SAML 2.0 identity providers.
//!
//! - [`response`]: standards checks on a `samlp:Response` and on IdP metadata.
//! - [`request`]: the `AuthnRequest` corpus (signature wrapping, comment and CDATA injection,
//!   tampering, DTDs, size, replay) run against an IdP through the [`request::Target`] and
//!   [`request::Signer`] an integrator provides.
//! - [`profiles`]: what well-known service providers additionally require.
//!
//! The crate has no dependencies and knows no particular IdP.

pub mod encode;
pub mod profiles;
pub mod request;
pub mod response;
pub mod time;
pub mod xml;

/// SAML 2.0 protocol namespace.
pub const SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// SAML 2.0 assertion namespace.
pub const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// SAML 2.0 metadata namespace.
pub const MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// XML signature namespace.
pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// A plain-text report of findings or case results, one line each, failures marked.
#[must_use]
pub fn report<'a>(lines: impl IntoIterator<Item = (&'a str, bool, &'a str)>) -> (String, usize) {
    let mut out = String::new();
    let mut failed = 0_usize;
    for (name, ok, detail) in lines {
        if !ok {
            failed = failed.saturating_add(1);
        }
        out.push_str(if ok { "ok    " } else { "FAIL  " });
        out.push_str(name);
        if !detail.is_empty() {
            out.push_str("  ");
            out.push_str(detail);
        }
        out.push('\n');
    }
    (out, failed)
}
