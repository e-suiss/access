//! The OID4VCI issuer metadata (`/.well-known/openid-credential-issuer`, OID4VCI 1.0 §12.2) and
//! the pre-authorized credential offer the account page makes (§4.1). Only the person-attribute
//! types are configured; the realm issuer is also the authorization server of the
//! pre-authorized code.

use serde_json::{Map, Value, json};

use crate::domain::types::{ALL, PersonAttribute};

/// The pre-authorized code grant type (OID4VCI 1.0 §4.1.1).
pub const PRE_AUTHORIZED_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// The key proof JWT `typ` (OID4VCI 1.0 Appendix F.1).
pub const PROOF_TYP: &str = "openid4vci-proof+jwt";

/// The issuer metadata of the realm issuer `issuer`.
#[must_use]
pub fn issuer_metadata(issuer: &str) -> Value {
    let base = issuer.trim_end_matches('/');
    let mut configurations = Map::new();
    for t in ALL {
        configurations.insert(
            String::from(t.name()),
            json!({
                "format": "dc+sd-jwt",
                "vct": t.vct(base),
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": { "proof_signing_alg_values_supported": ["ES256"] }
                },
            }),
        );
    }
    json!({
        "credential_issuer": base,
        "authorization_servers": [base],
        "credential_endpoint": format!("{base}/oid4vci/credential"),
        "nonce_endpoint": format!("{base}/oid4vci/nonce"),
        "credential_configurations_supported": Value::Object(configurations),
    })
}

/// A pre-authorized credential offer for one type.
#[must_use]
pub fn offer(issuer: &str, t: PersonAttribute, code: &str) -> Value {
    json!({
        "credential_issuer": issuer.trim_end_matches('/'),
        "credential_configuration_ids": [t.name()],
        "grants": { PRE_AUTHORIZED_GRANT: { "pre-authorized_code": code } },
    })
}

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let hex = b"0123456789ABCDEF";
            out.push('%');
            out.push(char::from(
                hex.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
            ));
            out.push(char::from(
                hex.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

/// The offer as the link or QR code a wallet opens (`openid-credential-offer://`).
#[must_use]
pub fn offer_link(offer: &Value) -> String {
    format!(
        "openid-credential-offer://?credential_offer={}",
        pct(&offer.to_string())
    )
}
