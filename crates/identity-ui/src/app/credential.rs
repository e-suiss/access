//! The `PublicKeyCredential` JSON a browser returns (`toJSON()`, WebAuthn L3 §5.1), decoded
//! into the byte views the relying party verifies. Anything malformed is `None`: a refusal,
//! never an error that says more (CR-40).

use access_identity_webauthn::domain::ceremony::{
    AssertionResponse, ClientExtensionResults, RegistrationResponse,
};
use access_kernel::json::b64url_decode;
use serde::Deserialize;
use serde_json::Value;

/// Longest credential JSON accepted (CR-10).
pub(crate) const MAX_LEN: usize = 16 * 1024;

/// At most this many transports are kept (OP-146 m.9 (g)).
const MAX_TRANSPORTS: usize = 8;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Raw {
    #[serde(rename = "rawId")]
    id: String,
    #[serde(rename = "type")]
    kind: String,
    response: RawResponse,
    #[serde(default)]
    client_extension_results: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(default)]
    authenticator_data: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    user_handle: Option<String>,
    #[serde(default)]
    attestation_object: Option<String>,
    #[serde(default)]
    transports: Vec<String>,
}

/// A decoded assertion.
pub(crate) struct Assertion {
    raw_id: Vec<u8>,
    client_data_json: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    user_handle: Option<Vec<u8>>,
}

impl Assertion {
    pub(crate) fn response(&self) -> AssertionResponse<'_> {
        AssertionResponse {
            raw_id: &self.raw_id,
            client_data_json: &self.client_data_json,
            authenticator_data: &self.authenticator_data,
            signature: &self.signature,
            user_handle: self.user_handle.as_deref(),
        }
    }
}

/// A decoded registration.
pub(crate) struct Registration {
    raw_id: Vec<u8>,
    client_data_json: Vec<u8>,
    attestation_object: Vec<u8>,
    transports: Vec<String>,
    extensions: ClientExtensionResults,
}

impl Registration {
    pub(crate) fn response(&self) -> RegistrationResponse<'_> {
        RegistrationResponse {
            raw_id: &self.raw_id,
            client_data_json: &self.client_data_json,
            attestation_object: &self.attestation_object,
            transports: &self.transports,
            extensions: self.extensions,
        }
    }
}

fn parse(text: &str) -> Option<Raw> {
    if text.len() > MAX_LEN {
        return None;
    }
    let raw: Raw = serde_json::from_str(text).ok()?;
    (raw.kind == "public-key").then_some(raw)
}

fn bytes(text: &str) -> Option<Vec<u8>> {
    b64url_decode(text).ok()
}

/// An assertion from `navigator.credentials.get()`.
pub(crate) fn assertion(text: &str) -> Option<Assertion> {
    let raw = parse(text)?;
    let r = raw.response;
    Some(Assertion {
        raw_id: bytes(&raw.id)?,
        client_data_json: bytes(&r.client_data_json)?,
        authenticator_data: bytes(&r.authenticator_data?)?,
        signature: bytes(&r.signature?)?,
        user_handle: match r.user_handle {
            Some(h) => Some(bytes(&h)?),
            None => None,
        },
    })
}

/// An assertion an app's platform passkey API returned, field by field (base64url), as the
/// approver SDK carries it (OP-157 m.17).
pub(crate) fn assertion_parts(
    credential_id: &str,
    authenticator_data: &str,
    client_data_json: &str,
    signature: &str,
    user_handle: Option<&str>,
) -> Option<Assertion> {
    let total = [
        credential_id,
        authenticator_data,
        client_data_json,
        signature,
    ]
    .iter()
    .map(|f| f.len())
    .sum::<usize>()
    .checked_add(user_handle.map_or(0, str::len))?;
    if total > MAX_LEN {
        return None;
    }
    Some(Assertion {
        raw_id: bytes(credential_id)?,
        client_data_json: bytes(client_data_json)?,
        authenticator_data: bytes(authenticator_data)?,
        signature: bytes(signature)?,
        user_handle: match user_handle {
            Some(h) => Some(bytes(h)?),
            None => None,
        },
    })
}

/// A registration from `navigator.credentials.create()`.
pub(crate) fn registration(text: &str) -> Option<Registration> {
    let raw = parse(text)?;
    let r = raw.response;
    let extensions = match raw.client_extension_results {
        Some(v) => ClientExtensionResults::from_json(&serde_json::to_vec(&v).ok()?).ok()?,
        None => ClientExtensionResults::default(),
    };
    if r.transports.len() > MAX_TRANSPORTS {
        return None;
    }
    Some(Registration {
        raw_id: bytes(&raw.id)?,
        client_data_json: bytes(&r.client_data_json)?,
        attestation_object: bytes(&r.attestation_object?)?,
        transports: r.transports,
        extensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-10, §10.2.4
    #[test]
    fn credential_json_is_bounded_and_typed() {
        let ok = r#"{"id":"AQ","rawId":"AQ","type":"public-key","response":{"clientDataJSON":"AQ","authenticatorData":"Ag","signature":"Aw"},"clientExtensionResults":{}}"#;
        let a = assertion(ok).unwrap();
        assert_eq!(a.response().signature, [3]);
        assert!(a.response().user_handle.is_none());
        assert!(assertion(&ok.replace("public-key", "password")).is_none());
        assert!(assertion(&ok.replace(r#""signature":"Aw""#, r#""x":"y""#)).is_none());
        assert!(assertion(&format!("{ok}{}", " ".repeat(MAX_LEN))).is_none());
        assert!(registration(ok).is_none());
    }

    // CR-10, OP-157 m.17
    #[test]
    fn an_assertion_in_fields_is_bounded_and_decoded() {
        let a = assertion_parts("AQ", "Ag", "Aw", "BA", Some("BQ")).unwrap();
        let r = a.response();
        assert_eq!(
            (
                r.raw_id,
                r.authenticator_data,
                r.client_data_json,
                r.signature
            ),
            (&[1][..], &[2][..], &[3][..], &[4][..])
        );
        assert_eq!(r.user_handle, Some(&[5][..]));
        assert!(assertion_parts("AQ", "Ag", "Aw", "B!", None).is_none());
        assert!(assertion_parts(&"A".repeat(MAX_LEN), "Ag", "Aw", "BA", None).is_none());
    }
}
