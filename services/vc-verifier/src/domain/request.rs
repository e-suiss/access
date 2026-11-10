//! The signed request object (OID4VP 1.0 §5, JAR; HAIP; Ek B 4833): `client_id` with the
//! `x509_hash` prefix of the verifier's certificate, `response_mode` `direct_post.jwt`, the DCQL
//! query, the nonce, and the request's own encryption key in `client_metadata`. The same
//! `openid4vp://` link opens it on the same device and, as a QR code, from another one.

use std::fmt::Write as _;

use access_kernel::json::b64url_encode;
use serde_json::{Value, json};
use suiss_crypto::signer::{SignError, Signer};

use super::dcql::Query;
use super::jwe::ENC_VALUES;

/// The request object `typ` (RFC 9101).
pub const TYP: &str = "oauth-authz-req+jwt";
/// The static wallet audience (OID4VP 1.0 §5.8).
pub const AUDIENCE: &str = "https://self-issued.me/v2";
/// How long a request object is valid, milliseconds.
pub const LIFETIME_MS: u64 = 5 * 60 * 1000;

/// How the wallet is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The wallet is on the device that started the request; it redirects back.
    SameDevice,
    /// The wallet is on another device, reached by a QR code; the starter polls.
    CrossDevice,
}

impl Mode {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SameDevice => "same-device",
            Self::CrossDevice => "cross-device",
        }
    }

    /// The mode of a wire name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "same-device" => Some(Self::SameDevice),
            "cross-device" => Some(Self::CrossDevice),
            _ => None,
        }
    }
}

/// `x509_hash:<base64url SHA-256 of the leaf>` (OID4VP 1.0 §5.9.3).
#[must_use]
pub fn client_id(leaf: &[u8]) -> String {
    format!(
        "x509_hash:{}",
        b64url_encode(&suiss_crypto::digest::sha256(leaf))
    )
}

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The link the wallet opens: `openid4vp://?client_id=…&request_uri=…`.
#[must_use]
pub fn wallet_link(client_id: &str, request_uri: &str) -> String {
    format!(
        "openid4vp://?client_id={}&request_uri={}",
        pct(client_id),
        pct(request_uri)
    )
}

/// What one request object says.
#[derive(Clone, Debug)]
pub struct Object<'a> {
    /// `client_id`.
    pub client_id: &'a str,
    /// `response_uri`.
    pub response_uri: &'a str,
    /// `nonce`.
    pub nonce: &'a str,
    /// `state`.
    pub state: &'a str,
    /// The DCQL query.
    pub query: &'a Query,
    /// The response key's JWK coordinates and `kid`.
    pub key: (&'a str, &'a str, &'a str),
    /// Issued at, milliseconds.
    pub now_ms: u64,
}

fn standard_b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18_u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> shift) & 63).unwrap_or(0);
                out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

impl Object<'_> {
    /// The payload.
    #[must_use]
    pub fn payload(&self) -> Value {
        let (x, y, kid) = self.key;
        let secs = self.now_ms / 1000;
        json!({
            "aud": AUDIENCE,
            "client_id": self.client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post.jwt",
            "response_uri": self.response_uri,
            "nonce": self.nonce,
            "state": self.state,
            "dcql_query": self.query.to_json(),
            "client_metadata": {
                "jwks": { "keys": [{
                    "kty": "EC", "crv": "P-256", "x": x, "y": y,
                    "use": "enc", "alg": "ECDH-ES", "kid": kid,
                }]},
                "encrypted_response_enc_values_supported": ENC_VALUES,
                "vp_formats_supported": {
                    "dc+sd-jwt": {
                        "sd-jwt_alg_values": ["ES256"],
                        "kb-jwt_alg_values": ["ES256"],
                    },
                    "mso_mdoc": {
                        "issuerauth_alg_values": [-7],
                        "deviceauth_alg_values": [-7],
                    },
                },
            },
            "iat": secs,
            "exp": secs.saturating_add(LIFETIME_MS / 1000),
        })
    }

    /// The signed request object: ES256 by the verifier's key, `x5c` its certificate chain.
    ///
    /// # Errors
    /// [`SignError`].
    pub fn sign(&self, signer: &dyn Signer, chain: &[Vec<u8>]) -> Result<String, SignError> {
        let x5c: Vec<String> = chain.iter().map(|c| standard_b64(c)).collect();
        let header = json!({ "alg": "ES256", "typ": TYP, "x5c": x5c });
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(self.payload().to_string().as_bytes())
        );
        let sig = signer.sign(input.as_bytes())?;
        Ok(format!("{input}.{}", b64url_encode(&sig)))
    }
}

/// RFC 4648 §4 base64 with padding.
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    standard_b64(bytes)
}
