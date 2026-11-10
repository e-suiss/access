//! Issuing one person-attribute SD-JWT VC (RFC 9901, SD-JWT VC; E55, Ek B 4196): the realm
//! issuer signs with its key named by `kid` (its 32-byte thumbprint), the attribute is one
//! selectively disclosable claim, `cnf.jwk` is the proven holder key, `vct` is under the issuer
//! and `status.status_list` names the credential's entry. The holder discloses the attribute or
//! nothing (minimum disclosure, PI-3); the issuer reads no value it was not given.

use access_kernel::json::{Json, b64url_encode};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use serde_json::{Value, json};
use suiss_crypto::signer::{SignError, Signer};

use crate::domain::types::PersonAttribute;

/// The issuer-signed JWT `typ`.
pub const TYP: &str = "dc+sd-jwt";
/// How long a person-attribute credential holds: 90 days.
pub const LIFETIME_MS: u64 = 90 * 24 * 3_600_000;

/// What one credential says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential<'a> {
    /// The realm issuer.
    pub issuer: &'a str,
    /// The type.
    pub attribute: PersonAttribute,
    /// The attribute's value: `true` for a fact, the name for `verified_name`.
    pub value: Value,
    /// The holder key the proof showed.
    pub holder: PublicKey,
    /// The credential's status list entry: index and list URI.
    pub status: (u64, &'a str),
    /// Issued at, milliseconds.
    pub now_ms: u64,
    /// The disclosure salt, 16 bytes from the RNG port.
    pub salt: [u8; 16],
}

/// Why a credential is not issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IssueError {
    /// The value does not fit the type: a fact must be `true`, a name must be text.
    #[error("credential-value")]
    Value,
    /// The issuer key could not sign.
    #[error("credential-sign")]
    Sign,
}

impl From<SignError> for IssueError {
    fn from(_: SignError) -> Self {
        Self::Sign
    }
}

/// The holder key as `cnf.jwk`.
#[must_use]
pub fn jwk(key: &PublicKey) -> Option<Value> {
    match key {
        PublicKey::P256(sec1) => {
            let (x, y) = sec1.get(1..33).zip(sec1.get(33..65))?;
            Some(
                json!({ "kty": "EC", "crv": "P-256", "x": b64url_encode(x), "y": b64url_encode(y) }),
            )
        }
        PublicKey::Ed25519(pk) => {
            Some(json!({ "kty": "OKP", "crv": "Ed25519", "x": b64url_encode(pk) }))
        }
        PublicKey::MlDsa(..) => None,
    }
}

fn alg(signer: &dyn Signer) -> Option<&'static str> {
    use access_kernel::verify::cose::Algorithm;
    match signer.algorithm() {
        Algorithm::Es256 | Algorithm::Esp256 => Some("ES256"),
        Algorithm::Ed25519 => Some("Ed25519"),
        _ => None,
    }
}

/// The disclosure of the attribute claim and its digest.
#[must_use]
pub fn disclosure(c: &Credential<'_>) -> (String, String) {
    let d = b64url_encode(
        json!([b64url_encode(&c.salt), c.attribute.name(), c.value])
            .to_string()
            .as_bytes(),
    );
    let digest = b64url_encode(&suiss_crypto::digest::sha256(d.as_bytes()));
    (d, digest)
}

/// Issues the credential: `<issuer-signed JWT>~<disclosure>~`.
///
/// # Errors
/// [`IssueError`].
pub fn issue(signer: &dyn Signer, c: &Credential<'_>) -> Result<String, IssueError> {
    let fits = match (&c.value, c.attribute.boolean()) {
        (Value::Bool(true), true) => true,
        (Value::String(s), false) => !s.trim().is_empty() && s.len() <= 512,
        _ => false,
    };
    if !fits {
        return Err(IssueError::Value);
    }
    let alg = alg(signer).ok_or(IssueError::Sign)?;
    let holder = jwk(&c.holder).ok_or(IssueError::Value)?;
    let (d, digest) = disclosure(c);
    let iat = c.now_ms / 1000;
    let payload = json!({
        "iss": c.issuer.trim_end_matches('/'),
        "vct": c.attribute.vct(c.issuer),
        "iat": iat,
        "exp": iat.saturating_add(LIFETIME_MS / 1000),
        "cnf": { "jwk": holder },
        "status": { "status_list": { "idx": c.status.0, "uri": c.status.1 } },
        "_sd": [digest],
        "_sd_alg": "sha-256",
    });
    let header = json!({
        "alg": alg,
        "kid": b64url_encode(&thumbprint(&signer.public_key())),
        "typ": TYP,
    });
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(payload.to_string().as_bytes())
    );
    let sig = signer.sign(input.as_bytes())?;
    Ok(format!("{input}.{}~{d}~", b64url_encode(&sig)))
}

/// The credential configuration id a credential request names, from its JSON body (OID4VCI 1.0
/// §8.2): `credential_configuration_id`; `credential_identifier` and any `format` request are
/// not served.
#[must_use]
pub fn requested(body: &Json) -> Option<&str> {
    if body.get("credential_identifier").is_some() || body.get("format").is_some() {
        return None;
    }
    body.get("credential_configuration_id")
        .and_then(Json::as_str)
}
