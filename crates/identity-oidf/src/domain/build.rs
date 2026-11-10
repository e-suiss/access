//! Payloads Access signs as a federation entity: its entity configuration as a leaf or trust
//! anchor, subordinate statements, resolve and trust mark status answers, and list answers
//! (§10.7.1 item 1). Signing is the identity signer's, with the realm's federation key and the
//! `typ` constants here.

use access_crypto::jose::output::{self, int, text};
use access_kernel::json::{Json, b64url_encode};

pub use crate::statement::ENTITY_TYP;
pub use crate::trust_mark::STATUS_TYP;

use crate::statement::MarkRef;

/// `typ` of a resolve answer.
pub const RESOLVE_TYP: &str = "resolve-response+jwt";
/// Media type of a resolve answer.
pub const RESOLVE_CONTENT_TYPE: &str = "application/resolve-response+jwt";

/// Why a payload could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// A time outside the I-JSON range, or `exp` not after `iat`.
    #[error("time")]
    Time,
    /// A key that is not an uncompressed P-256 point.
    #[error("key")]
    Key,
}

fn secs(ms: u64) -> Result<Json, BuildError> {
    int(ms / 1000).map_err(|_| BuildError::Time)
}

fn times(iat_ms: u64, exp_ms: u64) -> Result<[(String, Json); 2], BuildError> {
    if exp_ms <= iat_ms {
        return Err(BuildError::Time);
    }
    Ok([
        (String::from("iat"), secs(iat_ms)?),
        (String::from("exp"), secs(exp_ms)?),
    ])
}

fn strings(list: &[String]) -> Json {
    Json::Array(list.iter().map(|s| text(s)).collect())
}

/// A JWKS of P-256 signing keys from `(kid, SEC1 uncompressed point)` pairs.
///
/// # Errors
/// [`BuildError::Key`].
pub fn jwks_json(keys: &[(String, Vec<u8>)]) -> Result<Json, BuildError> {
    let mut out = Vec::with_capacity(keys.len());
    for (kid, sec1) in keys {
        let (Some(4), Some(x), Some(y), 65) = (
            sec1.first().copied(),
            sec1.get(1..33),
            sec1.get(33..65),
            sec1.len(),
        ) else {
            return Err(BuildError::Key);
        };
        out.push(Json::Object(vec![
            (String::from("kty"), text("EC")),
            (String::from("crv"), text("P-256")),
            (String::from("x"), text(&b64url_encode(x))),
            (String::from("y"), text(&b64url_encode(y))),
            (String::from("kid"), text(kid)),
            (String::from("use"), text("sig")),
            (String::from("alg"), text("ES256")),
        ]));
    }
    Ok(Json::Object(vec![(String::from("keys"), Json::Array(out))]))
}

/// An entity configuration.
#[derive(Clone, Debug)]
pub struct Configuration<'a> {
    /// The entity identifier, `iss` and `sub`.
    pub entity_id: &'a str,
    /// `iat`, Unix milliseconds.
    pub iat_ms: u64,
    /// `exp`, Unix milliseconds.
    pub exp_ms: u64,
    /// The federation JWKS.
    pub jwks: &'a Json,
    /// Superiors; empty for a trust anchor, and then omitted.
    pub authority_hints: &'a [String],
    /// Metadata by entity type.
    pub metadata: &'a Json,
    /// Trust marks it carries.
    pub trust_marks: &'a [MarkRef],
    /// `trust_mark_issuers`, for a trust anchor.
    pub trust_mark_issuers: Option<&'a Json>,
}

/// The payload of an entity configuration.
///
/// # Errors
/// [`BuildError`].
pub fn configuration(c: &Configuration<'_>) -> Result<String, BuildError> {
    let mut m = vec![
        (String::from("iss"), text(c.entity_id)),
        (String::from("sub"), text(c.entity_id)),
    ];
    m.extend(times(c.iat_ms, c.exp_ms)?);
    m.push((String::from("jwks"), c.jwks.clone()));
    if !c.authority_hints.is_empty() {
        m.push((String::from("authority_hints"), strings(c.authority_hints)));
    }
    m.push((String::from("metadata"), c.metadata.clone()));
    if !c.trust_marks.is_empty() {
        m.push((String::from("trust_marks"), marks(c.trust_marks)));
    }
    if let Some(i) = c.trust_mark_issuers {
        m.push((String::from("trust_mark_issuers"), i.clone()));
    }
    Ok(output::to_string(&Json::Object(m)))
}

fn marks(list: &[MarkRef]) -> Json {
    Json::Array(
        list.iter()
            .map(|t| {
                Json::Object(vec![
                    (String::from("trust_mark_type"), text(&t.trust_mark_type)),
                    (String::from("trust_mark"), text(&t.trust_mark)),
                ])
            })
            .collect(),
    )
}

/// A subordinate statement.
#[derive(Clone, Debug)]
pub struct Subordinate<'a> {
    /// The superior issuing it.
    pub iss: &'a str,
    /// The subordinate it is about.
    pub sub: &'a str,
    /// `iat`, Unix milliseconds.
    pub iat_ms: u64,
    /// `exp`, Unix milliseconds.
    pub exp_ms: u64,
    /// The subordinate's federation JWKS.
    pub jwks: &'a Json,
    /// `metadata_policy`.
    pub metadata_policy: Option<&'a Json>,
    /// `metadata` that replaces the subordinate's own values.
    pub metadata: Option<&'a Json>,
    /// `constraints.max_path_length`.
    pub max_path_length: Option<u32>,
}

/// The payload of a subordinate statement.
///
/// # Errors
/// [`BuildError`].
pub fn subordinate(s: &Subordinate<'_>) -> Result<String, BuildError> {
    let mut m = vec![
        (String::from("iss"), text(s.iss)),
        (String::from("sub"), text(s.sub)),
    ];
    m.extend(times(s.iat_ms, s.exp_ms)?);
    m.push((String::from("jwks"), s.jwks.clone()));
    if let Some(p) = s.metadata_policy {
        m.push((String::from("metadata_policy"), p.clone()));
    }
    if let Some(md) = s.metadata {
        m.push((String::from("metadata"), md.clone()));
    }
    if let Some(n) = s.max_path_length {
        m.push((
            String::from("constraints"),
            Json::Object(vec![(
                String::from("max_path_length"),
                Json::Int(i64::from(n)),
            )]),
        ));
    }
    Ok(output::to_string(&Json::Object(m)))
}

/// The payload of a resolve answer.
///
/// # Errors
/// [`BuildError`].
pub fn resolve_response(
    (iss, sub): (&str, &str),
    (iat_ms, exp_ms): (u64, u64),
    metadata: &Json,
    trust_chain: &[String],
    trust_marks: &[MarkRef],
) -> Result<String, BuildError> {
    let mut m = vec![
        (String::from("iss"), text(iss)),
        (String::from("sub"), text(sub)),
    ];
    m.extend(times(iat_ms, exp_ms)?);
    m.push((String::from("metadata"), metadata.clone()));
    m.push((String::from("trust_chain"), strings(trust_chain)));
    if !trust_marks.is_empty() {
        m.push((String::from("trust_marks"), marks(trust_marks)));
    }
    Ok(output::to_string(&Json::Object(m)))
}

/// The payload of a trust mark status answer.
///
/// # Errors
/// [`BuildError`].
pub fn status_response(
    iss: &str,
    trust_mark: &str,
    status: &str,
    iat_ms: u64,
) -> Result<String, BuildError> {
    Ok(output::to_string(&Json::Object(vec![
        (String::from("iss"), text(iss)),
        (String::from("iat"), secs(iat_ms)?),
        (String::from("trust_mark"), text(trust_mark)),
        (String::from("status"), text(status)),
    ])))
}

/// A list answer: the subordinates' entity identifiers as a JSON array.
#[must_use]
pub fn list_response(entities: &[String]) -> String {
    output::to_string(&strings(entities))
}

#[cfg(test)]
mod tests;
