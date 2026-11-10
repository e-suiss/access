//! Entity statements (OpenID Federation 1.0 §3): entity configurations, subordinate statements,
//! their keys and their validation (IDP-19 item 2).

use access_crypto::oauth::ClientKey;
use access_kernel::json::{Json, b64url_decode};

use crate::jws::{self, strings, time_ms};

/// `typ` of an entity statement.
pub const ENTITY_TYP: &str = "entity-statement+jwt";
/// `typ` of a trust mark.
pub const TRUST_MARK_TYP: &str = "trust-mark+jwt";
/// Media type of an offline trust chain: a JSON array of entity statements.
pub const TRUST_CHAIN_TYP: &str = "trust-chain+json";
/// The path-suffix well-known location of an entity configuration.
pub const WELL_KNOWN: &str = "/.well-known/openid-federation";
/// Media type of an entity statement.
pub const CONTENT_TYPE: &str = "application/entity-statement+jwt";
/// Largest entity statement read.
pub const MAX_STATEMENT: usize = 64 * 1024;
/// Clock skew allowed on `iat` and `exp` (§10.7.1 item 3).
pub const SKEW_MS: u64 = 60_000;
/// Most keys read from one JWKS.
pub const MAX_KEYS: usize = 32;
/// Longest entity identifier.
pub const MAX_ENTITY_ID: usize = 2048;

const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Why an entity statement, trust mark or request object is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OidfError {
    /// Larger than the limit.
    #[error("size")]
    Size,
    /// Not a compact JWS.
    #[error("format")]
    Format,
    /// The header is outside the profile.
    #[error("header")]
    Header,
    /// The `typ` is not the artefact's.
    #[error("typ")]
    Typ,
    /// The algorithm is not ES256 or RS256 (MD-3).
    #[error("algorithm")]
    Algorithm,
    /// No `kid`, or not exactly one key fits it.
    #[error("key")]
    Key,
    /// The signature does not verify.
    #[error("signature")]
    Signature,
    /// A claim is missing or malformed.
    #[error("claims")]
    Claims,
    /// An entity identifier is not an `https` URL without query or fragment.
    #[error("entity-id")]
    EntityId,
    /// Not yet valid or expired.
    #[error("time")]
    Time,
    /// The JWKS is malformed or holds private key material.
    #[error("jwks")]
    Jwks,
    /// A `crit` or `metadata_policy_crit` names something not understood.
    #[error("crit")]
    Crit,
    /// A constraint is malformed or not supported.
    #[error("constraints")]
    Constraints,
    /// A trust mark is refused.
    #[error("trust-mark")]
    TrustMark,
    /// A trust mark needs a delegation, which is not accepted.
    #[error("delegation")]
    Delegation,
    /// The audience is not this entity.
    #[error("audience")]
    Audience,
}

impl OidfError {
    /// The stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Size => "oidf-size",
            Self::Format => "oidf-format",
            Self::Header => "oidf-header",
            Self::Typ => "oidf-typ",
            Self::Algorithm => "oidf-algorithm",
            Self::Key => "oidf-key",
            Self::Signature => "oidf-signature",
            Self::Claims => "oidf-claims",
            Self::EntityId => "oidf-entity-id",
            Self::Time => "oidf-time",
            Self::Jwks => "oidf-jwks",
            Self::Crit => "oidf-crit",
            Self::Constraints => "oidf-constraints",
            Self::TrustMark => "oidf-trust-mark",
            Self::Delegation => "oidf-delegation",
            Self::Audience => "oidf-audience",
        }
    }
}

/// A public key from a JWKS with its `kid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwk {
    /// `kid`, when present; keys without one never verify a statement.
    pub kid: Option<String>,
    /// The key.
    pub key: ClientKey,
}

/// A trust mark an entity configuration carries, as listed in its `trust_marks` claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkRef {
    /// `trust_mark_type`.
    pub trust_mark_type: String,
    /// The trust mark JWT.
    pub trust_mark: String,
}

/// A validated entity statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityStatement {
    /// The issuer's entity identifier.
    pub iss: String,
    /// The subject's entity identifier; equal to `iss` in an entity configuration.
    pub sub: String,
    /// `iat`, Unix milliseconds.
    pub iat_ms: u64,
    /// `exp`, Unix milliseconds.
    pub exp_ms: u64,
    /// The subject's federation keys.
    pub jwks: Vec<Jwk>,
    /// The subject's superiors, in an entity configuration.
    pub authority_hints: Vec<String>,
    /// `metadata`, by entity type.
    pub metadata: Option<Json>,
    /// `metadata_policy`, by entity type, in a subordinate statement.
    pub metadata_policy: Option<Json>,
    /// `constraints.max_path_length`.
    pub max_path_length: Option<u32>,
    /// `constraints.allowed_entity_types`.
    pub allowed_entity_types: Option<Vec<String>>,
    /// `trust_marks`, in an entity configuration.
    pub trust_marks: Vec<MarkRef>,
    /// `trust_mark_issuers`, in a trust anchor's configuration.
    pub trust_mark_issuers: Option<Json>,
    /// `trust_mark_owners`, in a trust anchor's configuration.
    pub trust_mark_owners: Option<Json>,
    /// Every claim as read.
    pub claims: Json,
    /// The compact JWS.
    pub raw: String,
}

impl EntityStatement {
    /// Whether it is an entity configuration (`iss` = `sub`).
    #[must_use]
    pub fn is_configuration(&self) -> bool {
        self.iss == self.sub
    }

    /// A `federation_entity` metadata endpoint such as `federation_fetch_endpoint`.
    #[must_use]
    pub fn federation_entity_endpoint(&self, name: &str) -> Option<&str> {
        self.metadata
            .as_ref()?
            .get("federation_entity")?
            .get(name)?
            .as_str()
    }

    /// The metadata of one entity type.
    #[must_use]
    pub fn metadata_of(&self, entity_type: &str) -> Option<&Json> {
        self.metadata.as_ref()?.get(entity_type)
    }
}

/// Whether `id` is an entity identifier: an `https` URL with a host, without query, fragment
/// or user info.
#[must_use]
pub fn entity_id_ok(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    id.len() <= MAX_ENTITY_ID
        && id.bytes().all(|c| c.is_ascii_graphic())
        && !id.contains(['?', '#'])
        && !host.is_empty()
        && !host.contains('@')
}

fn members(v: &Json) -> Option<&[(String, Json)]> {
    match v {
        Json::Object(m) => Some(m),
        _ => None,
    }
}

fn text<'a>(m: &'a [(String, Json)], name: &str) -> Option<&'a str> {
    m.iter()
        .find(|(k, _)| k == name)
        .and_then(|(_, v)| v.as_str())
}

fn bytes(m: &[(String, Json)], name: &str) -> Result<Vec<u8>, OidfError> {
    text(m, name)
        .and_then(|s| b64url_decode(s).ok())
        .ok_or(OidfError::Jwks)
}

fn jwk(m: &[(String, Json)]) -> Result<Option<Jwk>, OidfError> {
    if m.iter().any(|(k, _)| PRIVATE_MEMBERS.contains(&k.as_str())) {
        return Err(OidfError::Jwks);
    }
    if text(m, "use").is_some_and(|u| u != "sig") {
        return Ok(None);
    }
    let key = match (text(m, "kty"), text(m, "crv")) {
        (Some("EC"), Some("P-256")) => {
            let (x, y) = (bytes(m, "x")?, bytes(m, "y")?);
            if x.len() != 32 || y.len() != 32 {
                return Err(OidfError::Jwks);
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(4);
            sec1.extend(x);
            sec1.extend(y);
            ClientKey::P256(sec1)
        }
        (Some("RSA"), None) => ClientKey::Rsa {
            n: bytes(m, "n")?,
            e: bytes(m, "e")?,
        },
        _ => return Ok(None),
    };
    Ok(Some(Jwk {
        kid: text(m, "kid").map(String::from),
        key,
    }))
}

/// The public signing keys of a JWKS object (`{"keys": [...]}`): EC P-256 and RSA keys; keys of
/// another type or use are skipped; a set holding private key material is refused whole.
///
/// # Errors
/// [`OidfError::Jwks`].
pub fn parse_jwks(v: &Json) -> Result<Vec<Jwk>, OidfError> {
    let Some(Json::Array(keys)) = v.get("keys") else {
        return Err(OidfError::Jwks);
    };
    if keys.len() > MAX_KEYS {
        return Err(OidfError::Jwks);
    }
    let mut out = Vec::new();
    for k in keys {
        if let Some(j) = jwk(members(k).ok_or(OidfError::Jwks)?)? {
            out.push(j);
        }
    }
    Ok(out)
}

/// Reads `iss` and `sub` without verifying anything, to select the keys to verify with.
///
/// # Errors
/// [`OidfError`].
pub fn peek(jwt: &str) -> Result<(String, String), OidfError> {
    let parts = jws::split(jwt, MAX_STATEMENT)?;
    let get = |n: &str| {
        parts
            .payload
            .get(n)
            .and_then(Json::as_str)
            .map(String::from)
            .ok_or(OidfError::Claims)
    };
    Ok((get("iss")?, get("sub")?))
}

/// The keys an unverified entity configuration names for itself.
pub(crate) fn self_keys(jwt: &str) -> Result<Vec<Jwk>, OidfError> {
    let parts = jws::split(jwt, MAX_STATEMENT)?;
    parse_jwks(parts.payload.get("jwks").ok_or(OidfError::Jwks)?)
}

fn object(v: Option<&Json>) -> Result<Option<Json>, OidfError> {
    match v {
        None => Ok(None),
        Some(o @ Json::Object(m)) if m.iter().all(|(_, t)| matches!(t, Json::Object(_))) => {
            Ok(Some(o.clone()))
        }
        Some(_) => Err(OidfError::Claims),
    }
}

fn constraints(c: Option<&Json>) -> Result<(Option<u32>, Option<Vec<String>>), OidfError> {
    let Some(c) = c else {
        return Ok((None, None));
    };
    let m = members(c).ok_or(OidfError::Constraints)?;
    let mut max = None;
    let mut types = None;
    for (k, v) in m {
        match k.as_str() {
            "max_path_length" => {
                max = Some(
                    v.as_int()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or(OidfError::Constraints)?,
                );
            }
            "allowed_entity_types" => types = Some(strings(v, OidfError::Constraints)?),
            _ => return Err(OidfError::Constraints),
        }
    }
    Ok((max, types))
}

fn trust_marks(v: Option<&Json>) -> Result<Vec<MarkRef>, OidfError> {
    let Some(v) = v else {
        return Ok(Vec::new());
    };
    let Json::Array(items) = v else {
        return Err(OidfError::Claims);
    };
    items
        .iter()
        .map(|i| {
            let m = members(i).ok_or(OidfError::Claims)?;
            Ok(MarkRef {
                trust_mark_type: String::from(text(m, "trust_mark_type").ok_or(OidfError::Claims)?),
                trust_mark: String::from(text(m, "trust_mark").ok_or(OidfError::Claims)?),
            })
        })
        .collect()
}

/// The checks of an entity statement (OpenID Federation 1.0, "Validating an Entity
/// Statement"): compact JWS of `typ` `entity-statement+jwt`, ES256 or RS256, a `kid` naming
/// exactly one of `keys`, a valid signature, `iss`/`sub` entity identifiers, `iat` not ahead
/// and `exp` not past (each ±[`SKEW_MS`]), `jwks` present, no `crit` or
/// `metadata_policy_crit` naming anything not understood, `metadata` and `metadata_policy`
/// objects of objects, `metadata_policy` only in a subordinate statement, `authority_hints`
/// and `trust_marks` only in a configuration, and only the supported constraints.
///
/// # Errors
/// [`OidfError`].
pub fn verify_statement(
    jwt: &str,
    keys: &[Jwk],
    now_ms: u64,
) -> Result<EntityStatement, OidfError> {
    verify_with(jwt, keys, now_ms, &[])
}

/// [`verify_statement`] allowing the header members `extra` besides `alg`, `kid` and `typ`.
pub(crate) fn verify_with(
    jwt: &str,
    keys: &[Jwk],
    now_ms: u64,
    extra: &[&str],
) -> Result<EntityStatement, OidfError> {
    let parts = jws::split(jwt, MAX_STATEMENT)?;
    let (alg, kid) = jws::check_header(&parts.header, Some(&[ENTITY_TYP]), extra)?;
    jws::verify(&parts, alg, &kid, keys)?;
    let c = &parts.payload;
    let claim = |n: &str| c.get(n).and_then(Json::as_str).map(String::from);
    let iss = claim("iss").ok_or(OidfError::Claims)?;
    let sub = claim("sub").ok_or(OidfError::Claims)?;
    if !entity_id_ok(&iss) || !entity_id_ok(&sub) {
        return Err(OidfError::EntityId);
    }
    let iat_ms = time_ms(c, "iat")?.ok_or(OidfError::Time)?;
    let exp_ms = time_ms(c, "exp")?.ok_or(OidfError::Time)?;
    if iat_ms > now_ms.saturating_add(SKEW_MS)
        || exp_ms.saturating_add(SKEW_MS) <= now_ms
        || exp_ms <= iat_ms
    {
        return Err(OidfError::Time);
    }
    if c.get("crit").is_some() || c.get("metadata_policy_crit").is_some() {
        return Err(OidfError::Crit);
    }
    let jwks = parse_jwks(c.get("jwks").ok_or(OidfError::Jwks)?)?;
    if jwks.is_empty() {
        return Err(OidfError::Jwks);
    }
    let configuration = iss == sub;
    let metadata = object(c.get("metadata"))?;
    let metadata_policy = object(c.get("metadata_policy"))?;
    let authority_hints = match c.get("authority_hints") {
        None => Vec::new(),
        Some(v) => {
            let hints = strings(v, OidfError::Claims)?;
            if hints.is_empty() || hints.iter().any(|h| !entity_id_ok(h)) {
                return Err(OidfError::Claims);
            }
            hints
        }
    };
    let trust_marks = trust_marks(c.get("trust_marks"))?;
    let (max_path_length, allowed_entity_types) = constraints(c.get("constraints"))?;
    if configuration
        && (metadata_policy.is_some()
            || max_path_length.is_some()
            || allowed_entity_types.is_some())
    {
        return Err(OidfError::Claims);
    }
    if !configuration && (!authority_hints.is_empty() || !trust_marks.is_empty()) {
        return Err(OidfError::Claims);
    }
    let side = |n: &str| match c.get(n) {
        None => Ok(None),
        Some(o @ Json::Object(_)) if configuration => Ok(Some(o.clone())),
        Some(_) => Err(OidfError::Claims),
    };
    Ok(EntityStatement {
        trust_mark_issuers: side("trust_mark_issuers")?,
        trust_mark_owners: side("trust_mark_owners")?,
        iss,
        sub,
        iat_ms,
        exp_ms,
        jwks,
        authority_hints,
        metadata,
        metadata_policy,
        max_path_length,
        allowed_entity_types,
        trust_marks,
        claims: c.clone(),
        raw: String::from(jwt),
    })
}

/// An entity configuration of `entity_id`: self-signed with one of the keys it publishes,
/// `iss` = `sub` = `entity_id`.
///
/// # Errors
/// [`OidfError`].
pub fn verify_configuration(
    jwt: &str,
    entity_id: &str,
    now_ms: u64,
) -> Result<EntityStatement, OidfError> {
    let keys = self_keys(jwt)?;
    let s = verify_statement(jwt, &keys, now_ms)?;
    if s.iss != entity_id || !s.is_configuration() {
        return Err(OidfError::Claims);
    }
    Ok(s)
}

/// The URL of the entity configuration of `entity_id` (path-suffix form, §10.7.1 item 2).
#[must_use]
pub fn configuration_url(entity_id: &str) -> String {
    let mut url = String::from(entity_id.trim_end_matches('/'));
    url.push_str(WELL_KNOWN);
    url
}

#[cfg(test)]
mod tests;
