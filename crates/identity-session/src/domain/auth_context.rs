//! The `auth_context` artifact (OP-149 m.8): what a session's authentication was, as
//! deterministic CBOR a product can keep with a record and cite by digest. It names the session
//! only by a domain-separated digest, never by its id. The schema is
//! `conformance/cddl/auth-context.cddl`.

use suiss_crypto::dcbor::{self, EncodeError, Limits, Value};
use suiss_crypto::digest::{Digest, context_digest};

use super::assurance::{Aal, AssuranceVector};

/// Version of the artifact.
pub const VERSION: u64 = 1;

/// Context label of the artifact's digest (OP-149 m.8).
pub const DIGEST_LABEL: &str = "suiss/auth-context/v1";

/// Context label of `session_ref`.
pub const SESSION_LABEL: &str = "suiss/auth-context/session/v1";

/// Context label of `ais_digest`, the digest of the session's whole assurance statement.
pub const AIS_LABEL: &str = "suiss/auth-context/ais/v1";

/// The content type of the signed artifact's `COSE_Sign1`.
pub const CONTENT_TYPE: &str = "application/access-auth-context+cbor";

/// Longest `content_type` a caller may bind.
pub const MAX_CONTENT_TYPE: usize = 127;

/// The flags of the assurance vector (§10.1.6) the artifact carries, by name.
pub const FLAGS: [&str; 7] = [
    "app_controlled_factor",
    "hardware_bound",
    "human_presence",
    "non_custodial",
    "phishing_resistant",
    "synced",
    "uv",
];

/// The content a caller binds the artifact to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Content {
    /// A media type (RFC 6838 `type/subtype`).
    pub content_type: String,
    /// SHA-256 of the content.
    pub digest: [u8; 32],
}

/// Why a content binding is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid content binding")]
pub struct InvalidContent;

fn token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&c))
}

impl Content {
    /// A content binding: a `type/subtype` media type without parameters, lower case.
    ///
    /// # Errors
    /// [`InvalidContent`].
    pub fn new(content_type: &str, digest: [u8; 32]) -> Result<Self, InvalidContent> {
        let ok = content_type.len() <= MAX_CONTENT_TYPE
            && !content_type.bytes().any(|c| c.is_ascii_uppercase())
            && content_type
                .split_once('/')
                .is_some_and(|(t, s)| token(t) && token(s));
        if ok {
            Ok(Self {
                content_type: String::from(content_type),
                digest,
            })
        } else {
            Err(InvalidContent)
        }
    }
}

/// The artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthContext {
    /// The realm's issuer.
    pub realm: String,
    /// [`session_ref`] of the session.
    pub session_ref: Digest,
    /// NIST AAL.
    pub aal: Aal,
    /// The vector's flags that are set, by name.
    pub assurance_flags: Vec<&'static str>,
    /// When the session authenticated, Unix milliseconds.
    pub auth_time: u64,
    /// When it last stepped up, Unix milliseconds.
    pub step_up_time: Option<u64>,
    /// [`ais_digest`] of the session's assurance.
    pub ais_digest: Digest,
    /// The device Instance the session is bound to, when it registered one (OP-149 m.30 (c)).
    pub instance: Option<[u8; 16]>,
    /// The content it is bound to.
    pub content: Option<Content>,
}

/// The `aal` value.
#[must_use]
pub const fn aal_name(aal: Aal) -> &'static str {
    match aal {
        Aal::Aal1 => "aal1",
        Aal::Aal2 => "aal2",
        Aal::Aal3 => "aal3",
    }
}

/// `session_ref`: the session id under its own context label; the id never leaves.
#[must_use]
pub fn session_ref(session: &[u8; 16]) -> Digest {
    context_digest(SESSION_LABEL, session)
}

/// The set flags of `v`, in [`FLAGS`] order (bytewise, so a CBOR set).
#[must_use]
pub fn flags(v: &AssuranceVector) -> Vec<&'static str> {
    let set = [
        v.app_controlled_factor,
        v.hardware_bound,
        v.human_presence,
        v.non_custodial,
        v.phishing_resistant,
        v.synced,
        v.uv,
    ];
    FLAGS
        .iter()
        .zip(set)
        .filter_map(|(name, on)| on.then_some(*name))
        .collect()
}

fn ais_value(v: &AssuranceVector) -> Value {
    let mut m = vec![
        (Value::text("aal"), Value::text(aal_name(v.aal))),
        (
            Value::text("flags"),
            Value::Array(flags(v).into_iter().map(Value::text).collect()),
        ),
        (Value::text("auth_time"), Value::Unsigned(v.auth_time_ms)),
    ];
    if let Some(l) = v.loa_eidas {
        let name = match l {
            super::assurance::LoaEidas::Low => "low",
            super::assurance::LoaEidas::Substantial => "substantial",
            super::assurance::LoaEidas::High => "high",
        };
        m.push((Value::text("loa_eidas"), Value::text(name)));
    }
    Value::Map(m)
}

/// `ais_digest`: the digest of the session's whole assurance statement (the vector of §10.1.6),
/// so the artifact commits to it without carrying it.
///
/// # Errors
/// [`EncodeError`] past the encoding limits.
pub fn ais_digest(v: &AssuranceVector) -> Result<Digest, EncodeError> {
    Ok(context_digest(
        AIS_LABEL,
        &dcbor::encode(&ais_value(v), Limits::CEILING)?,
    ))
}

impl AuthContext {
    /// The artifact of a session, bound to the device `instance` it registered, if any.
    ///
    /// # Errors
    /// [`EncodeError`].
    pub fn of(
        realm: &str,
        session: &[u8; 16],
        assurance: &AssuranceVector,
        step_up_time: Option<u64>,
        instance: Option<[u8; 16]>,
        content: Option<Content>,
    ) -> Result<Self, EncodeError> {
        Ok(Self {
            realm: String::from(realm),
            session_ref: session_ref(session),
            aal: assurance.aal,
            assurance_flags: flags(assurance),
            auth_time: assurance.auth_time_ms,
            step_up_time,
            ais_digest: ais_digest(assurance)?,
            instance,
            content,
        })
    }

    /// The artifact as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = vec![
            (Value::text("v"), Value::Unsigned(VERSION)),
            (Value::text("realm"), Value::text(&self.realm)),
            (Value::text("session_ref"), self.session_ref.to_value()),
            (Value::text("aal"), Value::text(aal_name(self.aal))),
            (
                Value::text("assurance_flags"),
                Value::Array(
                    self.assurance_flags
                        .iter()
                        .map(|f| Value::text(f))
                        .collect(),
                ),
            ),
            (Value::text("auth_time"), Value::Unsigned(self.auth_time)),
            (Value::text("ais_digest"), self.ais_digest.to_value()),
        ];
        if let Some(t) = self.step_up_time {
            m.push((Value::text("step_up_time"), Value::Unsigned(t)));
        }
        if let Some(i) = self.instance {
            m.push((Value::text("instance"), Value::Bytes(i.to_vec())));
        }
        if let Some(c) = &self.content {
            m.push((Value::text("content_type"), Value::text(&c.content_type)));
            m.push((Value::text("content_digest"), Digest(c.digest).to_value()));
        }
        Value::Map(m)
    }

    /// Deterministic CBOR (RFC 8949 §4.2.1).
    ///
    /// # Errors
    /// [`EncodeError`].
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        dcbor::encode(&self.to_value(), Limits::CEILING)
    }

    /// `SHA-256("suiss/auth-context/v1" ‖ 0x00 ‖ dCBOR(artifact))`.
    ///
    /// # Errors
    /// [`EncodeError`].
    pub fn digest(&self) -> Result<Digest, EncodeError> {
        Ok(context_digest(DIGEST_LABEL, &self.encode()?))
    }
}

#[cfg(test)]
mod tests;
