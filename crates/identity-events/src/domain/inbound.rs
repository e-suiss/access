//! The SSF receiver's rules free of I/O (TN-42, §9.16.2 k.4, OP-151 m.3 (l)): what an inbound
//! transmitter declares, how an inbound SET is checked (RFC 8417, RFC 8935 §2.3 errors), what a
//! verified event may do, and when a transmitter counts as delayed (§8.13).
//!
//! An inbound event is a Claim, never authority: its effects are closed ([`Effect`]); none
//! revokes a Grant, none widens anything, and a lost or late event changes no decision
//! (PI-9, CI-2, L18, INV-24).

use access_crypto::oauth::{ClientAlg, verify_client_signature};
use access_identity_account::domain::signal::{RiskLevel, SignalKind};
use access_identity_oauth::domain::jwt::Jwk;
use access_kernel::json::{self, Json, b64url_decode};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::domain::Invalid;
use crate::domain::mapping::signal_of;

/// Media type of an inbound push (RFC 8935 §2).
pub const CONTENT_TYPE: &str = "application/secevent+jwt";

/// Largest inbound SET read (PD).
pub const MAX_SET: usize = 64 * 1024;

/// Largest skew between a SET's `iat` and now: five minutes (OP-151 m.3 (l)).
pub const MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// How often a transmitter is expected to be heard from when it declares nothing: a day (PD).
pub const DEFAULT_INTERVAL_S: u32 = 86_400;

/// Longest `jti` accepted.
pub const MAX_JTI: usize = 256;

/// Digest context of an upstream subject, H(iss, sub) (§10.1.2: the pair, never an email); the
/// same context the Claim pipeline binds identity bindings to.
pub const SUBJECT_CONTEXT: &str = "access/upstream-subject/v1";

/// Digest context of an inbound `jti`, the replay key.
pub const JTI_CONTEXT: &str = "access/ssf-inbound-jti/v1";

/// Prefix of the `risk_signal` values an inbound event raises.
pub const RISK_PREFIX: &str = "ssf.";

/// An inbound transmitter as `idp.upstream.register` declares its SSF fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransmitterConfig {
    /// The SET `iss`.
    pub issuer: String,
    /// Where its signing keys are published.
    pub jwks_uri: String,
    /// The `aud` its SETs must name.
    pub audience: String,
    /// The CAEP/RISC type URIs it may send.
    pub events: Vec<String>,
    /// RFC 8936 poll endpoint, when it only offers poll.
    pub poll_endpoint: Option<String>,
    /// How often it is expected to be heard from, seconds.
    pub expected_interval_s: u32,
}

fn https(s: &str) -> bool {
    access_identity_oauth::adapters::outbound::Target::parse(s).is_ok()
}

fn field<'a>(
    o: &'a serde_json::Map<String, serde_json::Value>,
    k: &'static str,
) -> Result<Option<&'a str>, Invalid> {
    match o.get(k) {
        None => Ok(None),
        Some(serde_json::Value::String(s)) if s.len() <= 2048 => Ok(Some(s)),
        Some(_) => Err(Invalid(k)),
    }
}

impl TransmitterConfig {
    /// Reads the SSF fields: `issuer`, `jwks_uri`, `aud`, `events`, optional `poll_endpoint`
    /// and `expected_interval_s` (60 s to 30 days).
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn parse(v: &serde_json::Value) -> Result<Self, Invalid> {
        let o = v.as_object().ok_or(Invalid("ssf"))?;
        let issuer = field(o, "issuer")?
            .filter(|s| https(s))
            .ok_or(Invalid("issuer"))?;
        let jwks_uri = field(o, "jwks_uri")?
            .filter(|s| https(s))
            .ok_or(Invalid("jwks_uri"))?;
        let audience = field(o, "aud")?
            .filter(|s| !s.is_empty() && s.len() <= 512)
            .ok_or(Invalid("aud"))?;
        let poll_endpoint = match field(o, "poll_endpoint")? {
            None => None,
            Some(u) if https(u) => Some(String::from(u)),
            Some(_) => return Err(Invalid("poll_endpoint")),
        };
        let list = o
            .get("events")
            .and_then(serde_json::Value::as_array)
            .ok_or(Invalid("events"))?;
        let mut events = Vec::with_capacity(list.len());
        for e in list {
            let u = e.as_str().ok_or(Invalid("events"))?;
            signal_of(u).ok_or(Invalid("unsupported-event"))?;
            events.push(String::from(u));
        }
        events.sort();
        events.dedup();
        if events.is_empty() {
            return Err(Invalid("events"));
        }
        let expected_interval_s = match o.get("expected_interval_s") {
            None => DEFAULT_INTERVAL_S,
            Some(n) => n
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| (60..=2_592_000).contains(n))
                .ok_or(Invalid("expected_interval_s"))?,
        };
        Ok(Self {
            issuer: String::from(issuer),
            jwks_uri: String::from(jwks_uri),
            audience: String::from(audience),
            events,
            poll_endpoint,
            expected_interval_s,
        })
    }
}

/// Why an inbound SET is refused: the RFC 8935 §2.3 error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    /// Not a SET this receiver reads.
    #[error("invalid_request")]
    Request,
    /// No key of the transmitter verifies it.
    #[error("invalid_key")]
    Key,
    /// `iss` is not the transmitter's.
    #[error("invalid_issuer")]
    Issuer,
    /// `aud` does not name this receiver.
    #[error("invalid_audience")]
    Audience,
    /// The event type was not declared for the transmitter.
    #[error("access_denied")]
    Denied,
}

impl Reject {
    /// The RFC 8935 `err` value.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Request => "invalid_request",
            Self::Key => "invalid_key",
            Self::Issuer => "invalid_issuer",
            Self::Audience => "invalid_audience",
            Self::Denied => "access_denied",
        }
    }

    /// The RFC 8935 error body.
    #[must_use]
    pub fn body(self) -> serde_json::Value {
        let description = match self {
            Self::Request => "the SET is malformed, stale or carries other than one event",
            Self::Key => "no key of the transmitter verifies the SET",
            Self::Issuer => "the issuer is not the registered transmitter",
            Self::Audience => "the audience is not this receiver",
            Self::Denied => "the event type is not registered for this transmitter",
        };
        serde_json::json!({"err": self.code(), "description": description})
    }
}

/// What the receiver expects of a transmitter's SETs.
#[derive(Clone, Copy, Debug)]
pub struct Expect<'a> {
    /// `iss`.
    pub issuer: &'a str,
    /// `aud`.
    pub audience: &'a str,
    /// The type URIs it may send.
    pub events: &'a [String],
    /// Now, Unix ms.
    pub now_ms: u64,
}

/// A verified inbound SET.
#[derive(Clone, Debug, PartialEq)]
pub struct InboundSet {
    /// Digest of its `jti`, the replay key.
    pub jti: [u8; 32],
    /// Its one event type.
    pub kind: SignalKind,
    /// The type URI.
    pub event_type: String,
    /// The upstream subject `(iss, sub)`, when `sub_id` is `iss_sub` of this transmitter.
    pub subject: Option<(String, String)>,
    /// The event's members.
    pub body: Json,
}

fn member<'a>(v: &'a Json, k: &str) -> Option<&'a Json> {
    v.get(k)
}

fn seconds(v: Option<&Json>) -> Result<Option<u64>, Reject> {
    v.map(|t| {
        t.as_int()
            .and_then(|s| u64::try_from(s).ok())
            .and_then(|s| s.checked_mul(1000))
            .ok_or(Reject::Request)
    })
    .transpose()
}

/// Verifies an inbound SET (RFC 8417, SSF 1.0): compact JWS with `typ` `secevent+jwt`, `alg`
/// ES256 or RS256 from the allowlist under one key of `keys`, `iss` and `aud` as expected,
/// `iat` within [`MAX_SKEW_MS`] of now, an unexpired `exp` if any, a `jti`, and exactly one
/// event of a declared type.
///
/// # Errors
/// [`Reject`].
pub fn verify(token: &[u8], keys: &[Jwk], expect: &Expect<'_>) -> Result<InboundSet, Reject> {
    if token.len() > MAX_SET {
        return Err(Reject::Request);
    }
    let text = core::str::from_utf8(token).map_err(|_| Reject::Request)?;
    let mut parts = text.trim().split('.');
    let (Some(head), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Reject::Request);
    };
    let header = b64url_decode(head)
        .ok()
        .and_then(|b| json::parse(&b, 4096).ok())
        .ok_or(Reject::Request)?;
    let typ = member(&header, "typ").and_then(Json::as_str);
    if !typ.is_some_and(|t| t.eq_ignore_ascii_case("secevent+jwt")) {
        return Err(Reject::Request);
    }
    let alg = member(&header, "alg")
        .and_then(Json::as_str)
        .and_then(ClientAlg::from_name)
        .filter(|a| matches!(a, ClientAlg::Es256 | ClientAlg::Rs256))
        .ok_or(Reject::Key)?;
    let kid = member(&header, "kid").and_then(Json::as_str);
    let signature = b64url_decode(sig).map_err(|_| Reject::Request)?;
    let input = &text.trim()[..head.len().saturating_add(1).saturating_add(payload.len())];
    let verified = keys
        .iter()
        .filter(|k| kid.is_none_or(|id| k.kid.as_deref() == Some(id)))
        .any(|k| verify_client_signature(alg, &k.key, input.as_bytes(), &signature).is_ok());
    if !verified {
        return Err(Reject::Key);
    }
    let claims = b64url_decode(payload)
        .ok()
        .and_then(|b| json::parse(&b, MAX_SET).ok())
        .ok_or(Reject::Request)?;
    if member(&claims, "iss").and_then(Json::as_str) != Some(expect.issuer) {
        return Err(Reject::Issuer);
    }
    let aud_ok = match member(&claims, "aud") {
        Some(Json::Str(a)) => a == expect.audience,
        Some(Json::Array(items)) => items.iter().any(|a| a.as_str() == Some(expect.audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(Reject::Audience);
    }
    let iat = seconds(member(&claims, "iat"))?.ok_or(Reject::Request)?;
    if iat.abs_diff(expect.now_ms) > MAX_SKEW_MS {
        return Err(Reject::Request);
    }
    if seconds(member(&claims, "exp"))?.is_some_and(|x| x < expect.now_ms) {
        return Err(Reject::Request);
    }
    let jti = member(&claims, "jti")
        .and_then(Json::as_str)
        .filter(|j| !j.is_empty() && j.len() <= MAX_JTI)
        .ok_or(Reject::Request)?;
    let Some(Json::Object(events)) = member(&claims, "events") else {
        return Err(Reject::Request);
    };
    let [(uri, body)] = events.as_slice() else {
        return Err(Reject::Request);
    };
    let signal = signal_of(uri).ok_or(Reject::Denied)?;
    if !expect.events.contains(uri) {
        return Err(Reject::Denied);
    }
    let subject = member(&claims, "sub_id")
        .filter(|s| member(s, "format").and_then(Json::as_str) == Some("iss_sub"))
        .and_then(|s| {
            let iss = member(s, "iss").and_then(Json::as_str)?;
            let sub = member(s, "sub").and_then(Json::as_str)?;
            (iss == expect.issuer).then(|| (String::from(iss), String::from(sub)))
        });
    Ok(InboundSet {
        jti: access_crypto::oauth::opaque_digest(JTI_CONTEXT, jti.as_bytes()),
        kind: signal,
        event_type: uri.clone(),
        subject,
        body: body.clone(),
    })
}

/// H(iss, sub): the upstream subject an inbound event names.
#[must_use]
pub fn subject_digest(iss: &str, sub: &str) -> [u8; 32] {
    let pair = Value::Array(vec![Value::text(iss), Value::text(sub)]);
    let bytes = dcbor::encode(&pair, Limits::CEILING).unwrap_or_default();
    context_digest(SUBJECT_CONTEXT, &bytes).0
}

/// What a verified inbound event may do (TN-42, §9.16.2 k.4). The set is closed: nothing
/// revokes a Grant, nothing widens, and an unknown or widening event does nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// `session-revoked`: the subject's sessions end, its actor binding with them, and its
    /// `session_epoch` steps.
    EndSessions,
    /// A narrowing `risk_signal` Claim with this value.
    Risk(&'static str),
    /// An `account_status` Claim of `suspended` (RISC `account-disabled`); the account's own
    /// status does not change.
    Suspended,
    /// Recorded, nothing else.
    None,
}

/// The effect of an inbound event of `kind` with members `body`.
#[must_use]
pub fn effect(kind: SignalKind, body: &Json) -> Effect {
    let text = |k: &str| member(body, k).and_then(Json::as_str);
    match kind {
        SignalKind::SessionRevoked => Effect::EndSessions,
        SignalKind::CredentialChange => Effect::Risk("ssf.credential-change"),
        // CI-2
        SignalKind::RiskLevelChange => match text("current_level").and_then(RiskLevel::from_name) {
            Some(RiskLevel::Medium | RiskLevel::High) => Effect::Risk("ssf.risk-level-change"),
            _ => Effect::None,
        },
        SignalKind::DeviceComplianceChange => match text("current_status") {
            Some("not-compliant") => Effect::Risk("ssf.device-compliance-change"),
            _ => Effect::None,
        },
        SignalKind::AccountDisabled => Effect::Suspended,
        SignalKind::CredentialCompromise => Effect::Risk("ssf.credential-compromise"),
        SignalKind::AssuranceLevelChange
        | SignalKind::TokenClaimsChange
        | SignalKind::SessionEstablished
        | SignalKind::SessionPresented
        | SignalKind::AccountPurged
        | SignalKind::IdentifierRecycled => Effect::None,
    }
}

/// Since when a transmitter is delayed (§8.13): its last word, or its declaration when it never
/// spoke, plus the interval it is expected within, once that is past.
#[must_use]
pub fn delayed_since(
    last_seen_ms: Option<u64>,
    created_ms: u64,
    interval_s: u32,
    now_ms: u64,
) -> Option<u64> {
    let due = last_seen_ms
        .unwrap_or(created_ms)
        .saturating_add(u64::from(interval_s).saturating_mul(1000));
    (now_ms > due).then_some(due)
}

/// The administrator notice of a delayed transmitter (§8.13), `since` as UTC `HH:MM`.
#[must_use]
pub fn delay_notice(provider: &str, since_ms: u64) -> String {
    let minutes = (since_ms / 60_000) % (24 * 60);
    format!(
        "Signals from {provider} delayed since {:02}:{:02} UTC — decisions use declared validity windows",
        minutes / 60,
        minutes % 60
    )
}

#[cfg(test)]
mod tests;
