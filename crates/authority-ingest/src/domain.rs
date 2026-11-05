//! The ingest rules with no I/O: carrier mapping, minimisation, issuer order and quota (§9.13
//! rules 4 to 7, G36, G44).
//!
//! Carrier mapping table (§9.13, §10.1.2, OP-150 m.3 (i)): what each carrier this pipeline
//! accepts becomes. Every other field of the carrier stays out of the Claim (E26).
//!
//! | Carrier | Verified by | Issuer | Subject | Class | Value | `issued_at` / validity |
//! |---|---|---|---|---|---|---|
//! | `cose` | `COSE_Sign1` under the issuer Instance's key | statement | statement | statement | statement | statement |
//! | `unsigned` | the caller's channel (PEP or SCIM thumbprint) | statement | statement | statement | statement | statement |
//! | `webauthn` | as `cose`; the realm issuer mapped the ceremony | realm issuer | statement | `authentication` (method `webauthn`) or `authenticator_binding` (`passkey`) | body digest | statement |
//! | `oidc` | compact JWS under the Acceptance's pinned key set, `typ` `JWT` | the pinned issuer's Party | carrier context, held by an `identity_binding_person` Claim on `H(iss, sub)` | `authentication` (method `oidc`, `upstream` = `iss`, `acr`, `amr`) | body digest | `iat` / `[iat, exp]` |
//! | `set` | compact JWS under the pinned key set, `typ` `secevent+jwt` | as `oidc` | as `oidc`, from `sub_id` (`iss_sub`) or `sub` | `account_status` | the event's status | `iat` / `[iat, exp or iat + 90 days]` |
//!
//! SET events mapped (RFC 8935 RISC): `account-disabled` → `suspended`, `account-enabled` →
//! `active`, `account-purged` → `tombstone`; any other event is refused. The SAML, SCIM, LDAP,
//! SPNEGO, mTLS/PIV and device attestation rows of §10.1.2 move to their protocol stages
//! (OP-150 m.3 (i)); until then their carriers are not accepted.

use std::collections::BTreeMap;

use access_internal_api::claims::Carrier;
use access_kernel::claim::body::{
    self, AuthMethod, Authentication, Body, Class, IdentityBinding, Upstream,
};
use access_kernel::claim::{Pinned, Statement};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::{self, Json};
use access_kernel::model::{EqValue, Id, Window};
use access_kernel::verify::PureBackend;
use access_kernel::verify::jws::{self, ClaimRules, Origin};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

/// Largest Claim or carrier accepted, checked first (§14.6).
pub const MAX_CLAIM: usize = 96 * 1024;
/// Largest body beside a Claim.
pub const MAX_BODY: usize = 64 * 1024;

/// Digest context of a submission in the day's table (OP-150 m.6 (f)).
pub const SUBMISSION_CONTEXT: &str = "access/claim-ingest/v1";
/// Digest context of an upstream subject, `H(iss, sub)` (§10.1.2: the pair, never an email).
pub const SUBJECT_CONTEXT: &str = "access/upstream-subject/v1";
/// Digest context of a raw carrier artefact.
pub const EVIDENCE_CONTEXT: &str = "access/carrier-evidence/v1";

/// `typ` of an upstream ID token in the pinned profile.
pub const ID_TOKEN_TYP: &str = "JWT";
/// `typ` of a Security Event Token (RFC 8417).
pub const SET_TYP: &str = "secevent+jwt";
/// How long a SET without `exp` holds (PD).
pub const SET_VALIDITY_MS: u64 = 90 * 24 * 3_600 * 1_000;

const RISC: &str = "https://schemas.openid.net/secevent/risc/event-type/";

/// The RISC events a SET may carry and the `account_status` each declares.
pub const SET_EVENTS: [(&str, &str); 3] = [
    ("account-disabled", "suspended"),
    ("account-enabled", "active"),
    ("account-purged", "tombstone"),
];

/// A refused submission: not recorded, with its stable reason code (§9.13 rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Refusal(pub &'static str);

impl Refusal {
    /// The Claim or its carrier is too large.
    pub const SIZE: Self = Self("claim-size");
    /// The carrier does not verify or does not map.
    pub const CARRIER: Self = Self("claim-carrier");
    /// The carrier names an event outside the mapping table.
    pub const EVENT: Self = Self("claim-carrier-event");
    /// No pinned issuer verifies the carrier.
    pub const ISSUER: Self = Self("claim-issuer");
    /// The subject is not held by an identity binding.
    pub const SUBJECT: Self = Self("claim-subject");
    /// The carrier context does not parse.
    pub const CONTEXT: Self = Self("claim-carrier-context");
}

/// Digest of a submission in the day's table: carrier and bytes, nothing else.
#[must_use]
pub fn submission_hash(carrier: Carrier, claim: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(claim.len().saturating_add(8));
    input.extend_from_slice(carrier.name().as_bytes());
    input.push(0);
    input.extend_from_slice(claim);
    context_digest(SUBMISSION_CONTEXT, &input).0
}

/// Days since the Unix epoch of trusted time `now_ms`.
#[must_use]
pub fn day_of(now_ms: u64) -> u32 {
    u32::try_from(now_ms / 86_400_000).unwrap_or(u32::MAX)
}

/// Checks the sizes before anything is parsed.
///
/// # Errors
/// [`Refusal::SIZE`].
pub fn check_size(claim: &[u8], body: Option<&[u8]>) -> Result<(), Refusal> {
    if claim.is_empty() || claim.len() > MAX_CLAIM || body.is_some_and(|b| b.len() > MAX_BODY) {
        return Err(Refusal::SIZE);
    }
    Ok(())
}

/// Whether a Claim only narrows (G44, §13.7.4): it is never quarantined for quota.
#[must_use]
pub fn narrowing(s: &Statement) -> bool {
    match Class::parse(&s.class) {
        Some(Class::AccountStatus) => !matches!(
            &s.value,
            Some(EqValue::Text(t)) if t == "active" || t == "locked"
        ),
        Some(Class::PartyCompromise | Class::PartyTerminated | Class::PartyIdentityBreak) => true,
        _ => false,
    }
}

/// A `webauthn` carrier is a realm issuer's `authentication` of method `webauthn` with its
/// flags, or its `authenticator_binding` of a passkey; the body must travel with it.
///
/// # Errors
/// [`Refusal::CARRIER`].
pub fn check_webauthn(body: Option<&Body>) -> Result<(), Refusal> {
    match body {
        Some(Body::Authentication(a))
            if a.method == AuthMethod::Webauthn && a.webauthn.is_some() =>
        {
            Ok(())
        }
        Some(Body::AuthenticatorBinding(b)) if b.kind == body::AuthenticatorKind::Passkey => Ok(()),
        _ => Err(Refusal::CARRIER),
    }
}

/// `H(iss, sub)`: the upstream subject an `identity_binding_person` Claim binds a Party to.
#[must_use]
pub fn subject_digest(iss: &str, sub: &str) -> Digest {
    let pair = Value::Array(vec![Value::text(iss), Value::text(sub)]);
    let bytes = dcbor::encode(&pair, Limits::CEILING).unwrap_or_default();
    Digest(context_digest(SUBJECT_CONTEXT, &bytes).0)
}

/// The `value` of the `identity_binding_person` Claim whose evidence is `subject`.
#[must_use]
pub fn binding_value(subject: &Digest) -> Option<EqValue> {
    let b = Body::IdentityBinding(IdentityBinding { evidence: *subject }).to_value();
    body::body_digest(Class::IdentityBinding(body::BindingKind::Person), &b)
        .ok()
        .map(|d| EqValue::Bytes(d.to_vec()))
}

/// The carrier context of an `oidc` or `set` submission: `{subject: party-ref}`, the Party the
/// submitter resolved the upstream subject to; the pipeline checks it against an identity
/// binding.
///
/// # Errors
/// [`Refusal::CONTEXT`].
pub fn carrier_context(bytes: Option<&[u8]>) -> Result<Id, Refusal> {
    let v = bytes
        .and_then(|b| dcbor::decode(b, Limits::CEILING).ok())
        .ok_or(Refusal::CONTEXT)?;
    let Value::Map(entries) = &v else {
        return Err(Refusal::CONTEXT);
    };
    match entries.as_slice() {
        [(Value::Text(k), id)] if k == "subject" => {
            Id::from_value(id).map_err(|_| Refusal::CONTEXT)
        }
        _ => Err(Refusal::CONTEXT),
    }
}

/// The carrier context bytes for `subject`.
#[must_use]
pub fn context_bytes(subject: &Id) -> Vec<u8> {
    dcbor::encode(
        &Value::Map(vec![(Value::text("subject"), subject.to_value())]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// The `iss` a compact JWS names, read without verifying it, to find the pinned issuers to
/// verify it under.
///
/// # Errors
/// [`Refusal::CARRIER`].
pub fn peek_iss(token: &[u8]) -> Result<String, Refusal> {
    let text = core::str::from_utf8(token).map_err(|_| Refusal::CARRIER)?;
    let payload = text.split('.').nth(1).ok_or(Refusal::CARRIER)?;
    let bytes = json::b64url_decode(payload).map_err(|_| Refusal::CARRIER)?;
    let claims = json::parse(&bytes, jws::MAX_PAYLOAD).map_err(|_| Refusal::CARRIER)?;
    claims
        .get("iss")
        .and_then(Json::as_str)
        .map(String::from)
        .ok_or(Refusal::CARRIER)
}

/// A carrier mapped to a Claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapped {
    /// The statement.
    pub statement: Statement,
    /// Its body, dCBOR, when the class has one.
    pub body: Option<Vec<u8>>,
    /// `H(iss, sub)`, which an identity binding must hold for the subject.
    pub subject: Digest,
    /// Digest of the raw carrier.
    pub evidence: Digest,
}

/// Who the mapped Claim is from and about, and where and when it is read.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    /// The domain.
    pub domain: Digest,
    /// The pinned issuer's Party.
    pub issuer: Id,
    /// The Party the submitter names.
    pub subject: Id,
    /// The pinned key set.
    pub pinned: &'a Pinned,
    /// Trusted time.
    pub now: u64,
    /// Skew tolerance.
    pub skew_ms: u64,
}

fn verified(token: &[u8], typ: &str, f: &Frame<'_>) -> Result<Json, Refusal> {
    let text = core::str::from_utf8(token).map_err(|_| Refusal::CARRIER)?;
    let keys = f.pinned.key_set();
    let v = jws::verify_compact(&PureBackend, text, &keys, typ, Origin::External)
        .map_err(|_| Refusal::ISSUER)?;
    let claims = json::parse(&v.payload, jws::MAX_PAYLOAD).map_err(|_| Refusal::CARRIER)?;
    Ok(claims)
}

fn millis(claims: &Json, name: &str) -> Result<Option<u64>, Refusal> {
    claims
        .get(name)
        .map(|v| {
            v.as_int()
                .ok_or(Refusal::CARRIER)
                .and_then(|s| jws::millis(s).map_err(|_| Refusal::CARRIER))
                .and_then(|ms| u64::try_from(ms).map_err(|_| Refusal::CARRIER))
        })
        .transpose()
}

fn evidence(token: &[u8]) -> Digest {
    Digest(context_digest(EVIDENCE_CONTEXT, token).0)
}

fn statement(f: &Frame<'_>, class: &str, value: EqValue, issued_at: u64, until: u64) -> Statement {
    Statement {
        domain: f.domain,
        issuer: f.issuer,
        subject: f.subject,
        class: String::from(class),
        value: Some(value),
        issued_at,
        validity: Window {
            from: issued_at,
            until,
        },
        // §10.1.2 rule 2: without a mapping in the Acceptance, the lowest class
        assurance: BTreeMap::new(),
        bound_intent: None,
        bound_instance: None,
        bound_resource: None,
        supersedes: None,
    }
}

/// Maps an upstream ID token to an `authentication` Claim (§10.1.2 OIDC row).
///
/// # Errors
/// [`Refusal`].
pub fn map_oidc(token: &[u8], f: &Frame<'_>) -> Result<Mapped, Refusal> {
    let claims = verified(token, ID_TOKEN_TYP, f)?;
    jws::check_claims_json(
        &claims,
        &ClaimRules {
            issuer: &f.pinned.iss,
            audience: &f.pinned.aud,
            now: f.now,
            skew_ms: f.skew_ms,
        },
    )
    .map_err(|_| Refusal::CARRIER)?;
    let sub = claims
        .get("sub")
        .and_then(Json::as_str)
        .ok_or(Refusal::CARRIER)?;
    let iat = millis(&claims, "iat")?.ok_or(Refusal::CARRIER)?;
    let exp = millis(&claims, "exp")?.ok_or(Refusal::CARRIER)?;
    let auth_time = millis(&claims, "auth_time")?.unwrap_or(iat);
    let amr = match claims.get("amr") {
        None => Vec::new(),
        Some(Json::Array(items)) => items
            .iter()
            .map(|a| a.as_str().map(String::from).ok_or(Refusal::CARRIER))
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(Refusal::CARRIER),
    };
    let acr = claims.get("acr").and_then(Json::as_str).map(String::from);
    let ev = evidence(token);
    let b = Body::Authentication(Authentication {
        method: AuthMethod::Oidc,
        auth_time,
        statement: None,
        evidence: Some(ev),
        webauthn: None,
        upstream: Some(Upstream {
            iss: f.pinned.iss.clone(),
            acr,
            amr,
        }),
    })
    .to_value();
    let digest = body::body_digest(Class::Authentication, &b).map_err(|_| Refusal::CARRIER)?;
    Ok(Mapped {
        statement: statement(
            f,
            "authentication",
            EqValue::Bytes(digest.to_vec()),
            iat,
            exp,
        ),
        body: Some(dcbor::encode(&b, Limits::CEILING).map_err(|_| Refusal::CARRIER)?),
        subject: subject_digest(&f.pinned.iss, sub),
        evidence: ev,
    })
}

fn set_subject(claims: &Json) -> Option<String> {
    if let Some(id) = claims.get("sub_id") {
        return (id.get("format").and_then(Json::as_str) == Some("iss_sub"))
            .then(|| id.get("sub").and_then(Json::as_str).map(String::from))
            .flatten();
    }
    claims.get("sub").and_then(Json::as_str).map(String::from)
}

/// Maps a Security Event Token to an `account_status` Claim (§10.1.2 SET row).
///
/// # Errors
/// [`Refusal`].
pub fn map_set(token: &[u8], f: &Frame<'_>) -> Result<Mapped, Refusal> {
    let claims = verified(token, SET_TYP, f)?;
    if claims.get("iss").and_then(Json::as_str) != Some(f.pinned.iss.as_str()) {
        return Err(Refusal::CARRIER);
    }
    let aud_ok = match claims.get("aud") {
        Some(Json::Str(a)) => *a == f.pinned.aud,
        Some(Json::Array(items)) => items.iter().any(|a| a.as_str() == Some(&f.pinned.aud)),
        _ => false,
    };
    let iat = millis(&claims, "iat")?.ok_or(Refusal::CARRIER)?;
    if !aud_ok || iat > f.now.saturating_add(f.skew_ms) {
        return Err(Refusal::CARRIER);
    }
    let until = millis(&claims, "exp")?.unwrap_or(iat.saturating_add(SET_VALIDITY_MS));
    if f.now > until.saturating_add(f.skew_ms) {
        return Err(Refusal::CARRIER);
    }
    let Some(Json::Object(events)) = claims.get("events") else {
        return Err(Refusal::CARRIER);
    };
    let [(uri, _)] = events.as_slice() else {
        return Err(Refusal::EVENT);
    };
    let status = uri
        .strip_prefix(RISC)
        .and_then(|e| SET_EVENTS.iter().find(|(name, _)| *name == e))
        .map(|(_, s)| *s)
        .ok_or(Refusal::EVENT)?;
    let sub = set_subject(&claims).ok_or(Refusal::CARRIER)?;
    Ok(Mapped {
        statement: statement(
            f,
            "account_status",
            EqValue::Text(String::from(status)),
            iat,
            until,
        ),
        body: None,
        subject: subject_digest(&f.pinned.iss, &sub),
        evidence: evidence(token),
    })
}

/// How a domain takes a realm's identity Claims (TN-4, §12.1.1, MD-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    /// The realm's governing domain.
    Governing,
    /// A domain that consumes the realm's Claims through this Acceptance.
    Consuming(Id),
}

/// The domains a realm's identity Claims go to (TN-4): its governing domain and each consuming
/// domain whose Acceptance is still live there (`live`). A Claim names one domain, so the
/// issuer signs one per target; a domain without a live Acceptance gets none.
pub fn targets(bindings: &[(Digest, Bound)], live: impl Fn(&Digest, &Id) -> bool) -> Vec<Digest> {
    let mut out: Vec<Digest> = bindings
        .iter()
        .filter(|(d, b)| match b {
            Bound::Governing => true,
            Bound::Consuming(a) => live(d, a),
        })
        .map(|(d, _)| *d)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The start of the quota window holding `now`.
#[must_use]
pub fn window_start(now: u64, window_ms: u64) -> u64 {
    now.saturating_sub(now.checked_rem(window_ms).unwrap_or(0))
}

#[cfg(test)]
mod tests;
