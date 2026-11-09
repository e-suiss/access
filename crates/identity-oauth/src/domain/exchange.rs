//! Agent token exchange, identity assertions and the token type registry (RFC 8693, RFC 7523,
//! `draft-ietf-oauth-identity-assertion-authz-grant`, `draft-ietf-oauth-transaction-tokens`;
//! §9.9.4, §11.10, §11.11, §11.12.3, §11.21, OP-154 m.3 (m), (n), (o), (q)). Free of I/O.
//!
//! A presented token is Claim input only: its `act`, `scope` or `authorization_details` never
//! become authority, and nothing of it is copied into what is issued (AGI-1, P53). Authority
//! comes only from the holder's own `projection.issue` decision.

use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::verify::cose::KeySet;
use access_kernel::verify::jws::{self, MAX_PAYLOAD, Origin, verify_compact};
use serde_json::json;
use suiss_crypto::digest::context_digest;

/// RFC 8693 §3 `access_token`.
pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// RFC 8693 §3 `refresh_token`.
pub const REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
/// RFC 8693 §3 `id_token`.
pub const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
/// RFC 8693 §3 `jwt`.
pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
/// RFC 8693 §3 `saml1`.
pub const SAML1: &str = "urn:ietf:params:oauth:token-type:saml1";
/// RFC 8693 §3 `saml2`.
pub const SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
/// The ID-JAG token type (MD-18).
pub const ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
/// The Transaction Token type.
pub const TXN_TOKEN: &str = "urn:ietf:params:oauth:token-type:txn_token";
/// The ID-JAG grant profile (§11.11.1).
pub const ID_JAG_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";

/// `typ` of an ID-JAG (§11.21.3).
pub const ID_JAG_TYP: &str = "oauth-id-jag+jwt";
/// `typ` of a Transaction Token (§11.21.3).
pub const TXN_TYP: &str = "txntoken+jwt";
/// `typ` of a WIMSE Workload Identity Token (§11.21.3; interface only).
pub const WIT_TYP: &str = "wit+jwt";
/// `typ` of a WIMSE Workload Proof Token (§11.21.3; interface only).
pub const WPT_TYP: &str = "application/wpt+jwt";
/// `typ` of an OAuth client attestation (§11.21.3; interface only).
pub const CLIENT_ATTESTATION_TYP: &str = "oauth-client-attestation+jwt";
/// `typ` of an OAuth client attestation proof of possession (§11.21.3; interface only).
pub const CLIENT_ATTESTATION_POP_TYP: &str = "oauth-client-attestation-pop+jwt";
/// `typ` a cloud workload identity token or another accepted issuer's JWT carries.
pub const JWT_TYP: &str = "JWT";

/// What the realm does with a JOSE `typ` (§11.21.3, Ek B 4653).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypRole {
    /// An access token projection (`at+jwt`).
    Projection,
    /// An identity assertion the realm issues and accepts as Claim input (ID-JAG, ID token,
    /// another accepted issuer's JWT).
    Assertion,
    /// Audit context only: never a subject token, never a basis (Txn-Token, OP-154 m.3 (o)).
    AuditOnly,
    /// Declared and refused everywhere until its draft is an RFC (WIT, WPT, client
    /// attestation; OP-154 m.3 (cc)).
    Interface,
}

/// The role of `typ`; `None` for a `typ` the realm does not know.
#[must_use]
pub fn typ_role(typ: &str) -> Option<TypRole> {
    match typ {
        crate::domain::tokens::ACCESS_TYP => Some(TypRole::Projection),
        ID_JAG_TYP | JWT_TYP => Some(TypRole::Assertion),
        TXN_TYP => Some(TypRole::AuditOnly),
        WIT_TYP | WPT_TYP | CLIENT_ATTESTATION_TYP | CLIENT_ATTESTATION_POP_TYP => {
            Some(TypRole::Interface)
        }
        _ => None,
    }
}

/// The kind of a `subject_token_type` the agent exchange reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectKind {
    /// An access token: an Access projection of this realm's domain or an accepted issuer's
    /// JWT.
    Access,
    /// An ID token of this realm or of an accepted issuer.
    IdToken,
    /// A SAML assertion: not read before Stage 10 (OP-154 m.3 (m)).
    Saml,
}

/// The kind of `subject_token_type`; `None` for any other.
#[must_use]
pub fn subject_kind(t: &str) -> Option<SubjectKind> {
    match t {
        ACCESS_TOKEN | JWT => Some(SubjectKind::Access),
        ID_TOKEN => Some(SubjectKind::IdToken),
        SAML1 | SAML2 => Some(SubjectKind::Saml),
        _ => None,
    }
}

/// What an agent exchange asks to be issued (RFC 8693 §2.1, §11.21.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requested {
    /// An authority token projection (`access_token`, or `jwt`: an `at+jwt` is a JWT).
    Projection {
        /// The `issued_token_type` answered.
        issued: &'static str,
    },
    /// An ID-JAG.
    IdJag,
    /// A Transaction Token.
    Txn,
    /// An ID token for the subject token's own Party.
    IdToken,
    /// A refresh token for an agent bounds projection.
    Refresh,
}

/// The kind of `requested_token_type`, an access token when absent; `None` for any other.
#[must_use]
pub fn requested(t: Option<&str>) -> Option<Requested> {
    Some(match t {
        None | Some(ACCESS_TOKEN) => Requested::Projection {
            issued: ACCESS_TOKEN,
        },
        Some(JWT) => Requested::Projection { issued: JWT },
        Some(ID_JAG) => Requested::IdJag,
        Some(TXN_TOKEN) => Requested::Txn,
        Some(ID_TOKEN) => Requested::IdToken,
        Some(REFRESH_TOKEN) => Requested::Refresh,
        Some(_) => return None,
    })
}

/// The longest `act` nesting a presented token may carry (AG-25: at least four levels).
pub const MAX_ACT_DEPTH: usize = access_crypto::projection::MAX_ACT_DEPTH;

/// Why a presented token's `act` is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ActError {
    /// A level is not an object with a text `sub`.
    #[error("act shape")]
    Shape,
    /// Deeper than [`MAX_ACT_DEPTH`].
    #[error("act depth")]
    Depth,
}

/// The number of `act` levels in `claims` (§9.9.4, AG-25): 0 without `act`. The chain is read
/// to be bounded, never to be believed: nothing in it is authority or lineage (L22, §9.9.4
/// rule 3).
///
/// # Errors
/// [`ActError`].
pub fn act_depth(claims: &serde_json::Value) -> Result<usize, ActError> {
    let mut depth = 0_usize;
    let mut at = claims.get("act");
    while let Some(level) = at {
        if depth >= MAX_ACT_DEPTH {
            return Err(ActError::Depth);
        }
        if !level.is_object() || !level.get("sub").is_some_and(serde_json::Value::is_string) {
            return Err(ActError::Shape);
        }
        depth = depth.saturating_add(1);
        at = level.get("act");
    }
    Ok(depth)
}

/// Longest life of an inbound assertion (OP-154 m.3 (q)).
pub const MAX_ASSERTION_MS: u64 = 300_000;

/// Life of an ID-JAG the realm issues (OP-154 m.3 (n)).
pub const ID_JAG_TTL_MS: u64 = 300_000;

/// Life of a Transaction Token (OP-154 m.3 (o)).
pub const TXN_TTL_MS: u64 = 60_000;

/// Clock skew allowed on assertion times.
pub const SKEW_MS: u64 = 60_000;

/// Longest `jti`.
pub const MAX_JTI: usize = 256;

/// Why an inbound assertion is refused; every case is `invalid_grant`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AssertionError {
    /// Not a JWS of the accepted issuer with the expected `typ` (AG-29 steps 1, 2).
    #[error("signature")]
    Signature,
    /// `iss` or `aud` is not this realm's (AG-29 step 3).
    #[error("audience")]
    Audience,
    /// The assertion was issued to another client (AG-29 step 4).
    #[error("client")]
    Client,
    /// Expired, not yet valid, longer than [`MAX_ASSERTION_MS`] or without `iat` (step 5).
    #[error("time")]
    Time,
    /// No `sub`, no usable `jti`, or a malformed member.
    #[error("claims")]
    Claims,
}

/// A verified inbound assertion, as Claim input (§9.13.8 k.2): `jti` its identity, `iss` its
/// issuer, `sub` its subject. Its `email`, `scope` and `act` are never read (E26, L24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    /// `iss`.
    pub iss: String,
    /// `sub`.
    pub sub: String,
    /// `jti`.
    pub jti: String,
    /// `client_id`, when carried.
    pub client_id: Option<String>,
    /// `resource`, when carried.
    pub resource: Option<String>,
    /// `exp`, Unix milliseconds.
    pub exp_ms: u64,
}

/// What an assertion must be.
#[derive(Clone, Copy, Debug)]
pub struct AssertionRules<'a> {
    /// The issuer the accepted key set is pinned for.
    pub iss: &'a str,
    /// The expected `typ`.
    pub typ: &'a str,
    /// The realm's issuer: the only audience.
    pub audience: &'a str,
    /// The authenticated client, for the continuity check.
    pub client_id: Option<&'a str>,
    /// Trusted time.
    pub now_ms: u64,
}

fn ms(c: &Json, name: &str) -> Result<Option<u64>, AssertionError> {
    c.get(name)
        .map(|v| {
            v.as_int()
                .and_then(|s| u64::try_from(s).ok())
                .and_then(|s| s.checked_mul(1000))
                .ok_or(AssertionError::Time)
        })
        .transpose()
}

fn text(c: &Json, name: &str) -> Option<String> {
    c.get(name).and_then(Json::as_str).map(String::from)
}

/// Verifies an inbound assertion under an accepted issuer's pinned `keys` (§11.11.3, AG-29,
/// OP-154 m.3 (q)): the signature and `typ`, `iss` and the single audience, client continuity
/// when the assertion names a client, and its times with a life of at most
/// [`MAX_ASSERTION_MS`].
///
/// # Errors
/// [`AssertionError`].
pub fn verify_assertion(
    token: &str,
    keys: &KeySet,
    rules: &AssertionRules<'_>,
) -> Result<Assertion, AssertionError> {
    let v = verify_compact(
        &access_crypto::AwsLcBackend,
        token,
        keys,
        rules.typ,
        Origin::External,
    )
    .map_err(|_| AssertionError::Signature)?;
    let c = json::parse(&v.payload, MAX_PAYLOAD).map_err(|_| AssertionError::Claims)?;
    if text(&c, "iss").as_deref() != Some(rules.iss) {
        return Err(AssertionError::Audience);
    }
    let aud_ok = match c.get("aud") {
        Some(Json::Str(a)) => a == rules.audience,
        Some(Json::Array(items)) => {
            items.len() == 1 && items.first().and_then(Json::as_str) == Some(rules.audience)
        }
        _ => false,
    };
    if !aud_ok {
        return Err(AssertionError::Audience);
    }
    jws::check_times(&c, rules.now_ms, SKEW_MS).map_err(|_| AssertionError::Time)?;
    let (Some(iat), Some(exp)) = (ms(&c, "iat")?, ms(&c, "exp")?) else {
        return Err(AssertionError::Time);
    };
    if exp <= iat || exp.saturating_sub(iat) > MAX_ASSERTION_MS {
        return Err(AssertionError::Time);
    }
    let client_id = text(&c, "client_id");
    // AG-29
    if let (Some(named), Some(authenticated)) = (&client_id, rules.client_id)
        && named != authenticated
    {
        return Err(AssertionError::Client);
    }
    let sub = text(&c, "sub")
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .ok_or(AssertionError::Claims)?;
    let jti = text(&c, "jti")
        .filter(|j| !j.is_empty() && j.len() <= MAX_JTI)
        .ok_or(AssertionError::Claims)?;
    Ok(Assertion {
        iss: String::from(rules.iss),
        sub,
        jti,
        client_id,
        resource: text(&c, "resource"),
        exp_ms: exp,
    })
}

/// The unverified `typ` and `iss` of a compact JWS, to pick the keys that verify it; nothing is
/// trusted before [`verify_assertion`].
#[must_use]
pub fn peek(token: &str) -> Option<(String, String)> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let header = json::parse(&b64url_decode(h).ok()?, 1024).ok()?;
    let payload = json::parse(&b64url_decode(p).ok()?, MAX_PAYLOAD).ok()?;
    Some((text(&header, "typ")?, text(&payload, "iss")?))
}

const JTI_CONTEXT: &str = "access/assertion-jti/v1";
const DAY_MS: u64 = 86_400_000;

/// Where an assertion's `jti` is kept as used (AG-29 step 5, OP-154 m.3 (n)): the day of its
/// `exp` and a digest of its issuer and `jti`, so the same assertion always lands on the same
/// slot and is remembered for its whole life; `None` past the representable days.
#[must_use]
pub fn jti_slot(a: &Assertion) -> Option<(u32, [u8; 32])> {
    let day = u32::try_from(a.exp_ms.checked_div(DAY_MS)?).ok()?;
    let mut input = Vec::with_capacity(a.iss.len().saturating_add(a.jti.len()).saturating_add(1));
    input.extend_from_slice(a.iss.as_bytes());
    input.push(0);
    input.extend_from_slice(a.jti.as_bytes());
    Some((day, context_digest(JTI_CONTEXT, &input).0))
}

/// What an ID-JAG names (§11.11.1, §11.11.2, OP-154 m.3 (n)).
#[derive(Clone, Copy, Debug)]
pub struct IdJagFacts<'a> {
    /// This realm's issuer.
    pub issuer: &'a str,
    /// The subject: the domain-pairwise reference the decided projection names (MD-10, P52).
    pub sub: &'a str,
    /// The Resource AS's issuer.
    pub audience: &'a str,
    /// The client at the Resource AS.
    pub client_id: &'a str,
    /// The RFC 8707 resource (required in the MCP profile).
    pub resource: &'a str,
    /// The scope hint, never authority (R3).
    pub scope: Option<&'a str>,
    /// `jti`.
    pub jti: &'a str,
    /// Issue time, Unix milliseconds.
    pub now_ms: u64,
    /// The decided projection's end, Unix milliseconds: the ID-JAG never outlives it.
    pub until_ms: u64,
}

/// The ID-JAG's claims: an identity assertion with no authority member (MD-18, L6).
#[must_use]
pub fn id_jag_claims(f: &IdJagFacts<'_>) -> Vec<u8> {
    let exp = f.now_ms.saturating_add(ID_JAG_TTL_MS).min(f.until_ms);
    let mut c = json!({
        "iss": f.issuer,
        "sub": f.sub,
        "aud": f.audience,
        "client_id": f.client_id,
        "jti": f.jti,
        "iat": f.now_ms / 1000,
        "exp": exp / 1000,
        "resource": f.resource,
    });
    if let (Some(s), serde_json::Value::Object(m)) = (f.scope, &mut c) {
        m.insert(String::from("scope"), s.into());
    }
    c.to_string().into_bytes()
}

/// What a Transaction Token names (§11.12.3, OP-154 m.3 (o)).
#[derive(Clone, Copy, Debug)]
pub struct TxnFacts<'a> {
    /// This realm's issuer.
    pub issuer: &'a str,
    /// The trust domain it may travel in: this realm.
    pub audience: &'a str,
    /// The subject token's subject.
    pub sub: &'a str,
    /// The transaction id.
    pub txn: &'a str,
    /// The `ExerciseID` of the subject projection, text form.
    pub exercise: &'a str,
    /// The intent digest of an exact-intent subject projection, text form.
    pub intent: Option<&'a str>,
    /// Issue time, Unix milliseconds.
    pub now_ms: u64,
}

/// The Transaction Token's claims: audit context only, with no authority member; `tctx` names
/// the Exercise and its intent (OP-154 m.3 (o)).
#[must_use]
pub fn txn_claims(f: &TxnFacts<'_>) -> Vec<u8> {
    let mut tctx = json!({ "exercise": f.exercise });
    if let (Some(i), serde_json::Value::Object(m)) = (f.intent, &mut tctx) {
        m.insert(String::from("intent"), i.into());
    }
    json!({
        "iss": f.issuer,
        "aud": f.audience,
        "sub": f.sub,
        "txn": f.txn,
        "iat": f.now_ms / 1000,
        "exp": f.now_ms.saturating_add(TXN_TTL_MS) / 1000,
        "tctx": tctx,
    })
    .to_string()
    .into_bytes()
}

#[cfg(test)]
mod tests;
