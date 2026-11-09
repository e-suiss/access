//! Access over A2A (§9.4.1, §9.9.5, §11.15, AG-34, OP-154 m.3 (y)).
//!
//! - The extension `urn:suiss:access:a2a:authority:v1` carries, in a message's `metadata`, an
//!   authority request, the causal reference to the Exercise that caused a task, a
//!   `REQUIRE_ACTION` with its routes and nonce, and a continuation. A `REQUIRE_ACTION` is the
//!   task state `TASK_STATE_INPUT_REQUIRED` when a person has to act and
//!   `TASK_STATE_AUTH_REQUIRED` when the agent's side has to authenticate or refresh a Claim; a
//!   DENY is `TASK_STATE_FAILED`. None of it is OAuth `interaction_required` (AGI-4).
//! - A task message carries no authority: what arrives is [`Inbound`] data. Taking a task over
//!   is either the delegating agent's own sub-delegation (`grant.issue` from its depth-1
//!   template) or the receiving agent's separate Exercise under its own basis
//!   ([`separate_exercise`]), with the causal reference as `upstream_exercise` only.
//! - An Agent Card is a Claim: its JWS over the RFC 8785 (JCS) form of the card, ES256, counts
//!   only when the signing key is one the domain accepted (AGI-7), and everything in it,
//!   `securitySchemes`, skills and descriptions included, stays data (A-7).
//! - [`security_schemes`] lists the identity plane in a card's `securitySchemes` from its
//!   discovery document: `openIdConnectUrl`, the `authorizationCode`, `clientCredentials` and
//!   `deviceCode` flows it serves, and mTLS-bound tokens (RFC 8705).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use access_kernel::digest::Digest;
use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{Algorithm, KeySet};
use access_kernel::verify::jws::{Origin, verify_compact};

use super::contract::{Continuation, Exercise, Plan, Step};
use super::decision::Route;
use super::request::Handoff;
use super::text::Untrusted;
use crate::authorize::{MAX_BODY, Out};

/// The extension URI.
pub const EXTENSION: &str = "urn:suiss:access:a2a:authority:v1";

/// The `typ` of an Agent Card signature's protected header.
pub const CARD_TYP: &str = "JOSE";

/// The A2A task states Access maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    /// The work goes on.
    Working,
    /// A person has to act.
    InputRequired,
    /// The agent's side has to authenticate or refresh a Claim.
    AuthRequired,
    /// Refused.
    Failed,
}

impl TaskState {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Working => "TASK_STATE_WORKING",
            Self::InputRequired => "TASK_STATE_INPUT_REQUIRED",
            Self::AuthRequired => "TASK_STATE_AUTH_REQUIRED",
            Self::Failed => "TASK_STATE_FAILED",
        }
    }
}

/// The task state of `step` (§9.9.5 A2A row): no decision is a failed task, never a working one.
#[must_use]
pub fn task_state(step: &Step) -> TaskState {
    match step {
        Step::Proceed(_) => TaskState::Working,
        Step::Wait(w)
            if w.routes
                .iter()
                .all(|r| matches!(r, Route::SelfAuthenticate | Route::Issuer)) =>
        {
            TaskState::AuthRequired
        }
        Step::Wait(_) => TaskState::InputRequired,
        Step::Stop(_) | Step::Unknown(_) => TaskState::Failed,
    }
}

fn open(kind: &str) -> Out {
    let mut out = Out(String::new());
    out.0.push('{');
    out.key(EXTENSION);
    out.0.push('{');
    out.key("kind");
    out.text(kind);
    out
}

fn exercise_ref(out: &mut Out, exercise: &Exercise) {
    out.0.push(',');
    out.key("exercise_ref");
    out.0.push('{');
    out.key("domain");
    out.digest(exercise.domain());
    out.0.push(',');
    out.key("nonce");
    out.bytes(exercise.nonce());
    out.0.push(',');
    out.key("intent");
    out.digest(exercise.digest());
    out.0.push('}');
}

fn routes(out: &mut Out, routes: &[Route]) {
    out.0.push(',');
    out.key("remediation");
    out.0.push('[');
    let mut first = true;
    let mut seen = BTreeSet::new();
    for r in routes {
        if seen.insert(r.remediation()) {
            out.comma(&mut first);
            out.text(r.remediation());
        }
    }
    out.0.push(']');
}

/// The extension member of a task in `step` for `exercise`, with the task state: a
/// `REQUIRE_ACTION` names its nonce and routes; a DENY names its blocker classes. `None` for an
/// ALLOW or no decision, which carry no extension member.
#[must_use]
pub fn require_action(exercise: &Exercise, step: &Step) -> Option<(TaskState, String)> {
    let state = task_state(step);
    let mut out = match step {
        Step::Wait(w) => {
            let mut out = open("require_action");
            exercise_ref(&mut out, exercise);
            routes(&mut out, &w.routes);
            out
        }
        Step::Stop(s) => {
            let mut out = open("deny");
            out.0.push(',');
            out.key("classes");
            out.0.push('[');
            let mut first = true;
            for b in &s.blockers {
                out.comma(&mut first);
                out.text(crate::reason::class_name(b.class));
            }
            out.0.push(']');
            out
        }
        Step::Proceed(_) | Step::Unknown(_) => return None,
    };
    out.0.push_str("}}");
    Some((state, out.0))
}

/// The extension member carrying an authority request to the peer that coordinates.
#[must_use]
pub fn authority_request(handoff: &Handoff) -> String {
    let mut out = open("authority_request");
    out.0.push(',');
    out.key("request");
    out.0.push_str(&handoff.request);
    let rs: Vec<Route> = handoff.routes.clone();
    routes(&mut out, &rs);
    out.0.push(',');
    out.key("same_nonce");
    out.0
        .push_str(if handoff.same_nonce { "true" } else { "false" });
    out.0.push_str("}}");
    out.0
}

/// The extension member naming the Exercise that caused a task: an audit link only.
#[must_use]
pub fn causal(exercise: &Digest) -> String {
    let mut out = open("causal");
    out.0.push(',');
    out.key("exercise");
    out.digest(exercise);
    out.0.push_str("}}");
    out.0
}

/// The extension member of a long-running task's continuation: the Exercise and its horizon.
#[must_use]
pub fn continuation(c: &Continuation) -> String {
    let mut out = open("continuation");
    out.0.push(',');
    out.key("exercise");
    out.digest(c.exercise());
    out.0.push(',');
    out.key("horizon");
    out.uint(c.horizon());
    out.0.push_str("}}");
    out.0
}

/// What an inbound extension member says, as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// The Exercise that caused the task.
    Causal(Digest),
    /// The peer waits on a `REQUIRE_ACTION` with these remediation codes.
    RequireAction {
        /// Its nonce's Exercise reference.
        domain: Digest,
        /// Its nonce.
        nonce: Vec<u8>,
        /// The codes.
        remediation: Vec<Untrusted>,
    },
    /// The peer was refused.
    Deny,
    /// The peer asks its coordinator; the request is data for a person to see.
    AuthorityRequest(Untrusted),
    /// The peer's long-running task continues until `horizon`.
    Continuation {
        /// The Exercise.
        exercise: Digest,
        /// Its horizon.
        horizon: u64,
    },
}

/// Why an inbound member is not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum A2aError {
    /// No member of this extension.
    #[error("absent")]
    Absent,
    /// Not the extension's shape.
    #[error("malformed")]
    Malformed,
}

fn digest_of(v: Option<&Json>) -> Result<Digest, A2aError> {
    v.and_then(Json::as_str)
        .and_then(|s| b64url_decode(s).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .map(Digest)
        .ok_or(A2aError::Malformed)
}

/// Reads the extension member of a message's `metadata` object. Whatever else the message
/// carries, a token, a Grant or a statement, is not read: a task message is not authority.
///
/// # Errors
/// [`A2aError`].
pub fn inbound(metadata: &[u8]) -> Result<Inbound, A2aError> {
    let root = json::parse(metadata, MAX_BODY).map_err(|_| A2aError::Malformed)?;
    let m = root.get(EXTENSION).ok_or(A2aError::Absent)?;
    match m.get("kind").and_then(Json::as_str) {
        Some("causal") => Ok(Inbound::Causal(digest_of(m.get("exercise"))?)),
        Some("require_action") => {
            let r = m.get("exercise_ref").ok_or(A2aError::Malformed)?;
            let nonce = r
                .get("nonce")
                .and_then(Json::as_str)
                .and_then(|s| b64url_decode(s).ok())
                .filter(|n| (16..=64).contains(&n.len()))
                .ok_or(A2aError::Malformed)?;
            let remediation = match m.get("remediation") {
                Some(Json::Array(items)) => items
                    .iter()
                    .map(|c| c.as_str().map(Untrusted::new).ok_or(A2aError::Malformed))
                    .collect::<Result<_, _>>()?,
                _ => return Err(A2aError::Malformed),
            };
            Ok(Inbound::RequireAction {
                domain: digest_of(r.get("domain"))?,
                nonce,
                remediation,
            })
        }
        Some("deny") => Ok(Inbound::Deny),
        Some("authority_request") => {
            let r = m.get("request").ok_or(A2aError::Malformed)?;
            let mut out = String::new();
            jcs(&mut out, r);
            Ok(Inbound::AuthorityRequest(Untrusted::new(&out)))
        }
        Some("continuation") => Ok(Inbound::Continuation {
            exercise: digest_of(m.get("exercise"))?,
            horizon: m
                .get("horizon")
                .and_then(Json::as_int)
                .and_then(|h| u64::try_from(h).ok())
                .ok_or(A2aError::Malformed)?,
        }),
        _ => Err(A2aError::Malformed),
    }
}

/// The receiving agent's own Exercise for a task it took over (AG-34): its own basis and
/// capacity in `plan`, with the delegator's Exercise only as `upstream_exercise`.
#[must_use]
pub fn separate_exercise(mut plan: Plan, caused_by: &Inbound) -> Plan {
    if let Inbound::Causal(e) = caused_by {
        plan.intent.context.upstream_exercise = Some(*e);
    }
    plan
}

fn jcs_text(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Appends the RFC 8785 form of `v`: members sorted by their UTF-16 code units, no whitespace.
pub fn jcs(out: &mut String, v: &Json) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::Str(s) => jcs_text(out, s),
        Json::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                jcs(out, item);
            }
            out.push(']');
        }
        Json::Object(members) => {
            let mut sorted: Vec<&(String, Json)> = members.iter().collect();
            sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (n, (k, item)) in sorted.into_iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                jcs_text(out, k);
                out.push(':');
                jcs(out, item);
            }
            out.push('}');
        }
    }
}

/// The card without `signatures`, in JCS form: what a card signature signs.
fn signed_form(card: &Json) -> Option<String> {
    let Json::Object(members) = card else {
        return None;
    };
    let unsigned = Json::Object(
        members
            .iter()
            .filter(|(k, _)| k != "signatures")
            .cloned()
            .collect(),
    );
    let mut out = String::new();
    jcs(&mut out, &unsigned);
    Some(out)
}

/// The JWS signing input of `card` for the key `kid`: `protected.payload`, where the protected
/// header is `{"alg":"ES256","kid":…,"typ":"JOSE"}` and the payload is the JCS form of the card
/// without `signatures`.
#[must_use]
pub fn card_signing_input(card: &[u8], kid: &[u8; 32]) -> Option<String> {
    let card = json::parse(card, MAX_BODY).ok()?;
    let payload = signed_form(&card)?;
    let header = alloc::format!(
        "{{\"alg\":\"ES256\",\"kid\":\"{}\",\"typ\":\"{CARD_TYP}\"}}",
        b64url_encode(kid)
    );
    Some(alloc::format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    ))
}

/// A verified Agent Card: the accepted signer's key id and the card, as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    /// The accepted key that signed it.
    pub signer: [u8; 32],
    /// The card's `name`.
    pub name: Untrusted,
    /// The whole card in JCS form.
    pub card: Untrusted,
}

/// Why a card is not a Claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CardError {
    /// Not a card.
    #[error("card-malformed")]
    Malformed,
    /// Unsigned.
    #[error("card-unsigned")]
    Unsigned,
    /// No signature verifies under a key the domain accepted.
    #[error("card-signer-not-accepted")]
    NotAccepted,
}

/// Verifies `card` (§11.15, AG-34, AGI-7): at least one entry of `signatures`, each exactly
/// `{protected, signature}`, verifies as ES256 over the card's JCS form under a key in
/// `accepted`, the keys the domain's Acceptance names for the card's issuer. A card no accepted
/// key signed is nothing: not a Claim, not an input.
///
/// # Errors
/// [`CardError`].
pub fn verify_card(card: &[u8], accepted: &KeySet) -> Result<Card, CardError> {
    let parsed = json::parse(card, MAX_BODY).map_err(|_| CardError::Malformed)?;
    let payload = signed_form(&parsed).ok_or(CardError::Malformed)?;
    let name = parsed
        .get("name")
        .and_then(Json::as_str)
        .ok_or(CardError::Malformed)?;
    let Some(Json::Array(signatures)) = parsed.get("signatures") else {
        return Err(CardError::Unsigned);
    };
    if signatures.is_empty() {
        return Err(CardError::Unsigned);
    }
    let mut keys = KeySet {
        keys: accepted.keys.clone(),
        allowed: BTreeSet::from([Algorithm::Es256]),
    };
    keys.allowed.retain(|a| accepted.allowed.contains(a));
    let encoded = b64url_encode(payload.as_bytes());
    for s in signatures {
        let Json::Object(members) = s else {
            return Err(CardError::Malformed);
        };
        if members.len() != 2 {
            return Err(CardError::Malformed);
        }
        let (Some(protected), Some(signature)) = (
            s.get("protected").and_then(Json::as_str),
            s.get("signature").and_then(Json::as_str),
        ) else {
            return Err(CardError::Malformed);
        };
        let token = alloc::format!("{protected}.{encoded}.{signature}");
        if let Ok(v) = verify_compact(&PureBackend, &token, &keys, CARD_TYP, Origin::External) {
            return Ok(Card {
                signer: v.kid,
                name: Untrusted::new(name),
                card: Untrusted::new(&payload),
            });
        }
    }
    Err(CardError::NotAccepted)
}

fn https(v: Option<&Json>) -> Option<&str> {
    v.and_then(Json::as_str)
        .filter(|u| u.starts_with("https://"))
}

fn flow(out: &mut Out, first: &mut bool, name: &str, members: &[(&str, &str)]) {
    out.comma(first);
    out.key(name);
    out.0.push('{');
    for (k, v) in members {
        out.key(k);
        out.text(v);
        out.0.push(',');
    }
    out.0.push_str("\"scopes\":{}}");
}

/// The identity plane's entries for an Agent Card's `securitySchemes` (`OpenAPI` 3 shapes), from
/// the realm's OpenID discovery document: OpenID Connect discovery, the OAuth 2.0 flows it
/// serves, and mutual TLS when it binds tokens to client certificates. `None` when the document
/// is not an `https` issuer's.
#[must_use]
pub fn security_schemes(discovery: &[u8]) -> Option<String> {
    let d = json::parse(discovery, MAX_BODY).ok()?;
    let issuer = https(d.get("issuer"))?;
    let token = https(d.get("token_endpoint"))?;
    let grants: Vec<&str> = match d.get("grant_types_supported") {
        Some(Json::Array(g)) => g.iter().filter_map(Json::as_str).collect(),
        _ => Vec::from(["authorization_code"]),
    };
    let mut out = Out(String::new());
    out.0.push('{');
    out.key("access_openid");
    out.0.push_str("{\"type\":\"openIdConnect\",");
    out.key("openIdConnectUrl");
    out.text(&alloc::format!("{issuer}/.well-known/openid-configuration"));
    out.0.push_str("},");
    out.key("access_oauth2");
    out.0.push_str("{\"type\":\"oauth2\",\"flows\":{");
    let mut first = true;
    if let Some(a) = https(d.get("authorization_endpoint"))
        && grants.contains(&"authorization_code")
    {
        flow(
            &mut out,
            &mut first,
            "authorizationCode",
            &[("authorizationUrl", a), ("tokenUrl", token)],
        );
    }
    if grants.contains(&"client_credentials") {
        flow(
            &mut out,
            &mut first,
            "clientCredentials",
            &[("tokenUrl", token)],
        );
    }
    if let Some(device) = https(d.get("device_authorization_endpoint"))
        && grants.contains(&"urn:ietf:params:oauth:grant-type:device_code")
    {
        flow(
            &mut out,
            &mut first,
            "deviceCode",
            &[("deviceAuthorizationUrl", device), ("tokenUrl", token)],
        );
    }
    out.0.push_str("}}");
    if matches!(
        d.get("tls_client_certificate_bound_access_tokens"),
        Some(Json::Bool(true))
    ) {
        out.0.push(',');
        out.key("access_mtls");
        out.0.push_str("{\"type\":\"mutualTLS\"}");
    }
    out.0.push('}');
    Some(out.0)
}
