//! The hook contract free of I/O (OP-63): call points, registrations and their changes, the
//! signed request, and how an answer is read into an outcome (TN-135, OP-151 m.3 (j), MD-8).

use std::collections::BTreeMap;

use access_internal_api::idp::RESOURCE_NAMESPACE;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::model::{ResourceRef, Window};
use serde_json::{Map, Value, json};
use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
use suiss_crypto::digest::context_digest;

use crate::actions::ExtensionAction;

/// How long Access waits for a hook's answer (OP-151 m.3 (j), PD).
pub const TIMEOUT_MS: u64 = 3_000;

/// Largest answer body read, bytes.
pub const MAX_ANSWER: usize = 16 * 1024;

/// Most claims one `token_issuance` answer adds.
pub const MAX_CLAIMS: usize = 16;

/// Longest string claim value, bytes.
pub const MAX_CLAIM_VALUE: usize = 1024;

/// Most items of an array claim value.
pub const MAX_CLAIM_ITEMS: usize = 16;

/// Context label of a change digest, the one every `idp.*` change uses (EI-25).
pub const CHANGE_CONTEXT: &str = "access/idp-change/v1";

/// The intent's opaque parameter that carries the change digest (EI-25).
pub const CHANGE_PARAM: &str = "change";

/// Type URN prefix of a hook request.
pub const TYPE_PREFIX: &str = "urn:suiss:access:hook:";

/// Protocol claims a hook can never write (must-never #18, §9.9.4).
pub const RESERVED_CLAIMS: [&str; 21] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "jti",
    "nbf",
    "act",
    "may_act",
    "cnf",
    "scope",
    "client_id",
    "nonce",
    "auth_time",
    "acr",
    "amr",
    "azp",
    "sid",
    "at_hash",
    "c_hash",
    "authorization_details",
];

/// Claims only an authority projection carries (OP-150 m.11 (e), INV-12, INV-33): a hook's
/// answer is identity data and never names them.
pub const AUTHORITY_CLAIMS: [&str; 10] = [
    "roles",
    "role",
    "groups",
    "entitlements",
    "permissions",
    "access_contract",
    "family",
    "rev",
    "status",
    "events",
];

/// A value outside the contract; the code is the RFC 9457 reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid: {0}")]
pub struct Invalid(pub &'static str);

/// Where the identity plane calls a hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HookPoint {
    /// Before an account is created; may only refuse.
    PreRegistration,
    /// Before the ID token is signed; may only add identity claims.
    TokenIssuance,
    /// After every sign-in requirement is met, before the session opens; may only refuse.
    PostLogin,
}

impl HookPoint {
    /// Every call point.
    pub const ALL: [Self; 3] = [Self::PreRegistration, Self::TokenIssuance, Self::PostLogin];

    /// The stored and wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PreRegistration => "pre_registration",
            Self::TokenIssuance => "token_issuance",
            Self::PostLogin => "post_login",
        }
    }

    /// The call point of a name.
    #[must_use]
    pub fn from_name(n: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == n)
    }
}

/// What happens when a hook gives no usable answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnNoAnswer {
    /// Refuse (MD-8); the only choice for a refusing call point.
    Refuse,
    /// Issue the token without the hook's claims; `token_issuance` only.
    ContinueWithoutClaims,
}

impl OnNoAnswer {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::ContinueWithoutClaims => "continue_without_claims",
        }
    }

    /// From the stored name.
    #[must_use]
    pub fn from_name(n: &str) -> Option<Self> {
        [Self::Refuse, Self::ContinueWithoutClaims]
            .into_iter()
            .find(|o| o.name() == n)
    }
}

/// How a hook or webhook request is signed (TN-136).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signing {
    /// Standard Webhooks `v1a`, the default.
    Ed25519,
    /// Standard Webhooks `v1`, for compatibility only.
    Hmac,
}

impl Signing {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Hmac => "hmac",
        }
    }

    /// From the stored name.
    #[must_use]
    pub fn from_name(n: &str) -> Option<Self> {
        [Self::Ed25519, Self::Hmac]
            .into_iter()
            .find(|s| s.name() == n)
    }
}

/// Personal data a hook may receive besides pseudonymous ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disclosure {
    /// The e-mail identifier, at `pre_registration`.
    Email,
}

impl Disclosure {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Email => "email",
        }
    }

    /// From the stored name.
    #[must_use]
    pub fn from_name(n: &str) -> Option<Self> {
        (n == "email").then_some(Self::Email)
    }
}

/// Whether `url` may be a hook or webhook endpoint: `https`, at most 2048 bytes, no user info
/// or fragment, a DNS host name (never an IP literal), and, unless the realm allows private
/// targets, port 443 and no local-only name. A name that resolves to a private address is
/// refused again when the request is sent (§14.3).
///
/// # Errors
/// [`Invalid`] `url`.
pub fn check_target(url: &str, allow_private: bool) -> Result<(), Invalid> {
    let bad = Invalid("url");
    if url.len() > 2048 || url.bytes().any(|c| !c.is_ascii_graphic() || c == b'#') {
        return Err(bad);
    }
    let rest = url.strip_prefix("https://").ok_or(bad)?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = rest.get(..end).ok_or(bad)?;
    if authority.contains('@') || authority.starts_with('[') {
        return Err(bad);
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p.parse::<u16>().map_err(|_| bad)?)),
        None => (authority, None),
    };
    let host = host.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let dns = labels.len() >= 2
        && host.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.bytes().any(|c| c.is_ascii_alphabetic()));
    if !dns {
        return Err(bad);
    }
    let local = [
        "localhost",
        "local",
        "internal",
        "home",
        "lan",
        "localdomain",
    ]
    .iter()
    .any(|s| labels.last() == Some(s));
    if !allow_private && (local || port.is_some_and(|p| p != 443)) {
        return Err(bad);
    }
    Ok(())
}

/// A hook as an actor registers it (`idp.hook.register`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookSpec {
    /// The call point.
    pub point: HookPoint,
    /// The tenant's HTTPS endpoint.
    pub url: String,
    /// What a missing answer means.
    pub on_no_answer: OnNoAnswer,
    /// Personal data it may receive.
    pub disclose: Vec<Disclosure>,
    /// How its requests are signed.
    pub signing: Signing,
}

impl HookSpec {
    /// Checks the registration on its own: a valid target, `continue_without_claims` only at
    /// `token_issuance`, the e-mail only at `pre_registration`.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn check(&self, allow_private: bool) -> Result<(), Invalid> {
        check_target(&self.url, allow_private)?;
        if self.on_no_answer == OnNoAnswer::ContinueWithoutClaims
            && self.point != HookPoint::TokenIssuance
        {
            return Err(Invalid("on_no_answer"));
        }
        if !self.disclose.is_empty() && self.point != HookPoint::PreRegistration {
            return Err(Invalid("disclose"));
        }
        Ok(())
    }
}

/// One `idp.hook.*` change (TN-135): a URL change is a retirement and a new registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookChange {
    /// `idp.hook.register` of a new hook with this id.
    Register {
        /// The new hook's id.
        id: [u8; 16],
        /// Its registration.
        spec: HookSpec,
    },
    /// `idp.hook.retire`.
    Retire {
        /// The hook.
        id: [u8; 16],
    },
}

/// The `dCBOR` text of a UUID-shaped id.
fn id_text(id: &[u8; 16]) -> String {
    uuid(id)
}

/// `SHA-256(CHANGE_CONTEXT ‖ 0x00 ‖ dCBOR({action, body}))`, the digest every `idp.*` change is
/// bound by (EI-25).
///
/// # Errors
/// [`dcbor::EncodeError`].
pub fn change_digest(action: ExtensionAction, body: Cbor) -> Result<Digest, dcbor::EncodeError> {
    let v = Cbor::Map(vec![
        (Cbor::text("action"), Cbor::text(&action.label())),
        (Cbor::text("body"), body),
    ]);
    let bytes = dcbor::encode(&v, Limits::CEILING)?;
    Ok(Digest(context_digest(CHANGE_CONTEXT, &bytes).0))
}

/// The intent of a change of `resource` in realm `slug` (EI-25).
///
/// # Errors
/// [`dcbor::EncodeError`].
pub fn change_intent(
    action: ExtensionAction,
    body: Cbor,
    slug: &str,
    resource: [&str; 2],
    validity: Window,
) -> Result<IntentEnvelope, dcbor::EncodeError> {
    Ok(IntentEnvelope {
        action: action.action_ref(),
        resources: vec![ResourceRef {
            namespace: String::from(RESOURCE_NAMESPACE),
            path: vec![
                String::from(slug),
                String::from(resource[0]),
                String::from(resource[1]),
            ],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::from([(String::from(CHANGE_PARAM), change_digest(action, body)?)]),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity,
    })
}

impl HookChange {
    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> ExtensionAction {
        match self {
            Self::Register { .. } => ExtensionAction::HookRegister,
            Self::Retire { .. } => ExtensionAction::HookRetire,
        }
    }

    /// What the change digest covers.
    #[must_use]
    pub fn body(&self) -> Cbor {
        match self {
            Self::Register { id, spec } => Cbor::Map(vec![
                (Cbor::text("hook"), Cbor::text(&id_text(id))),
                (Cbor::text("point"), Cbor::text(spec.point.name())),
                (Cbor::text("url"), Cbor::text(&spec.url)),
                (
                    Cbor::text("on_no_answer"),
                    Cbor::text(spec.on_no_answer.name()),
                ),
                (
                    Cbor::text("disclose"),
                    Cbor::Array(spec.disclose.iter().map(|d| Cbor::text(d.name())).collect()),
                ),
                (Cbor::text("signing"), Cbor::text(spec.signing.name())),
            ]),
            Self::Retire { id } => Cbor::Map(vec![(Cbor::text("hook"), Cbor::text(&id_text(id)))]),
        }
    }

    /// The intent that authorizes it in realm `slug`, valid over `validity`.
    ///
    /// # Errors
    /// [`dcbor::EncodeError`].
    pub fn intent(
        &self,
        slug: &str,
        validity: Window,
    ) -> Result<IntentEnvelope, dcbor::EncodeError> {
        let id = match self {
            Self::Register { id, .. } | Self::Retire { id } => id_text(id),
        };
        change_intent(self.action(), self.body(), slug, ["hook", &id], validity)
    }
}

/// A live hook as the caller finds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// Its id.
    pub id: [u8; 16],
    /// Its call point.
    pub point: HookPoint,
    /// Its endpoint.
    pub url: String,
    /// What a missing answer means.
    pub on_no_answer: OnNoAnswer,
    /// Personal data it may receive.
    pub disclose: Vec<Disclosure>,
}

/// The facts of a `pre_registration` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreRegistration {
    /// The kinds of identifiers the new account would have (`email`, `phone`, `username`).
    pub identifier_kinds: Vec<&'static str>,
    /// The e-mail identifier, sent only when disclosed.
    pub email: Option<String>,
}

/// The facts of a `token_issuance` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenIssuance {
    /// The client.
    pub client_id: String,
    /// The pairwise `sub` the token carries (MD-10).
    pub subject: String,
    /// The granted scope.
    pub scope: String,
    /// The `acr` of the authentication.
    pub acr: String,
}

/// The facts of a `post_login` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostLogin {
    /// The account's `usr_` id.
    pub account: String,
    /// The AAL reached.
    pub aal: u8,
    /// The method classes used (`password`, `passkey`, `totp`, …).
    pub methods: Vec<&'static str>,
}

/// One call, with its facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    /// `pre_registration`.
    PreRegistration(PreRegistration),
    /// `token_issuance`.
    TokenIssuance(TokenIssuance),
    /// `post_login`.
    PostLogin(PostLogin),
}

impl Call {
    /// Its call point.
    #[must_use]
    pub const fn point(&self) -> HookPoint {
        match self {
            Self::PreRegistration(_) => HookPoint::PreRegistration,
            Self::TokenIssuance(_) => HookPoint::TokenIssuance,
            Self::PostLogin(_) => HookPoint::PostLogin,
        }
    }

    fn data(&self, disclose_email: bool) -> Value {
        match self {
            Self::PreRegistration(p) => {
                let mut m = Map::new();
                m.insert("identifier_kinds".into(), p.identifier_kinds.clone().into());
                if let (true, Some(e)) = (disclose_email, &p.email) {
                    m.insert("email".into(), e.clone().into());
                }
                Value::Object(m)
            }
            Self::TokenIssuance(t) => json!({
                "client_id": t.client_id,
                "subject": t.subject,
                "scope": t.scope,
                "acr": t.acr,
            }),
            Self::PostLogin(p) => json!({
                "account": p.account,
                "aal": p.aal,
                "methods": p.methods,
            }),
        }
    }
}

/// A UUID in its text form.
#[must_use]
pub fn uuid(b: &[u8; 16]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The JSON body of one call: `{type, id, hook, realm, at, data}`. The e-mail enters only when
/// the registration discloses it and the realm allows disclosure.
///
/// # Errors
/// [`Invalid`] when encoding fails.
pub fn request_body(
    reg: &Registration,
    call: &Call,
    call_id: &str,
    realm: &[u8; 16],
    at_ms: u64,
    realm_allows_disclosure: bool,
) -> Result<Vec<u8>, Invalid> {
    let email = realm_allows_disclosure && reg.disclose.contains(&Disclosure::Email);
    serde_json::to_vec(&json!({
        "type": format!("{TYPE_PREFIX}{}", call.point().name()),
        "id": call_id,
        "hook": uuid(&reg.id),
        "realm": uuid(realm),
        "at": at_ms,
        "data": call.data(email),
    }))
    .map_err(|_| Invalid("encoding"))
}

/// The headers of one call: the Standard Webhooks triple, so any Standard Webhooks library
/// verifies it, and `hook-id` and `hook-timestamp` naming the registration and the time.
#[must_use]
pub fn request_headers(
    call_id: &str,
    timestamp_s: u64,
    signature: String,
    hook: &[u8; 16],
) -> Vec<(&'static str, String)> {
    vec![
        ("webhook-id", String::from(call_id)),
        ("webhook-timestamp", timestamp_s.to_string()),
        ("webhook-signature", signature),
        ("hook-id", uuid(hook)),
        ("hook-timestamp", timestamp_s.to_string()),
    ]
}

/// What came back from one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// An HTTP answer within the deadline, its body read up to [`MAX_ANSWER`].
    Answered {
        /// Status.
        status: u16,
        /// Body.
        body: Vec<u8>,
    },
    /// No answer: a timeout, an unreachable or refused endpoint, or no usable key.
    NoAnswer,
}

/// Why a call refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The hook answered `deny`.
    Denied {
        /// Its reason code, as it gave it.
        reason_code: Option<String>,
    },
    /// No answer, or a non-`2xx` answer (MD-8).
    Unanswered,
    /// An answer outside its schema, or a claim it may not write (must-never #18).
    Violation,
    /// The hook registration could not be read (MD-8).
    Unavailable,
}

impl Refusal {
    /// The stable reason code a refusal surfaces as.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Denied { .. } => "hook-denied",
            Self::Unanswered | Self::Unavailable => "hook-unavailable",
            Self::Violation => "hook-invalid-answer",
        }
    }
}

/// The outcome of a call point. A decision, not an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Go on; `claims` are the identity claims a `token_issuance` hook added (empty otherwise).
    Proceed {
        /// Claims to add.
        claims: Map<String, Value>,
    },
    /// Stop: registration refused, sign-in refused, token not issued.
    Refused(Refusal),
}

impl Outcome {
    /// Go on, nothing added.
    #[must_use]
    pub fn proceed() -> Self {
        Self::Proceed { claims: Map::new() }
    }
}

/// Whether a hook may write claim `name`: the token claim grammar, never reserved, never
/// authority (must-never #18, OP-150 m.11 (e)).
#[must_use]
pub fn claim_allowed(name: &str) -> bool {
    let mut bytes = name.bytes();
    let first = bytes.next().is_some_and(|c| c.is_ascii_lowercase());
    first
        && name.len() <= 64
        && bytes.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        && !RESERVED_CLAIMS.contains(&name)
        && !AUTHORITY_CLAIMS.contains(&name)
}

fn scalar_ok(v: &Value) -> bool {
    match v {
        Value::String(s) => s.len() <= MAX_CLAIM_VALUE,
        Value::Bool(_) | Value::Number(_) => true,
        Value::Null | Value::Array(_) | Value::Object(_) => false,
    }
}

fn claim_value_ok(v: &Value) -> bool {
    match v {
        Value::Array(items) => items.len() <= MAX_CLAIM_ITEMS && items.iter().all(scalar_ok),
        other => scalar_ok(other),
    }
}

fn reason_code_ok(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_lowercase())
        && s.len() <= 64
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// Reads a refusing call point's answer: `{"decision": "allow"|"deny", "reason_code"?}` and
/// nothing else.
fn read_decision(body: &[u8]) -> Result<Outcome, Refusal> {
    let v: Value = serde_json::from_slice(body).map_err(|_| Refusal::Violation)?;
    let o = v.as_object().ok_or(Refusal::Violation)?;
    if o.keys().any(|k| k != "decision" && k != "reason_code") {
        return Err(Refusal::Violation);
    }
    let reason_code = match o.get("reason_code") {
        None => None,
        Some(Value::String(s)) if reason_code_ok(s) => Some(s.clone()),
        Some(_) => return Err(Refusal::Violation),
    };
    match o.get("decision").and_then(Value::as_str) {
        Some("allow") => Ok(Outcome::proceed()),
        Some("deny") => Ok(Outcome::Refused(Refusal::Denied { reason_code })),
        _ => Err(Refusal::Violation),
    }
}

/// Reads a `token_issuance` answer: `{"claims": {…}}` and nothing else; one name or value
/// outside the contract drops the whole answer (must-never #18).
fn read_claims(body: &[u8]) -> Result<Outcome, Refusal> {
    let v: Value = serde_json::from_slice(body).map_err(|_| Refusal::Violation)?;
    let o = v.as_object().ok_or(Refusal::Violation)?;
    if o.len() != 1 {
        return Err(Refusal::Violation);
    }
    let claims = o
        .get("claims")
        .and_then(Value::as_object)
        .ok_or(Refusal::Violation)?;
    if claims.len() > MAX_CLAIMS
        || claims
            .iter()
            .any(|(k, v)| !claim_allowed(k) || !claim_value_ok(v))
    {
        return Err(Refusal::Violation);
    }
    Ok(Outcome::Proceed {
        claims: claims.clone(),
    })
}

/// The outcome of one call (MD-8): an answer inside its schema decides; anything else refuses,
/// except that a `token_issuance` hook registered with `continue_without_claims` lets a missing
/// or non-`2xx` answer through without claims. A schema violation refuses at every call point.
#[must_use]
pub fn decide(point: HookPoint, on_no_answer: OnNoAnswer, reply: &Reply) -> Outcome {
    let unanswered = || match (point, on_no_answer) {
        (HookPoint::TokenIssuance, OnNoAnswer::ContinueWithoutClaims) => Outcome::proceed(),
        _ => Outcome::Refused(Refusal::Unanswered),
    };
    match reply {
        Reply::NoAnswer => unanswered(),
        Reply::Answered { status, .. } if !(200..=299).contains(status) => unanswered(),
        Reply::Answered { body, .. } if body.len() > MAX_ANSWER => {
            Outcome::Refused(Refusal::Violation)
        }
        Reply::Answered { body, .. } => {
            let read = match point {
                HookPoint::TokenIssuance => read_claims(body),
                HookPoint::PreRegistration | HookPoint::PostLogin => read_decision(body),
            };
            read.unwrap_or_else(Outcome::Refused)
        }
    }
}

/// Adds a hook's claims to the JSON claims of an ID token; a name the token already has is
/// never overwritten (must-never #18).
///
/// # Errors
/// [`Invalid`] when `token` is not a JSON object.
pub fn with_claims(token: &[u8], claims: &Map<String, Value>) -> Result<Vec<u8>, Invalid> {
    if claims.is_empty() {
        return Ok(token.to_vec());
    }
    let mut v: Value = serde_json::from_slice(token).map_err(|_| Invalid("claims"))?;
    let m = v.as_object_mut().ok_or(Invalid("claims"))?;
    for (k, val) in claims {
        if claim_allowed(k) && !m.contains_key(k) {
            m.insert(k.clone(), val.clone());
        }
    }
    serde_json::to_vec(&v).map_err(|_| Invalid("encoding"))
}

#[cfg(test)]
mod tests;
