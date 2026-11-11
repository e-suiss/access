//! Authorization at the PEP (§9.5, §9.5.2 k.6, K08, K11, CR-52): asking the decision point
//! for one intent with the actor's own statement, checking the signed receipt of an ALLOW
//! against the intent, the nonce and the PEP's own identity (L2-RCP-3), and handing the effect
//! an [`Authorized`] value that exists only after that check.
//!
//! Everything that is not a verified ALLOW is a [`Denied`]: a DENY or `REQUIRE_ACTION`, a
//! transport fault, a timeout, a 5xx, an unparsable body, a receipt for another intent,
//! audience or nonce, an ALLOW without a receipt (INV-26, X21, TI-9, MD-8). The PEP's own
//! identity is only the audience; the actor is whoever signed the statement (E17, PI-7).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::marker::PhantomData;

use access_kernel::ais::Statement;
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, ParamValue, intent_digest};
use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, exercise_id};
use access_kernel::model::{ActionRef, EqValue, Id, PurposeRef, ResourceRef, TrustedTime};
use access_kernel::receipt::{self, Expected, Receipt, ReceiptError};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::parse_sign1;
use access_kernel::verify::key_scope::DomainMetadata;

use crate::transport::{Answer, Clock, Fault};

/// Largest decision body read (§14.6).
pub const MAX_BODY: usize = 64 * 1024;

/// Shortest nonce (L1-ADP-7).
pub const MIN_NONCE: usize = 16;

/// Longest nonce (L1-ADP-7).
pub const MAX_NONCE: usize = 64;

/// An action the PEP enforces: the type parameter `A` of [`Authorized`].
pub trait Action {
    /// The action's namespace.
    const NAMESPACE: &'static str;
    /// The action's name.
    const NAME: &'static str;
}

/// A resource the PEP guards: the type parameter `R` of [`Authorized`].
pub trait Resource {
    /// The resource namespace.
    const NAMESPACE: &'static str;
}

/// Why an envelope is not an intent of `R` and `A`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IntentError {
    /// The envelope's action is not `A`.
    #[error("intent-action")]
    Action,
    /// The envelope's primary resource is not an `R`.
    #[error("intent-resource")]
    Resource,
    /// The envelope cannot be encoded.
    #[error("intent-encode")]
    Encode,
}

/// The intent an effect applies, typed by its resource and action. The digest is computed
/// here from the envelope (TI-11); a PEP that only holds the digest the Conformant Surface
/// approved names it with [`Intent::approved`] (§13.4 U6).
#[derive(Clone)]
pub struct Intent<R, A> {
    digest: Digest,
    action: Option<ActionRef>,
    envelope: Option<IntentEnvelope>,
    marker: PhantomData<fn() -> (R, A)>,
}

impl<R, A> core::fmt::Debug for Intent<R, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Intent")
            .field("digest", &self.digest)
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

impl<R: Resource, A: Action> Intent<R, A> {
    /// The intent of an envelope whose action is `A` on an `R`.
    ///
    /// # Errors
    /// [`IntentError`].
    pub fn of(envelope: IntentEnvelope) -> Result<Self, IntentError> {
        if envelope.action.namespace != A::NAMESPACE || envelope.action.name != A::NAME {
            return Err(IntentError::Action);
        }
        if envelope
            .resources
            .first()
            .is_none_or(|r| r.namespace != R::NAMESPACE)
        {
            return Err(IntentError::Resource);
        }
        let digest = intent_digest(&envelope).map_err(|_| IntentError::Encode)?;
        Ok(Self {
            digest,
            action: Some(envelope.action.clone()),
            envelope: Some(envelope),
            marker: PhantomData,
        })
    }
}

impl<R, A> Intent<R, A> {
    /// The intent of an envelope whose action is data rather than a type, such as one row of
    /// an MCP tool table (§9.4.1, AG-2): the digest is computed here, the type parameters name
    /// no action.
    ///
    /// # Errors
    /// [`IntentError::Encode`].
    pub fn named(envelope: IntentEnvelope) -> Result<Self, IntentError> {
        let digest = intent_digest(&envelope).map_err(|_| IntentError::Encode)?;
        Ok(Self {
            digest,
            action: Some(envelope.action.clone()),
            envelope: Some(envelope),
            marker: PhantomData,
        })
    }

    /// An intent known only by the digest the Conformant Surface approved, and the action it
    /// names when the PEP knows it.
    #[must_use]
    pub const fn approved(digest: Digest, action: Option<ActionRef>) -> Self {
        Self {
            digest,
            action,
            envelope: None,
            marker: PhantomData,
        }
    }

    /// The intent digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The action, when known.
    #[must_use]
    pub const fn action(&self) -> Option<&ActionRef> {
        self.action.as_ref()
    }

    /// The envelope, when the PEP has it.
    #[must_use]
    pub const fn envelope(&self) -> Option<&IntentEnvelope> {
        self.envelope.as_ref()
    }
}

/// A request nonce (L1-ADP-7): 16 to 64 bytes from the caller's RNG port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce(Vec<u8>);

/// The nonce length is outside 16 to 64 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("nonce length")]
pub struct NonceError;

impl Nonce {
    /// A nonce of 16 to 64 bytes.
    ///
    /// # Errors
    /// [`NonceError`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, NonceError> {
        if (MIN_NONCE..=MAX_NONCE).contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(NonceError)
        }
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Who acts (§9.5 k.2, k.3, E17): the actor Instance's signed statement, forwarded as signed,
/// or nobody. The PEP has no way to act with its own identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Actor {
    /// The Actor Intent Statement `COSE_Sign1`, exactly as the Instance signed it.
    Statement(Vec<u8>),
    /// No statement: only Public Grants apply.
    Anonymous,
}

/// The PEP: its audience identifier, its domain and the verified Domain Metadata it pins.
#[derive(Clone, Debug)]
pub struct Pep {
    /// The PEP's own authenticated identity, the receipt's audience.
    pub audience: String,
    /// The domain the PEP decides in.
    pub domain: Digest,
    /// Verified Domain Metadata of that domain (CR-58).
    pub metadata: DomainMetadata,
}

/// One Exercise Request as the SDK hands it to the decision port (§9.5, L1-ADP-5 to
/// L1-ADP-8). [`adp_body`] renders it when the envelope is known.
#[derive(Clone, Copy, Debug)]
pub struct ExerciseRequest<'a> {
    /// The domain.
    pub domain: &'a Digest,
    /// `commit` or `continue`.
    pub mode: Mode,
    /// The nonce.
    pub nonce: &'a [u8],
    /// The intent digest.
    pub intent: &'a Digest,
    /// The intent envelope, when the PEP has it.
    pub envelope: Option<&'a IntentEnvelope>,
    /// The actor.
    pub actor: &'a Actor,
    /// The basis.
    pub basis: &'a ExerciseBasis,
    /// The capacity.
    pub capacity: Capacity,
    /// The PEP audience.
    pub pep: &'a str,
    /// The Exercise continued, for `continue` (L1-ADP-13).
    pub exercise: Option<&'a Digest>,
}

/// The decision point port: sends one Exercise Request and reports what came back.
pub trait AskDecision {
    /// Asks; a fault is reported, never decided.
    fn ask(&self, request: &ExerciseRequest<'_>) -> Answer;
}

/// What the PEP asks for one effect.
#[derive(Clone, Copy, Debug)]
pub struct Ask<'a, R, A> {
    /// The intent.
    pub intent: &'a Intent<R, A>,
    /// The nonce.
    pub nonce: &'a Nonce,
    /// The actor.
    pub actor: &'a Actor,
    /// The basis.
    pub basis: &'a ExerciseBasis,
    /// The capacity.
    pub capacity: Capacity,
    /// The Exercise continued; `None` asks a `commit`.
    pub continued: Option<&'a Digest>,
    /// The position the protected content was written at, when the PEP knows it (§9.7A.3,
    /// §13.4 U60, P44): a decision at an older position is refused.
    pub content_position: Option<u64>,
}

/// How Access answered when it did not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// DENY.
    Deny,
    /// `REQUIRE_ACTION`; a PEP applies it as DENY (§9.5 R2).
    RequireAction,
    /// `decision: false` with an outcome the SDK does not know.
    Other,
}

/// What class of thing stopped the effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Access decided against the effect.
    Decision,
    /// An ALLOW the PEP could not verify for this effect.
    Unverified,
    /// No decision could be obtained; the PEP's UNKNOWN (§9.5 "Access-unavailable").
    Unknown,
}

/// Why no effect happens. A value, not an error: every variant is applied as DENY.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Denied {
    /// No trusted time.
    #[error("clock")]
    Clock,
    /// The actor statement does not match this request (§9.5 k.3).
    #[error("actor-statement: {0}")]
    Actor(&'static str),
    /// No response (E25, E28).
    #[error("unavailable: {0}")]
    Unavailable(Fault),
    /// A response other than 200 (L1-ADP-3).
    #[error("status {0}")]
    Status(u16),
    /// The body is not a decision.
    #[error("malformed")]
    Malformed,
    /// Access did not allow.
    #[error("refused")]
    Refused(Refusal),
    /// ALLOW without a receipt (L2-RCP-2).
    #[error("receipt-missing")]
    NoReceipt,
    /// The receipt is not for this PEP, intent, domain or time (L2-RCP-3).
    #[error("{0}")]
    Receipt(ReceiptError),
    /// The receipt names another Exercise than this nonce's.
    #[error("receipt-exercise")]
    Exercise,
    /// The decision is older than the protected content (§13.4 U60).
    #[error("content-position")]
    Stale,
    /// The executed body is not the approved digest (INV-19, §13.4 U6).
    #[error("intent-body")]
    Body,
}

impl Denied {
    /// Stable reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Clock => "clock",
            Self::Actor(_) => "actor-statement",
            Self::Unavailable(_) => "unavailable",
            Self::Status(_) => "status",
            Self::Malformed => "malformed",
            Self::Refused(_) => "refused",
            Self::NoReceipt => "receipt-missing",
            Self::Receipt(e) => e.code(),
            Self::Exercise => "receipt-exercise",
            Self::Stale => "content-position",
            Self::Body => "intent-body",
        }
    }

    /// The class of the denial.
    #[must_use]
    pub const fn class(&self) -> Class {
        match self {
            Self::Refused(_) => Class::Decision,
            Self::Actor(_)
            | Self::NoReceipt
            | Self::Receipt(_)
            | Self::Exercise
            | Self::Stale
            | Self::Body => Class::Unverified,
            Self::Clock | Self::Unavailable(_) | Self::Status(_) | Self::Malformed => {
                Class::Unknown
            }
        }
    }
}

/// Whether the upstream link of a chained effect was enforced (§9.9.2, §13.4 U8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CausalBinding {
    /// A causal-bound allowance keyed to the upstream Exercise applied.
    Enforced,
    /// The upstream reference is recorded only; the console warns (X21).
    AuditOnly,
}

/// What the effect may record about its authorization (EI-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence<'a> {
    /// The Exercise.
    pub exercise: &'a Digest,
    /// The intent digest.
    pub intent: &'a Digest,
    /// The position the decision was made at.
    pub as_of: u64,
}

/// Proof that this intent on an `R` by `A` was allowed: it is built only here, from a verified
/// receipt or a verified projection, carries the `ExerciseID`, the intent digest and the position,
/// and is consumed by the one effect it authorizes (§9.5.2 k.6, CR-52, P40, §13.4 U1).
pub struct Authorized<R, A> {
    exercise: Digest,
    intent: Digest,
    as_of: u64,
    causal_binding: Option<CausalBinding>,
    marker: PhantomData<fn() -> (R, A)>,
}

impl<R, A> core::fmt::Debug for Authorized<R, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authorized")
            .field("exercise", &self.exercise)
            .field("intent", &self.intent)
            .field("as_of", &self.as_of)
            .field("causal_binding", &self.causal_binding)
            .finish()
    }
}

impl<R, A> Authorized<R, A> {
    pub(crate) const fn new(
        exercise: Digest,
        intent: Digest,
        as_of: u64,
        causal_binding: Option<CausalBinding>,
    ) -> Self {
        Self {
            exercise,
            intent,
            as_of,
            causal_binding,
            marker: PhantomData,
        }
    }

    /// The `ExerciseID`; a downstream PEP carries it as its causal reference (§9.9.2).
    #[must_use]
    pub const fn exercise(&self) -> &Digest {
        &self.exercise
    }

    /// The intent digest the ALLOW is for.
    #[must_use]
    pub const fn intent(&self) -> &Digest {
        &self.intent
    }

    /// The position the decision reflects (OP-150 m.3 (l)).
    #[must_use]
    pub const fn as_of(&self) -> u64 {
        self.as_of
    }

    /// Whether the upstream link was enforced, for a chained effect.
    #[must_use]
    pub const fn causal_binding(&self) -> Option<CausalBinding> {
        self.causal_binding
    }

    /// Performs the effect once: `actual` is the digest of the body about to be executed and
    /// must be the approved intent (INV-19, §13.4 U6); the proof is consumed either way.
    ///
    /// # Errors
    /// [`Denied::Body`]; no effect happens.
    pub fn apply<T>(
        self,
        actual: &Digest,
        effect: impl FnOnce(Evidence<'_>) -> T,
    ) -> Result<T, Denied> {
        if *actual != self.intent {
            return Err(Denied::Body);
        }
        Ok(effect(Evidence {
            exercise: &self.exercise,
            intent: &self.intent,
            as_of: self.as_of,
        }))
    }
}

fn statement_matches(
    bytes: &[u8],
    request: &ExerciseRequest<'_>,
    now: TrustedTime,
) -> Result<(), Denied> {
    let payload = parse_sign1(bytes)
        .ok()
        .and_then(|s| s.payload)
        .ok_or(Denied::Actor("payload"))?;
    let s = Statement::from_bytes(&payload).map_err(|_| Denied::Actor("payload"))?;
    if s.domain != *request.domain {
        return Err(Denied::Actor("domain"));
    }
    if s.nonce != request.nonce {
        return Err(Denied::Actor("nonce"));
    }
    if s.intent != *request.intent {
        return Err(Denied::Actor("intent"));
    }
    if s.mode != request.mode {
        return Err(Denied::Actor("mode"));
    }
    if s.pep != request.pep {
        return Err(Denied::Actor("pep"));
    }
    if s.capacity != request.capacity {
        return Err(Denied::Actor("capacity"));
    }
    if s.basis != *request.basis {
        return Err(Denied::Actor("basis"));
    }
    if s.exercise.as_ref() != request.exercise {
        return Err(Denied::Actor("exercise"));
    }
    if s.iat > now.saturating_add(access_kernel::ais::SKEW_MS) {
        return Err(Denied::Actor("future"));
    }
    Ok(())
}

fn member_bytes(v: &Json, name: &str) -> Option<Vec<u8>> {
    v.get(name)
        .and_then(Json::as_str)
        .and_then(|s| b64url_decode(s).ok())
}

fn digest32(bytes: &[u8]) -> Option<Digest> {
    <[u8; 32]>::try_from(bytes).ok().map(Digest)
}

impl Pep {
    /// Asks Access for `ask` and verifies the answer (§9.5, L2-RCP-3): the actor statement
    /// matches the request; the port answered 200 with a decision; `decision` is `true`; the
    /// receipt verifies under the domain's receipt key for this domain, this audience, this
    /// intent and this time; it names the Exercise of this nonce (or the Exercise continued);
    /// and it is not older than the protected content. Only then is the effect authorized.
    ///
    /// # Errors
    /// [`Denied`]: no effect.
    pub fn authorize<R, A>(
        &self,
        ask: &Ask<'_, R, A>,
        clock: &impl Clock,
        decisions: &impl AskDecision,
    ) -> Result<Authorized<R, A>, Denied> {
        let now = clock.now().ok_or(Denied::Clock)?;
        let mode = if ask.continued.is_some() {
            Mode::Continue
        } else {
            Mode::Commit
        };
        let request = ExerciseRequest {
            domain: &self.domain,
            mode,
            nonce: ask.nonce.as_bytes(),
            intent: ask.intent.digest(),
            envelope: ask.intent.envelope(),
            actor: ask.actor,
            basis: ask.basis,
            capacity: ask.capacity,
            pep: &self.audience,
            exercise: ask.continued,
        };
        // §9.5 k.3
        if let Actor::Statement(bytes) = ask.actor {
            statement_matches(bytes, &request, now)?;
        }
        let response = match decisions.ask(&request) {
            Answer::Response(r) => r,
            Answer::Unanswered(fault) => return Err(Denied::Unavailable(fault)),
        };
        // L1-ADP-3
        if response.status != 200 {
            return Err(Denied::Status(response.status));
        }
        let body = json::parse(&response.body, MAX_BODY).map_err(|_| Denied::Malformed)?;
        let Some(Json::Bool(decision)) = body.get("decision") else {
            return Err(Denied::Malformed);
        };
        let context = body.get("context").unwrap_or(&Json::Null);
        // §9.5 R2
        if !*decision {
            let refusal = match context.get("outcome").and_then(Json::as_str) {
                Some("deny") => Refusal::Deny,
                Some("require_action") => Refusal::RequireAction,
                _ => Refusal::Other,
            };
            return Err(Denied::Refused(refusal));
        }
        let receipt = context.get("receipt").ok_or(Denied::NoReceipt)?;
        let (Some(sign1), Some(excerpt)) = (
            member_bytes(receipt, "sign1"),
            member_bytes(receipt, "excerpt"),
        ) else {
            return Err(Denied::NoReceipt);
        };
        let expected = Expected {
            domain: &self.domain,
            audience: &self.audience,
            intent: ask.intent.digest(),
            now,
        };
        let receipt: Receipt =
            receipt::verify(&PureBackend, &self.metadata, &sign1, &excerpt, &expected)
                .map_err(Denied::Receipt)?;
        // OP-141 m.6
        let exercise = match ask.continued {
            Some(e) => *e,
            None => {
                exercise_id(&self.domain, ask.nonce.as_bytes()).map_err(|_| Denied::Exercise)?
            }
        };
        if receipt.exercise != exercise {
            return Err(Denied::Exercise);
        }
        if let Some(named) = member_bytes(context, "exercise")
            && digest32(&named) != Some(exercise)
        {
            return Err(Denied::Exercise);
        }
        // §13.4 U60
        if ask.content_position.is_some_and(|q| receipt.record < q) {
            return Err(Denied::Stale);
        }
        let causal_binding = match context.get("causal_binding").and_then(Json::as_str) {
            Some("enforced") => Some(CausalBinding::Enforced),
            Some("audit-only") => Some(CausalBinding::AuditOnly),
            _ => None,
        };
        Ok(Authorized::new(
            exercise,
            *ask.intent.digest(),
            receipt.record,
            causal_binding,
        ))
    }
}

pub(crate) struct Out(pub(crate) String);

impl Out {
    pub(crate) fn text(&mut self, s: &str) {
        self.0.push('"');
        for c in s.chars() {
            match c {
                '"' => self.0.push_str("\\\""),
                '\\' => self.0.push_str("\\\\"),
                '\n' => self.0.push_str("\\n"),
                '\r' => self.0.push_str("\\r"),
                '\t' => self.0.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    let _ = write!(self.0, "\\u{:04x}", c as u32);
                }
                c => self.0.push(c),
            }
        }
        self.0.push('"');
    }

    pub(crate) fn key(&mut self, k: &str) {
        self.text(k);
        self.0.push(':');
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.text(&b64url_encode(b));
    }

    pub(crate) fn uint(&mut self, n: u64) {
        let _ = write!(self.0, "{n}");
    }

    pub(crate) fn int(&mut self, n: i64) {
        let _ = write!(self.0, "{n}");
    }

    pub(crate) fn id(&mut self, id: &Id) {
        self.bytes(&id.0);
    }

    pub(crate) fn digest(&mut self, d: &Digest) {
        self.bytes(&d.0);
    }

    pub(crate) fn comma(&mut self, first: &mut bool) {
        if !*first {
            self.0.push(',');
        }
        *first = false;
    }

    pub(crate) fn action(&mut self, a: &ActionRef) {
        self.0.push('{');
        self.key("namespace");
        self.text(&a.namespace);
        self.0.push(',');
        self.key("name");
        self.text(&a.name);
        self.0.push(',');
        self.key("major");
        self.uint(a.major);
        self.0.push(',');
        self.key("schema");
        self.digest(&a.schema);
        self.0.push('}');
    }

    pub(crate) fn resource(&mut self, r: &ResourceRef) {
        self.0.push('{');
        self.key("namespace");
        self.text(&r.namespace);
        self.0.push(',');
        self.key("path");
        self.0.push('[');
        let mut first = true;
        for p in &r.path {
            self.comma(&mut first);
            self.text(p);
        }
        self.0.push(']');
        self.0.push(',');
        self.key("incarnation");
        self.uint(r.incarnation);
        self.0.push('}');
    }

    pub(crate) fn purpose(&mut self, p: &PurposeRef) {
        self.0.push('{');
        match p {
            PurposeRef::Code(c) => {
                self.key("code");
                self.text(c);
            }
            PurposeRef::Work(d) => {
                self.key("work");
                self.digest(d);
            }
            PurposeRef::Aim(d) => {
                self.key("aim");
                self.digest(d);
            }
            PurposeRef::Case(d) => {
                self.key("case");
                self.digest(d);
            }
        }
        self.0.push('}');
    }

    pub(crate) fn param(&mut self, v: &ParamValue) {
        self.0.push('{');
        match v {
            ParamValue::Enum(s) => {
                self.key("enum");
                self.text(s);
            }
            ParamValue::Eq(e) => {
                self.key("eq");
                match e {
                    EqValue::Text(t) => self.text(t),
                    EqValue::Int(i) => self.int(*i),
                    EqValue::Bool(b) => self.0.push_str(if *b { "true" } else { "false" }),
                    EqValue::Bytes(b) => {
                        self.0.push('{');
                        self.key("bytes");
                        self.bytes(b);
                        self.0.push('}');
                    }
                }
            }
            ParamValue::Amount { value, unit } => {
                self.key("amount");
                self.0.push('{');
                self.key("value");
                self.int(*value);
                self.0.push(',');
                self.key("unit");
                self.text(unit);
                self.0.push('}');
            }
            ParamValue::Count(n) => {
                self.key("count");
                self.uint(*n);
            }
            ParamValue::Interval(w) => {
                self.key("interval");
                self.window(w.from, w.until);
            }
            ParamValue::Resource(r) => {
                self.key("resource");
                self.resource(r);
            }
            ParamValue::Subject(id) => {
                self.key("subject");
                self.id(id);
            }
            ParamValue::Purpose(p) => {
                self.key("purpose");
                self.purpose(p);
            }
            ParamValue::Flag(b) => {
                self.key("flag");
                self.0.push_str(if *b { "true" } else { "false" });
            }
            ParamValue::Origin { origin, write } => {
                self.key("origin");
                self.0.push('{');
                self.key("origin");
                self.text(origin);
                self.0.push(',');
                self.key("access");
                self.text(if *write { "write" } else { "read" });
                self.0.push('}');
            }
        }
        self.0.push('}');
    }

    pub(crate) fn window(&mut self, from: u64, until: u64) {
        self.0.push('{');
        self.key("from");
        self.uint(from);
        self.0.push(',');
        self.key("until");
        self.uint(until);
        self.0.push('}');
    }

    pub(crate) fn envelope(&mut self, e: &IntentEnvelope) {
        self.0.push('{');
        self.key("action");
        self.action(&e.action);
        self.0.push(',');
        self.key("resources");
        self.0.push('[');
        let mut first = true;
        for r in &e.resources {
            self.comma(&mut first);
            self.resource(r);
        }
        self.0.push(']');
        if !e.params.is_empty() {
            self.0.push(',');
            self.key("params");
            self.0.push('{');
            let mut first = true;
            for (k, v) in &e.params {
                self.comma(&mut first);
                self.key(k);
                self.param(v);
            }
            self.0.push('}');
        }
        if !e.opaque.is_empty() {
            self.0.push(',');
            self.key("opaque");
            self.0.push('{');
            let mut first = true;
            for (k, d) in &e.opaque {
                self.comma(&mut first);
                self.key(k);
                self.digest(d);
            }
            self.0.push('}');
        }
        if let Some(r) = &e.recipient {
            self.0.push(',');
            self.key("recipient");
            self.id(r);
        }
        if let Some(p) = &e.purpose {
            self.0.push(',');
            self.key("purpose");
            self.purpose(p);
        }
        let c = &e.context;
        if *c != access_kernel::intent::ContextRefs::default() {
            self.0.push(',');
            self.key("context");
            self.0.push('{');
            let mut first = true;
            for (k, d) in [
                ("work", &c.work),
                ("commitment", &c.commitment),
                ("step", &c.step),
                ("upstream_exercise", &c.upstream_exercise),
                ("plan", &c.plan),
            ] {
                if let Some(d) = d {
                    self.comma(&mut first);
                    self.key(k);
                    self.digest(d);
                }
            }
            self.0.push('}');
        }
        if !e.provenance.is_empty() {
            self.0.push(',');
            self.key("provenance");
            self.0.push('{');
            let mut first = true;
            for (k, p) in &e.provenance {
                self.comma(&mut first);
                self.key(k);
                self.text(p.label());
            }
            self.0.push('}');
        }
        self.0.push(',');
        self.key("validity");
        self.window(e.validity.from, e.validity.until);
        self.0.push('}');
    }

    pub(crate) fn basis(&mut self, b: &ExerciseBasis) {
        self.0.push('{');
        match b {
            ExerciseBasis::Anchor(id) => {
                self.key("anchor");
                self.id(id);
            }
            ExerciseBasis::Public(id) => {
                self.key("public");
                self.id(id);
            }
            ExerciseBasis::Holding(h) => {
                self.key("holding");
                self.0.push('{');
                self.key("grant");
                self.id(&h.grant);
                self.0.push(',');
                self.key("holder");
                self.id(&h.holder);
                self.0.push(',');
                self.key("since");
                self.uint(h.since);
                self.0.push('}');
            }
        }
        self.0.push('}');
    }
}

/// The `AuthZEN` evaluation body of a request (L1-ADP-5 to L1-ADP-8), when its envelope is
/// known: `subject` is the fixed `access_actor` placeholder Access ignores, `action` and
/// `resource` mirror the intent's action name and primary resource, and the Access members
/// are in `context`. `None` without an envelope: the intent digest is never sent by itself
/// (L1-ADP-8).
#[must_use]
pub fn adp_body(request: &ExerciseRequest<'_>) -> Option<String> {
    let mut out = adp_open(request)?;
    out.0.push_str("}}");
    Some(out.0)
}

/// [`adp_body`] without its two closing braces, so a caller can add `context` members.
pub(crate) fn adp_open(request: &ExerciseRequest<'_>) -> Option<Out> {
    let envelope = request.envelope?;
    let primary = envelope.resources.first()?;
    let mut out = Out(String::new());
    out.0.push('{');
    out.key("subject");
    out.0.push_str(r#"{"type":"access_actor","id":"-"},"#);
    out.key("action");
    out.0.push('{');
    out.key("name");
    out.text(&envelope.action.name);
    out.0.push_str("},");
    out.key("resource");
    out.0.push('{');
    out.key("type");
    out.text(&primary.namespace);
    out.0.push(',');
    out.key("id");
    out.text(&primary.path.join("/"));
    out.0.push_str("},");
    out.key("context");
    out.0.push('{');
    out.key("domain");
    out.digest(request.domain);
    out.0.push(',');
    out.key("mode");
    out.text(match request.mode {
        Mode::Commit => "commit",
        Mode::Continue => "continue",
        Mode::Check => "check",
    });
    out.0.push(',');
    out.key("nonce");
    out.bytes(request.nonce);
    if let Actor::Statement(ais) = request.actor {
        out.0.push(',');
        out.key("ais");
        out.bytes(ais);
    }
    out.0.push(',');
    out.key("basis");
    out.basis(request.basis);
    out.0.push(',');
    out.key("capacity");
    match request.capacity {
        Capacity::Own => out.text("own"),
        Capacity::For(id) => {
            out.0.push('{');
            out.key("for");
            out.id(&id);
            out.0.push('}');
        }
    }
    out.0.push(',');
    out.key("intent");
    out.envelope(envelope);
    if let Some(e) = request.exercise {
        out.0.push(',');
        out.key("exercise");
        out.digest(e);
    }
    Some(out)
}
