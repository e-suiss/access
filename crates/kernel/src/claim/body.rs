//! Claim classes of the identity and verifier boundary (OP-150 m.2, §9.13, §10.1.5, §9.12.1–
//! §9.12.3) and their bodies (L2-CLB-1 to L2-CLB-3). A class with one scalar field carries it
//! in the Claim's `value`; any other class carries the digest of its body there, and the body
//! travels beside the Claim, or is withheld (E26).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::codec::{Canonical, Fields, ModelError, ident, int, map, set_of, set_value, text, uint};
use crate::digest::Digest;
use crate::model::{EqValue, Id};
use crate::report::Report;
use crate::validity::{ProfileVariant, VARIANTS, word, word_of};
use crate::verify::key_scope::{SpecVersions, ct_key, horizon_caps};

use super::Statement;

/// Digest context of a Claim body: `SHA-256(context ‖ 0x00 ‖ dCBOR([class, body]))` (L2-CLB-1).
pub const BODY_CONTEXT: &str = "access/claim-body/v1";

/// Kinds of `identity_binding_<kind>` (§10.1.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingKind {
    /// A natural person.
    Person,
    /// An organization.
    Organization,
    /// A workload.
    Workload,
    /// An agent.
    Agent,
    /// A legal representative.
    LegalRepresentative,
}

const BINDING_KINDS: [(&str, BindingKind); 5] = [
    ("person", BindingKind::Person),
    ("organization", BindingKind::Organization),
    ("workload", BindingKind::Workload),
    ("agent", BindingKind::Agent),
    ("legal_representative", BindingKind::LegalRepresentative),
];

/// The Stage 6 Claim classes, by wire name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Class {
    /// `authentication`: body [`Authentication`].
    Authentication,
    /// `authenticator_binding`: body [`AuthenticatorBinding`].
    AuthenticatorBinding,
    /// `posture_device`: body [`DevicePosture`].
    PostureDevice,
    /// `verifier_profile`: body [`VerifierProfile`].
    VerifierProfile,
    /// `offline_exercise_report`: body [`Report`].
    OfflineExerciseReport,
    /// `authority_state_ack`: body [`AuthorityStateAck`].
    AuthorityStateAck,
    /// `party_key_state`: body [`PartyKeyState`].
    PartyKeyState,
    /// `party_recovered`: body [`PartyRecovered`].
    PartyRecovered,
    /// `identity_binding_<kind>`: body [`IdentityBinding`].
    IdentityBinding(BindingKind),
    /// `account_status`: text value, one of [`ACCOUNT_STATUSES`].
    AccountStatus,
    /// `party_compromise`: optional unsigned value, `occurred_at`.
    PartyCompromise,
    /// `party_terminated`: unsigned value, the time.
    PartyTerminated,
    /// `party_identity_break`: ident value, the reason.
    PartyIdentityBreak,
    /// `controller_of`: Party value, the controller.
    ControllerOf,
    /// `operated_by`: Party value, the operator.
    OperatedBy,
    /// `sponsored_by`: Party value, the sponsor.
    SponsoredBy,
    /// `agent_kind`: ident value.
    AgentKind,
    /// `org_member`: Party value, the organization whose member the subject is, so a `Pred`
    /// holder selects one organization's members (OP-153 m.17 (c), m.25 (a)).
    OrgMember,
    /// `attestation_runtime`: 32-byte value, the digest of the attested runtime class; a
    /// narrowing input only (AG-31, OP-154 m.3 (s)).
    AttestationRuntime,
    /// `effect_attestation`: body [`EffectAttestation`], an executor's report of one effect
    /// (E64, OP-154 m.3 (u)).
    EffectAttestation,
    /// `executor_control`: body [`ExecutorControl`], an executor's confirmation that an
    /// Exercise's job is paused or stopped (U5, OP-154 m.3 (u)).
    ExecutorControl,
}

const SIMPLE: [(&str, Class); 20] = [
    ("authentication", Class::Authentication),
    ("authenticator_binding", Class::AuthenticatorBinding),
    ("posture_device", Class::PostureDevice),
    ("verifier_profile", Class::VerifierProfile),
    ("offline_exercise_report", Class::OfflineExerciseReport),
    ("authority_state_ack", Class::AuthorityStateAck),
    ("party_key_state", Class::PartyKeyState),
    ("party_recovered", Class::PartyRecovered),
    ("account_status", Class::AccountStatus),
    ("party_compromise", Class::PartyCompromise),
    ("party_terminated", Class::PartyTerminated),
    ("party_identity_break", Class::PartyIdentityBreak),
    ("controller_of", Class::ControllerOf),
    ("operated_by", Class::OperatedBy),
    ("sponsored_by", Class::SponsoredBy),
    ("agent_kind", Class::AgentKind),
    ("org_member", Class::OrgMember),
    ("attestation_runtime", Class::AttestationRuntime),
    ("effect_attestation", Class::EffectAttestation),
    ("executor_control", Class::ExecutorControl),
];

const IDENTITY_BINDING: &str = "identity_binding_";

/// The `account_status` values (TN-49); `suspended`, `deactivated` and `tombstone` narrow
/// (§5.6, §12.3.1).
pub const ACCOUNT_STATUSES: [&str; 5] =
    ["active", "locked", "suspended", "deactivated", "tombstone"];

impl Class {
    /// The class of a wire name; `None` for a class outside this table.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        if let Some(kind) = name.strip_prefix(IDENTITY_BINDING) {
            return BINDING_KINDS
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, b)| Self::IdentityBinding(*b));
        }
        SIMPLE.iter().find(|(k, _)| *k == name).map(|(_, c)| *c)
    }

    /// The wire name.
    #[must_use]
    pub fn name(self) -> String {
        if let Self::IdentityBinding(kind) = self {
            let k = BINDING_KINDS
                .iter()
                .find(|(_, b)| *b == kind)
                .map_or("", |(k, _)| k);
            let mut s = String::from(IDENTITY_BINDING);
            s.push_str(k);
            return s;
        }
        String::from(
            SIMPLE
                .iter()
                .find(|(_, c)| *c == self)
                .map_or("", |(k, _)| k),
        )
    }

    /// Whether the class carries a body, its digest in `value`.
    #[must_use]
    pub const fn has_body(self) -> bool {
        matches!(
            self,
            Self::Authentication
                | Self::AuthenticatorBinding
                | Self::PostureDevice
                | Self::VerifierProfile
                | Self::OfflineExerciseReport
                | Self::AuthorityStateAck
                | Self::PartyKeyState
                | Self::PartyRecovered
                | Self::IdentityBinding(_)
                | Self::EffectAttestation
                | Self::ExecutorControl
        )
    }
}

/// How an authentication was made (§10.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthMethod {
    /// A WebAuthn assertion of the realm's RP.
    Webauthn,
    /// A password.
    Password,
    /// A TOTP code.
    Totp,
    /// An app-bound device key.
    DeviceKey,
    /// An upstream OpenID provider.
    Oidc,
    /// An upstream SAML provider.
    Saml,
    /// An LDAP bind at the edge.
    LdapBind,
    /// Kerberos at the edge.
    Kerberos,
    /// An X.509 client certificate.
    X509,
}

const METHODS: [(&str, AuthMethod); 9] = [
    ("webauthn", AuthMethod::Webauthn),
    ("password", AuthMethod::Password),
    ("totp", AuthMethod::Totp),
    ("device-key", AuthMethod::DeviceKey),
    ("oidc", AuthMethod::Oidc),
    ("saml", AuthMethod::Saml),
    ("ldap-bind", AuthMethod::LdapBind),
    ("kerberos", AuthMethod::Kerberos),
    ("x509", AuthMethod::X509),
];

/// WebAuthn details of an assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the four WebAuthn flags UP, UV, BE and BS"
)]
pub struct WebauthnDetail {
    /// The authenticator's AAGUID; a hint only.
    pub aaguid: [u8; 16],
    /// The signature counter.
    pub sign_count: u64,
    /// User present.
    pub up: bool,
    /// User verified.
    pub uv: bool,
    /// Backup eligible.
    pub be: bool,
    /// Backed up.
    pub bs: bool,
}

/// What an upstream provider said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    /// The verified `iss` (RFC 9207).
    pub iss: String,
    /// `acr`, as declared.
    pub acr: Option<String>,
    /// `amr`, as declared.
    pub amr: Vec<String>,
}

/// Body of an `authentication` Claim (§10.1.5). Binding and assurance are the Claim's own
/// `bound_instance`, `bound_intent` and `assurance`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication {
    /// The method.
    pub method: AuthMethod,
    /// When the user authenticated.
    pub auth_time: u64,
    /// H(AAS) the challenge committed to (§9.14.1).
    pub statement: Option<Digest>,
    /// Digest of the raw assertion.
    pub evidence: Option<Digest>,
    /// WebAuthn details.
    pub webauthn: Option<WebauthnDetail>,
    /// Upstream details.
    pub upstream: Option<Upstream>,
}

/// Kinds of authenticator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthenticatorKind {
    /// A passkey.
    Passkey,
    /// An app-bound device key.
    DeviceKey,
    /// A password.
    Password,
    /// A TOTP secret.
    Totp,
    /// A client certificate.
    X509,
}

const AUTHENTICATOR_KINDS: [(&str, AuthenticatorKind); 5] = [
    ("passkey", AuthenticatorKind::Passkey),
    ("device-key", AuthenticatorKind::DeviceKey),
    ("password", AuthenticatorKind::Password),
    ("totp", AuthenticatorKind::Totp),
    ("x509", AuthenticatorKind::X509),
];

/// The attestation verdict, a signal only (IDI-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttestationResult {
    /// The statement verified to a known root.
    Verified,
    /// Self attestation.
    SelfAttested,
    /// No attestation.
    None,
    /// The statement did not verify.
    Failed,
}

const ATTESTATION_RESULTS: [(&str, AttestationResult); 4] = [
    ("verified", AttestationResult::Verified),
    ("self", AttestationResult::SelfAttested),
    ("none", AttestationResult::None),
    ("failed", AttestationResult::Failed),
];

/// Body of an `authenticator_binding` Claim (§10.1.3, IDP-2): public material only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatorBinding {
    /// The kind.
    pub kind: AuthenticatorKind,
    /// Digest of the public material.
    pub material: Digest,
    /// COSE algorithm of the key.
    pub alg: Option<i64>,
    /// Attestation format and verdict.
    pub attestation: Option<(String, AttestationResult)>,
    /// The AAGUID.
    pub aaguid: Option<[u8; 16]>,
    /// Backup eligible.
    pub be: bool,
    /// Transports, sorted.
    pub transports: BTreeSet<String>,
}

/// A device posture verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// Compliant.
    Compliant,
    /// Not compliant.
    Noncompliant,
    /// Not known.
    Unknown,
}

const VERDICTS: [(&str, Verdict); 3] = [
    ("compliant", Verdict::Compliant),
    ("noncompliant", Verdict::Noncompliant),
    ("unknown", Verdict::Unknown),
];

/// Body of a `posture_device` Claim (§5.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevicePosture {
    /// The verdict.
    pub verdict: Verdict,
    /// Who observed it.
    pub source: String,
    /// When.
    pub observed_at: u64,
    /// The nonce it is bound to.
    pub nonce: Option<Digest>,
    /// Digest of the evidence.
    pub evidence: Option<Digest>,
}

/// Who a verifier is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifierId {
    /// An Instance.
    Instance(Id),
    /// A workload identifier.
    Workload(String),
}

/// Body of a `verifier_profile` Claim (§9.12.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierProfile {
    /// The verifier.
    pub verifier: VerifierId,
    /// Implemented variants with their parameter ceilings.
    pub profiles: BTreeMap<ProfileVariant, BTreeMap<String, u64>>,
    /// Supported versions.
    pub versions: SpecVersions,
    /// Clock source class.
    pub clock_source: String,
    /// Clock skew in milliseconds.
    pub clock_skew_ms: u64,
    /// Holds a tamper-evident counter.
    pub tamper_evident_counter: bool,
    /// Sends Offline Exercise Reports.
    pub offline_report: bool,
    /// Checks content positions (§9.10.1 step 8).
    pub content_position_check: bool,
    /// Status sources it reaches.
    pub status_access: BTreeSet<String>,
    /// Epoch and status refresh interval.
    pub refresh_interval_ms: Option<u64>,
    /// Attestation evidence.
    pub attestation: Option<Digest>,
    /// Local horizon ceilings by variant and CT.
    pub cap_horizon: BTreeMap<ProfileVariant, BTreeMap<u8, u64>>,
    /// Local slice ceilings by unit.
    pub slice_max: BTreeMap<String, i64>,
    /// Conformance declarations.
    pub conformance: BTreeSet<String>,
}

impl VerifierProfile {
    /// `cap_horizon(variant, CT)` (§9.10.1 step 2, U25): the declared ceiling, if any.
    #[must_use]
    pub fn cap_horizon(&self, variant: ProfileVariant, ct: u8) -> Option<u64> {
        self.cap_horizon.get(&variant)?.get(&ct).copied()
    }

    /// Whether the profile covers a contract of `variant` with these parameters: the variant is
    /// implemented and every parameter is within its declared ceiling (PI-12, §9.12.1).
    #[must_use]
    pub fn covers(&self, variant: ProfileVariant, params: &BTreeMap<String, u64>) -> bool {
        self.profiles.get(&variant).is_some_and(|ceilings| {
            params
                .iter()
                .all(|(k, v)| ceilings.get(k).is_some_and(|c| v <= c))
        })
    }
}

/// What an authority-state acknowledgement is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AckEvent {
    /// An Exercise.
    Exercise(Digest),
    /// A semantic event id (§9.16).
    Event(String),
}

/// What the PEP updated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AckScope {
    /// A decision cache.
    Cache,
    /// Pending decisions.
    Decision,
    /// Sessions.
    Session,
    /// Tokens.
    Token,
}

const ACK_SCOPES: [(&str, AckScope); 4] = [
    ("cache", AckScope::Cache),
    ("decision", AckScope::Decision),
    ("session", AckScope::Session),
    ("token", AckScope::Token),
];

/// Body of an `authority_state_ack` Claim (§9.12.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityStateAck {
    /// The PEP.
    pub pep: String,
    /// The event applied.
    pub event: AckEvent,
    /// PEP-local time it was applied.
    pub applied_at: u64,
    /// Clock evidence.
    pub clock_evidence: Option<Digest>,
    /// The basis position applied.
    pub basis: u64,
    /// What was updated.
    pub scope: BTreeSet<AckScope>,
}

/// Body of a `party_key_state` Claim (§10.1.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyKeyState {
    /// Key-event sequence number.
    pub sequence: u64,
    /// Digests of the keys.
    pub keys: BTreeSet<Digest>,
    /// Designated issuers per class (§9.13.1).
    pub designated: BTreeMap<String, BTreeSet<Id>>,
}

/// Body of a `party_recovered` Claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartyRecovered {
    /// Digest of the key-state before.
    pub previous: Digest,
    /// Digest of the key-state after.
    pub next: Digest,
}

/// Body of an `identity_binding_<kind>` Claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBinding {
    /// Digest of the evidence.
    pub evidence: Digest,
    /// For `identity_binding_workload`: the verified workload and the key it presented
    /// (OP-154 m.3 (d)); absent for every other kind.
    pub workload: Option<Workload>,
}

/// The workload an `identity_binding_workload` Claim binds (OP-154 m.3 (d), §11.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workload {
    /// The workload URI (`spiffe://…`, `wimse://…` or a cloud workload subject), at most 2048
    /// bytes.
    pub uri: String,
    /// RFC 7638 thumbprint of the DPoP key the workload presented.
    pub thumbprint: [u8; 32],
}

/// What an executor reports an effect came to (E64 (1)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectOutcome {
    /// It happened, with at least one kind of evidence.
    Done,
    /// It did not happen.
    NotDone,
    /// It could not be verified (E62 (3)).
    Unknown,
}

const EFFECT_OUTCOMES: [(&str, EffectOutcome); 3] = [
    ("done", EffectOutcome::Done),
    ("not-done", EffectOutcome::NotDone),
    ("unknown", EffectOutcome::Unknown),
];

/// The closed list of evidence kinds, strongest first (E64 (2)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceKind {
    /// The upstream API's structured answer: an order number, a transaction id.
    UpstreamConfirmation,
    /// A separate later read: an account page, a confirmation mail, an API query.
    IndependentRecheck,
    /// Only a page observation.
    BrowserObservation,
}

const EVIDENCE_KINDS: [(&str, EvidenceKind); 3] = [
    ("upstream-confirmation", EvidenceKind::UpstreamConfirmation),
    ("independent-recheck", EvidenceKind::IndependentRecheck),
    ("browser-observation", EvidenceKind::BrowserObservation),
];

/// One evidence reference: the digest of a body that never enters Access, and an opaque
/// reference to it (E64 (3)).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceRef {
    /// Digest of the evidence body.
    pub digest: Digest,
    /// Opaque reference, at most 2048 bytes.
    pub reference: Option<String>,
}

/// Body of an `effect_attestation` Claim (E64): a Claim, never truth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectAttestation {
    /// The Exercise the effect belongs to.
    pub exercise: Digest,
    /// Its step.
    pub step: Digest,
    /// The idempotency key, `H(ExerciseID ‖ StepRef)` (E62 (2)).
    pub idempotency_key: Digest,
    /// The action.
    pub action: crate::model::ActionRef,
    /// Digest of the typed parameters actually applied.
    pub params: Digest,
    /// What it came to.
    pub outcome: EffectOutcome,
    /// The evidence kinds; `done` names at least one.
    pub evidence: BTreeSet<EvidenceKind>,
    /// The evidence references.
    pub refs: BTreeSet<EvidenceRef>,
    /// When, trusted milliseconds.
    pub at: u64,
    /// The executor Instance.
    pub executor: Id,
    /// Digest of the execution environment's measurement (E61), when it has one.
    pub environment: Option<Digest>,
}

/// What an executor confirms about an Exercise's job (U5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlState {
    /// Paused: no further effect until it resumes under a new decision.
    Paused,
    /// Stopped, confirmed: no further effect.
    StoppedConfirmed,
}

const CONTROL_STATES: [(&str, ControlState); 2] = [
    ("paused", ControlState::Paused),
    ("stopped_confirmed", ControlState::StoppedConfirmed),
];

/// Body of an `executor_control` Claim (U5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorControl {
    /// The state.
    pub state: ControlState,
    /// The Exercise whose job it is.
    pub exercise: Digest,
    /// When, trusted milliseconds.
    pub at: u64,
}

/// A decoded Claim body.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Body {
    /// `authentication`.
    Authentication(Authentication),
    /// `authenticator_binding`.
    AuthenticatorBinding(AuthenticatorBinding),
    /// `posture_device`.
    DevicePosture(DevicePosture),
    /// `verifier_profile`.
    VerifierProfile(VerifierProfile),
    /// `offline_exercise_report`.
    OfflineReport(Report),
    /// `authority_state_ack`.
    AuthorityStateAck(AuthorityStateAck),
    /// `party_key_state`.
    PartyKeyState(PartyKeyState),
    /// `party_recovered`.
    PartyRecovered(PartyRecovered),
    /// `identity_binding_<kind>`.
    IdentityBinding(IdentityBinding),
    /// `effect_attestation`.
    EffectAttestation(EffectAttestation),
    /// `executor_control`.
    ExecutorControl(ExecutorControl),
}

/// Why a Claim's value or body is refused (L2-CLB-2, L2-CLB-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BodyError {
    /// The value does not have the class's shape.
    #[error("claim-value")]
    Value,
    /// The body does not decode as the class's body.
    #[error("claim-body: {0}")]
    Body(ModelError),
    /// The body's digest is not the value.
    #[error("claim-body-digest")]
    Digest,
}

impl BodyError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Value => "claim-value",
            Self::Body(_) => "claim-body",
            Self::Digest => "claim-body-digest",
        }
    }
}

fn flag(f: &mut Fields<'_>, key: &str) -> Result<bool, ModelError> {
    match f.opt(key) {
        None => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(_) => Err(ModelError::Range),
    }
}

fn flag_value(b: bool) -> Option<Value> {
    b.then_some(Value::Bool(true))
}

fn digest(v: &Value) -> Result<Digest, ModelError> {
    Digest::from_value(v).ok_or(ModelError::Shape)
}

fn opt_digest(f: &mut Fields<'_>, key: &str) -> Result<Option<Digest>, ModelError> {
    f.opt(key).map(digest).transpose()
}

fn sized_text(v: &Value, max: usize) -> Result<String, ModelError> {
    let t = text(v)?;
    if (1..=max).contains(&t.len()) {
        Ok(String::from(t))
    } else {
        Err(ModelError::Range)
    }
}

fn bytes16(v: &Value) -> Result<[u8; 16], ModelError> {
    match v {
        Value::Bytes(b) => <[u8; 16]>::try_from(b.as_slice()).map_err(|_| ModelError::Range),
        _ => Err(ModelError::Shape),
    }
}

fn texts(s: &BTreeSet<String>) -> Option<Value> {
    (!s.is_empty()).then(|| set_value(s.iter().map(|t| Value::text(t))))
}

fn read_texts(f: &mut Fields<'_>, key: &str, max: usize) -> Result<BTreeSet<String>, ModelError> {
    f.opt(key)
        .map(|v| set_of(v, true, |t| sized_text(t, max)))
        .transpose()
        .map(Option::unwrap_or_default)
}

impl Canonical for Authentication {
    fn to_value(&self) -> Value {
        let webauthn = self.webauthn.map(|w| {
            map([
                ("aaguid", Some(Value::Bytes(w.aaguid.to_vec()))),
                ("sign_count", Some(Value::Unsigned(w.sign_count))),
                ("up", flag_value(w.up)),
                ("uv", flag_value(w.uv)),
                ("be", flag_value(w.be)),
                ("bs", flag_value(w.bs)),
            ])
        });
        let upstream = self.upstream.as_ref().map(|u| {
            map([
                ("iss", Some(Value::text(&u.iss))),
                ("acr", u.acr.as_ref().map(|a| Value::text(a))),
                (
                    "amr",
                    (!u.amr.is_empty())
                        .then(|| Value::Array(u.amr.iter().map(|a| Value::text(a)).collect())),
                ),
            ])
        });
        map([
            ("method", Some(word_of(self.method, &METHODS))),
            ("auth_time", Some(Value::Unsigned(self.auth_time))),
            (
                "statement",
                self.statement.as_ref().map(Canonical::to_value),
            ),
            ("evidence", self.evidence.as_ref().map(Canonical::to_value)),
            ("webauthn", webauthn),
            ("upstream", upstream),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let webauthn = match f.opt("webauthn") {
            None => None,
            Some(w) => {
                let mut wf = Fields::of(w)?;
                let d = WebauthnDetail {
                    aaguid: bytes16(wf.req("aaguid")?)?,
                    sign_count: uint(wf.req("sign_count")?)?,
                    up: flag(&mut wf, "up")?,
                    uv: flag(&mut wf, "uv")?,
                    be: flag(&mut wf, "be")?,
                    bs: flag(&mut wf, "bs")?,
                };
                wf.done()?;
                Some(d)
            }
        };
        let upstream = match f.opt("upstream") {
            None => None,
            Some(u) => {
                let mut uf = Fields::of(u)?;
                let up = Upstream {
                    iss: sized_text(uf.req("iss")?, 2048)?,
                    acr: uf.opt("acr").map(text).transpose()?.map(String::from),
                    amr: match uf.opt("amr") {
                        None => Vec::new(),
                        Some(Value::Array(items)) if !items.is_empty() => items
                            .iter()
                            .map(|a| text(a).map(String::from))
                            .collect::<Result<_, _>>()?,
                        Some(_) => return Err(ModelError::Range),
                    },
                };
                uf.done()?;
                Some(up)
            }
        };
        let a = Self {
            method: word(f.req("method")?, &METHODS)?,
            auth_time: uint(f.req("auth_time")?)?,
            statement: opt_digest(&mut f, "statement")?,
            evidence: opt_digest(&mut f, "evidence")?,
            webauthn,
            upstream,
        };
        f.done()?;
        Ok(a)
    }
}

impl Canonical for AuthenticatorBinding {
    fn to_value(&self) -> Value {
        map([
            ("kind", Some(word_of(self.kind, &AUTHENTICATOR_KINDS))),
            ("material", Some(self.material.to_value())),
            ("alg", self.alg.map(Value::int)),
            (
                "attestation",
                self.attestation.as_ref().map(|(format, result)| {
                    map([
                        ("format", Some(Value::text(format))),
                        ("result", Some(word_of(*result, &ATTESTATION_RESULTS))),
                    ])
                }),
            ),
            ("aaguid", self.aaguid.map(|a| Value::Bytes(a.to_vec()))),
            ("be", flag_value(self.be)),
            ("transports", texts(&self.transports)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let attestation = match f.opt("attestation") {
            None => None,
            Some(a) => {
                let mut af = Fields::of(a)?;
                let out = (
                    sized_text(af.req("format")?, 64)?,
                    word(af.req("result")?, &ATTESTATION_RESULTS)?,
                );
                af.done()?;
                Some(out)
            }
        };
        let b = Self {
            kind: word(f.req("kind")?, &AUTHENTICATOR_KINDS)?,
            material: digest(f.req("material")?)?,
            alg: f.opt("alg").map(int).transpose()?,
            attestation,
            aaguid: f.opt("aaguid").map(bytes16).transpose()?,
            be: flag(&mut f, "be")?,
            transports: read_texts(&mut f, "transports", 32)?,
        };
        f.done()?;
        Ok(b)
    }
}

impl Canonical for DevicePosture {
    fn to_value(&self) -> Value {
        map([
            ("verdict", Some(word_of(self.verdict, &VERDICTS))),
            ("source", Some(Value::text(&self.source))),
            ("observed_at", Some(Value::Unsigned(self.observed_at))),
            ("nonce", self.nonce.as_ref().map(Canonical::to_value)),
            ("evidence", self.evidence.as_ref().map(Canonical::to_value)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let p = Self {
            verdict: word(f.req("verdict")?, &VERDICTS)?,
            source: sized_text(f.req("source")?, 255)?,
            observed_at: uint(f.req("observed_at")?)?,
            nonce: opt_digest(&mut f, "nonce")?,
            evidence: opt_digest(&mut f, "evidence")?,
        };
        f.done()?;
        Ok(p)
    }
}

fn variant_key(k: &str) -> Result<ProfileVariant, ModelError> {
    VARIANTS
        .iter()
        .find(|(name, _)| *name == k)
        .map(|(_, v)| *v)
        .ok_or(ModelError::Unknown)
}

fn uint_map(v: &Value) -> Result<BTreeMap<String, u64>, ModelError> {
    let mut f = Fields::of(v)?;
    if f.is_empty() {
        return Err(ModelError::Range);
    }
    let out = f
        .drain(|k, x| Ok((ident(&Value::text(k))?, uint(x)?)))?
        .into_iter()
        .collect();
    f.done()?;
    Ok(out)
}

fn uint_map_value(m: &BTreeMap<String, u64>) -> Value {
    Value::Map(
        m.iter()
            .map(|(k, n)| (Value::text(k), Value::Unsigned(*n)))
            .collect(),
    )
}

impl Canonical for VerifierProfile {
    fn to_value(&self) -> Value {
        let verifier = match &self.verifier {
            VerifierId::Instance(i) => map([("instance", Some(i.to_value()))]),
            VerifierId::Workload(w) => map([("workload", Some(Value::text(w)))]),
        };
        let profiles = Value::Map(
            self.profiles
                .iter()
                .map(|(variant, params)| {
                    (
                        word_of(*variant, &VARIANTS),
                        map([(
                            "params",
                            (!params.is_empty()).then(|| uint_map_value(params)),
                        )]),
                    )
                })
                .collect(),
        );
        let cap_horizon = (!self.cap_horizon.is_empty()).then(|| {
            Value::Map(
                self.cap_horizon
                    .iter()
                    .map(|(variant, caps)| {
                        (
                            word_of(*variant, &VARIANTS),
                            Value::Map(
                                caps.iter()
                                    .map(|(ct, ms)| (ct_key(*ct), Value::Unsigned(*ms)))
                                    .collect(),
                            ),
                        )
                    })
                    .collect(),
            )
        });
        map([
            ("verifier", Some(verifier)),
            ("profiles", Some(profiles)),
            ("versions", Some(self.versions.to_value())),
            (
                "clock",
                Some(map([
                    ("source_class", Some(Value::text(&self.clock_source))),
                    ("skew_ms", Some(Value::Unsigned(self.clock_skew_ms))),
                ])),
            ),
            (
                "tamper_evident_counter",
                flag_value(self.tamper_evident_counter),
            ),
            ("offline_report", flag_value(self.offline_report)),
            (
                "content_position_check",
                flag_value(self.content_position_check),
            ),
            ("status_access", texts(&self.status_access)),
            (
                "refresh_interval_ms",
                self.refresh_interval_ms.map(Value::Unsigned),
            ),
            (
                "attestation",
                self.attestation.as_ref().map(Canonical::to_value),
            ),
            ("cap_horizon", cap_horizon),
            (
                "slice_max",
                (!self.slice_max.is_empty()).then(|| {
                    Value::Map(
                        self.slice_max
                            .iter()
                            .map(|(k, n)| (Value::text(k), Value::int(*n)))
                            .collect(),
                    )
                }),
            ),
            ("conformance", texts(&self.conformance)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let mut vf = Fields::of(f.req("verifier")?)?;
        let verifier = match (vf.opt("instance"), vf.opt("workload")) {
            (Some(i), None) => VerifierId::Instance(Id::from_value(i)?),
            (None, Some(w)) => VerifierId::Workload(sized_text(w, 255)?),
            _ => return Err(ModelError::Shape),
        };
        vf.done()?;
        let mut pf = Fields::of(f.req("profiles")?)?;
        if pf.is_empty() {
            return Err(ModelError::Range);
        }
        let profiles = pf
            .drain(|k, x| {
                let mut xf = Fields::of(x)?;
                let params = xf.opt("params").map(uint_map).transpose()?;
                xf.done()?;
                Ok((variant_key(k)?, params.unwrap_or_default()))
            })?
            .into_iter()
            .collect();
        pf.done()?;
        let mut clock = Fields::of(f.req("clock")?)?;
        let clock_source = ident(clock.req("source_class")?)?;
        let clock_skew_ms = uint(clock.req("skew_ms")?)?;
        clock.done()?;
        let cap_horizon = match f.opt("cap_horizon") {
            None => BTreeMap::new(),
            Some(c) => {
                let mut cf = Fields::of(c)?;
                if cf.is_empty() {
                    return Err(ModelError::Range);
                }
                let out = cf
                    .drain(|k, caps| Ok((variant_key(k)?, horizon_caps(caps)?)))?
                    .into_iter()
                    .collect();
                cf.done()?;
                out
            }
        };
        let slice_max = match f.opt("slice_max") {
            None => BTreeMap::new(),
            Some(s) => {
                let mut sf = Fields::of(s)?;
                if sf.is_empty() {
                    return Err(ModelError::Range);
                }
                let out = sf
                    .drain(|k, n| Ok((crate::codec::unit(&Value::text(k))?, int(n)?)))?
                    .into_iter()
                    .collect();
                sf.done()?;
                out
            }
        };
        let p = Self {
            verifier,
            profiles,
            versions: SpecVersions::from_value(f.req("versions")?)?,
            clock_source,
            clock_skew_ms,
            tamper_evident_counter: flag(&mut f, "tamper_evident_counter")?,
            offline_report: flag(&mut f, "offline_report")?,
            content_position_check: flag(&mut f, "content_position_check")?,
            status_access: f
                .opt("status_access")
                .map(|v| set_of(v, true, |t| text(t).map(String::from)))
                .transpose()?
                .unwrap_or_default(),
            refresh_interval_ms: f.opt("refresh_interval_ms").map(uint).transpose()?,
            attestation: opt_digest(&mut f, "attestation")?,
            cap_horizon,
            slice_max,
            conformance: read_texts(&mut f, "conformance", 255)?,
        };
        f.done()?;
        Ok(p)
    }
}

impl Canonical for AuthorityStateAck {
    fn to_value(&self) -> Value {
        let event = match &self.event {
            AckEvent::Exercise(d) => map([("exercise", Some(d.to_value()))]),
            AckEvent::Event(e) => map([("event", Some(Value::text(e)))]),
        };
        map([
            ("pep", Some(Value::text(&self.pep))),
            ("event", Some(event)),
            ("applied_at", Some(Value::Unsigned(self.applied_at))),
            (
                "clock_evidence",
                self.clock_evidence.as_ref().map(Canonical::to_value),
            ),
            ("basis", Some(Value::Unsigned(self.basis))),
            (
                "scope",
                Some(set_value(
                    self.scope.iter().map(|s| word_of(*s, &ACK_SCOPES)),
                )),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let mut ef = Fields::of(f.req("event")?)?;
        let event = match (ef.opt("exercise"), ef.opt("event")) {
            (Some(d), None) => AckEvent::Exercise(digest(d)?),
            (None, Some(e)) => AckEvent::Event(sized_text(e, 255)?),
            _ => return Err(ModelError::Shape),
        };
        ef.done()?;
        let a = Self {
            pep: sized_text(f.req("pep")?, 255)?,
            event,
            applied_at: uint(f.req("applied_at")?)?,
            clock_evidence: opt_digest(&mut f, "clock_evidence")?,
            basis: uint(f.req("basis")?)?,
            scope: set_of(f.req("scope")?, true, |s| word(s, &ACK_SCOPES))?,
        };
        f.done()?;
        Ok(a)
    }
}

impl Canonical for PartyKeyState {
    fn to_value(&self) -> Value {
        map([
            ("sequence", Some(Value::Unsigned(self.sequence))),
            (
                "keys",
                Some(set_value(self.keys.iter().map(Canonical::to_value))),
            ),
            (
                "designated",
                (!self.designated.is_empty()).then(|| {
                    Value::Map(
                        self.designated
                            .iter()
                            .map(|(class, issuers)| {
                                (
                                    Value::text(class),
                                    set_value(issuers.iter().map(Canonical::to_value)),
                                )
                            })
                            .collect(),
                    )
                }),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let designated = match f.opt("designated") {
            None => BTreeMap::new(),
            Some(d) => {
                let mut df = Fields::of(d)?;
                if df.is_empty() {
                    return Err(ModelError::Range);
                }
                let out = df
                    .drain(|k, issuers| {
                        Ok((
                            ident(&Value::text(k))?,
                            set_of(issuers, true, Id::from_value)?,
                        ))
                    })?
                    .into_iter()
                    .collect();
                df.done()?;
                out
            }
        };
        let s = Self {
            sequence: uint(f.req("sequence")?)?,
            keys: set_of(f.req("keys")?, true, digest)?,
            designated,
        };
        f.done()?;
        Ok(s)
    }
}

impl Canonical for PartyRecovered {
    fn to_value(&self) -> Value {
        map([
            ("previous", Some(self.previous.to_value())),
            ("next", Some(self.next.to_value())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let r = Self {
            previous: digest(f.req("previous")?)?,
            next: digest(f.req("next")?)?,
        };
        f.done()?;
        Ok(r)
    }
}

impl Canonical for IdentityBinding {
    fn to_value(&self) -> Value {
        map([
            ("evidence", Some(self.evidence.to_value())),
            (
                "workload",
                self.workload.as_ref().map(|w| {
                    map([
                        ("uri", Some(Value::text(&w.uri))),
                        ("thumbprint", Some(Value::Bytes(w.thumbprint.to_vec()))),
                    ])
                }),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let workload = match f.opt("workload") {
            None => None,
            Some(w) => {
                let mut wf = Fields::of(w)?;
                let out = Workload {
                    uri: sized_text(wf.req("uri")?, 2048)?,
                    thumbprint: bytes32(wf.req("thumbprint")?)?,
                };
                wf.done()?;
                Some(out)
            }
        };
        let b = Self {
            evidence: digest(f.req("evidence")?)?,
            workload,
        };
        f.done()?;
        Ok(b)
    }
}

fn bytes32(v: &Value) -> Result<[u8; 32], ModelError> {
    match v {
        Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| ModelError::Range),
        _ => Err(ModelError::Shape),
    }
}

impl Canonical for EvidenceRef {
    fn to_value(&self) -> Value {
        map([
            ("digest", Some(self.digest.to_value())),
            ("ref", self.reference.as_ref().map(|r| Value::text(r))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let r = Self {
            digest: digest(f.req("digest")?)?,
            reference: f.opt("ref").map(|r| sized_text(r, 2048)).transpose()?,
        };
        f.done()?;
        Ok(r)
    }
}

impl Canonical for EffectAttestation {
    fn to_value(&self) -> Value {
        map([
            ("exercise", Some(self.exercise.to_value())),
            ("step", Some(self.step.to_value())),
            ("idempotency_key", Some(self.idempotency_key.to_value())),
            ("action", Some(self.action.to_value())),
            ("params", Some(self.params.to_value())),
            ("outcome", Some(word_of(self.outcome, &EFFECT_OUTCOMES))),
            (
                "evidence",
                (!self.evidence.is_empty())
                    .then(|| set_value(self.evidence.iter().map(|e| word_of(*e, &EVIDENCE_KINDS)))),
            ),
            (
                "refs",
                (!self.refs.is_empty())
                    .then(|| set_value(self.refs.iter().map(Canonical::to_value))),
            ),
            ("at", Some(Value::Unsigned(self.at))),
            ("executor", Some(self.executor.to_value())),
            (
                "environment",
                self.environment.as_ref().map(Canonical::to_value),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let a = Self {
            exercise: digest(f.req("exercise")?)?,
            step: digest(f.req("step")?)?,
            idempotency_key: digest(f.req("idempotency_key")?)?,
            action: crate::model::ActionRef::from_value(f.req("action")?)?,
            params: digest(f.req("params")?)?,
            outcome: word(f.req("outcome")?, &EFFECT_OUTCOMES)?,
            evidence: f
                .opt("evidence")
                .map(|e| set_of(e, true, |w| word(w, &EVIDENCE_KINDS)))
                .transpose()?
                .unwrap_or_default(),
            refs: f
                .opt("refs")
                .map(|r| set_of(r, true, EvidenceRef::from_value))
                .transpose()?
                .unwrap_or_default(),
            at: uint(f.req("at")?)?,
            executor: Id::from_value(f.req("executor")?)?,
            environment: opt_digest(&mut f, "environment")?,
        };
        f.done()?;
        // E64 (2)
        if a.outcome == EffectOutcome::Done && a.evidence.is_empty() {
            return Err(ModelError::Range);
        }
        Ok(a)
    }
}

impl Canonical for ExecutorControl {
    fn to_value(&self) -> Value {
        map([
            ("state", Some(word_of(self.state, &CONTROL_STATES))),
            ("exercise", Some(self.exercise.to_value())),
            ("at", Some(Value::Unsigned(self.at))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let c = Self {
            state: word(f.req("state")?, &CONTROL_STATES)?,
            exercise: digest(f.req("exercise")?)?,
            at: uint(f.req("at")?)?,
        };
        f.done()?;
        Ok(c)
    }
}

impl Body {
    /// The body's CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Authentication(b) => b.to_value(),
            Self::AuthenticatorBinding(b) => b.to_value(),
            Self::DevicePosture(b) => b.to_value(),
            Self::VerifierProfile(b) => b.to_value(),
            Self::OfflineReport(b) => b.to_value(),
            Self::AuthorityStateAck(b) => b.to_value(),
            Self::PartyKeyState(b) => b.to_value(),
            Self::PartyRecovered(b) => b.to_value(),
            Self::IdentityBinding(b) => b.to_value(),
            Self::EffectAttestation(b) => b.to_value(),
            Self::ExecutorControl(b) => b.to_value(),
        }
    }

    /// Reads the body of `class` (L2-CLB-3).
    ///
    /// # Errors
    /// [`ModelError`]; [`ModelError::Range`] for a class without a body.
    pub fn from_value(class: Class, v: &Value) -> Result<Self, ModelError> {
        Ok(match class {
            Class::Authentication => Self::Authentication(Authentication::from_value(v)?),
            Class::AuthenticatorBinding => {
                Self::AuthenticatorBinding(AuthenticatorBinding::from_value(v)?)
            }
            Class::PostureDevice => Self::DevicePosture(DevicePosture::from_value(v)?),
            Class::VerifierProfile => Self::VerifierProfile(VerifierProfile::from_value(v)?),
            Class::OfflineExerciseReport => Self::OfflineReport(Report::from_value(v)?),
            Class::AuthorityStateAck => Self::AuthorityStateAck(AuthorityStateAck::from_value(v)?),
            Class::PartyKeyState => Self::PartyKeyState(PartyKeyState::from_value(v)?),
            Class::PartyRecovered => Self::PartyRecovered(PartyRecovered::from_value(v)?),
            Class::IdentityBinding(kind) => {
                let b = IdentityBinding::from_value(v)?;
                // OP-154 m.3 (d)
                if b.workload.is_some() && kind != BindingKind::Workload {
                    return Err(ModelError::Range);
                }
                Self::IdentityBinding(b)
            }
            Class::EffectAttestation => Self::EffectAttestation(EffectAttestation::from_value(v)?),
            Class::ExecutorControl => Self::ExecutorControl(ExecutorControl::from_value(v)?),
            _ => return Err(ModelError::Range),
        })
    }
}

/// The digest a Claim of `class` carries in `value` for `body` (L2-CLB-1).
///
/// # Errors
/// The body cannot be encoded.
pub fn body_digest(class: Class, body: &Value) -> Result<[u8; 32], dcbor::EncodeError> {
    let bytes = dcbor::encode(
        &Value::Array(alloc::vec![Value::text(&class.name()), body.clone()]),
        Limits::CEILING,
    )?;
    Ok(context_digest(BODY_CONTEXT, &bytes).0)
}

fn scalar_ok(class: Class, value: Option<&EqValue>) -> bool {
    match (class, value) {
        (Class::AccountStatus, Some(EqValue::Text(t))) => ACCOUNT_STATUSES.contains(&t.as_str()),
        (Class::PartyCompromise, None) => true,
        (Class::PartyCompromise | Class::PartyTerminated, Some(EqValue::Int(n))) => *n >= 0,
        (Class::PartyIdentityBreak | Class::AgentKind, Some(EqValue::Text(t))) => {
            ident(&Value::text(t)).is_ok()
        }
        (
            Class::ControllerOf | Class::OperatedBy | Class::SponsoredBy | Class::OrgMember,
            Some(EqValue::Bytes(b)),
        ) => b.len() == 16,
        (Class::AttestationRuntime, Some(EqValue::Bytes(b))) => b.len() == 32,
        _ => false,
    }
}

/// Checks a Claim's `value` against its class and, when the body travels with it, the body
/// against the value (L2-CLB-2, L2-CLB-3). A class outside the table is not checked here.
///
/// # Errors
/// [`BodyError`].
pub fn check(statement: &Statement, body: Option<&[u8]>) -> Result<Option<Body>, BodyError> {
    let Some(class) = Class::parse(&statement.class) else {
        return Ok(None);
    };
    if !class.has_body() {
        return if body.is_none() && scalar_ok(class, statement.value.as_ref()) {
            Ok(None)
        } else {
            Err(BodyError::Value)
        };
    }
    let Some(EqValue::Bytes(expected)) = &statement.value else {
        return Err(BodyError::Value);
    };
    if expected.len() != 32 {
        return Err(BodyError::Value);
    }
    let Some(bytes) = body else {
        return Ok(None);
    };
    let value =
        dcbor::decode(bytes, Limits::CEILING).map_err(|e| BodyError::Body(ModelError::Cbor(e)))?;
    let decoded = Body::from_value(class, &value).map_err(BodyError::Body)?;
    let got = body_digest(class, &value).map_err(|_| BodyError::Body(ModelError::Range))?;
    if got.as_slice() != expected.as_slice() {
        return Err(BodyError::Digest);
    }
    Ok(Some(decoded))
}

#[cfg(test)]
mod tests;
