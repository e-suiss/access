//! The identity plane's own Claims (§10.1.2, §10.1.5, CMP-8, OP-150 L2): what an identity event
//! asks the realm issuer to claim, as a [`ClaimOrder`] queued in the business transaction, and
//! the `claim-statement` and body it becomes. Only the fields of the §10.1.2 mapping enter a
//! Claim; public material, credential ids and identifiers enter as digests, never in clear
//! (K16, E26, §7.9.15.1).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::claim::Statement;
use access_kernel::claim::body::{
    AttestationResult, AuthMethod, Authentication, AuthenticatorBinding, AuthenticatorKind,
    BindingKind, Body, Class, DevicePosture, IdentityBinding, Verdict, WebauthnDetail, body_digest,
};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::model::{EqValue, Id, Window};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::domain::claim_classes::{IdentityClass, RecoveryResult, digest as class_digest};

/// The identity outbox kind prefix of Claim orders.
pub const OUTBOX_PREFIX: &str = "claim.";

/// How long an `authentication` Claim holds: the absolute session lifetime ceiling (PD); its
/// freshness is judged from `auth_time` by the requirement, not from this window.
pub const AUTHENTICATION_TTL_MS: u64 = 12 * 3_600_000;

/// How long a binding Claim holds before it must be issued again (PD).
pub const BINDING_TTL_MS: u64 = 400 * 86_400_000;

/// How long a risk signal or a posture verdict holds (PD).
pub const SIGNAL_TTL_MS: u64 = 86_400_000;

/// The class of the identity plane's risk signals (§7.6 TN-O4, TN-63): a signal for policy, never
/// a gate.
pub const RISK_SIGNAL: &str = "risk_signal";

/// Digest context of an authenticator's public material.
pub const MATERIAL_CONTEXT: &str = "access/authenticator-material/v1";

/// Digest context of a Claim line.
pub const LINE_CONTEXT: &str = "access/claim-line/v1";

/// Digest context of a WebAuthn assertion kept as evidence.
pub const ASSERTION_CONTEXT: &str = "access/webauthn-assertion/v1";

/// Digest context of the proof an identity binding rests on.
pub const BINDING_EVIDENCE_CONTEXT: &str = "access/identity-binding-evidence/v1";

/// What a Claim is bound to, besides its subject (§10.1.5 `binding`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bind {
    /// Nothing.
    None,
    /// A device Instance.
    Instance([u8; 16]),
    /// The device Instance the session registered, if any, resolved when the Claim is issued.
    Session([u8; 16]),
    /// An approved statement, H(AAS), and the approver's device Instance (§9.14.1, §13.7.3): the
    /// Claim meets the approval's binding and an actor-Instance term of the same actor (OP-149
    /// m.33 (c)).
    Statement {
        /// H(AAS).
        statement: [u8; 32],
        /// The approving Instance, the one named in the statement.
        instance: [u8; 16],
    },
}

/// A risk signal of the identity plane (§7.6, §12.3.2 TN-63, §10.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskSignal {
    /// First authentication from a browser without a known device marker.
    NewDevice,
    /// A passkey whose AAGUID no other passkey of the account has.
    AaguidChange,
    /// The signature counter did not advance on a device-bound passkey.
    SignCountRegression,
    /// BS went from 1 to 0.
    BackupStateLost,
    /// BS went from 0 to 1.
    BackupStateGained,
    /// Too many attempts in a window.
    Velocity,
}

impl RiskSignal {
    /// The signal's name, the Claim's value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NewDevice => "new_device",
            Self::AaguidChange => "aaguid_change",
            Self::SignCountRegression => "sign_count_regression",
            Self::BackupStateLost => "backup_state_lost",
            Self::BackupStateGained => "backup_state_gained",
            Self::Velocity => "velocity",
        }
    }
}

/// What the order claims: a value for a scalar class, or a body whose digest is the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// A scalar value.
    Scalar(EqValue),
    /// A body of a class of the identity plane's registry (OP-153 m.2 N0), always sent beside
    /// the Claim; `party` names a subject Party that is no identity subject, such as an
    /// organization (TN-90).
    About {
        /// The class body.
        body: Value,
        /// The subject Party, when it is not the order's subject's Party.
        party: Option<[u8; 16]>,
    },
    /// A body, sent beside the Claim when `disclose`, else the Claim stays digest-valued.
    Body {
        /// The body.
        body: Body,
        /// Whether the body travels with the Claim.
        disclose: bool,
    },
    /// A body of a registry class outside the Kernel table (OP-153 m.2 N0): its digest is the
    /// value, and it always travels with the Claim.
    Registry(Value),
    /// A scalar value about a subject Party that is no identity subject, such as an agent
    /// (OP-154 m.3 (c)).
    PartyScalar {
        /// The value.
        value: EqValue,
        /// The subject Party.
        party: [u8; 16],
    },
    /// A body about a subject Party that is no identity subject, always sent beside the Claim,
    /// such as an agent's workload binding (OP-154 m.3 (d)).
    PartyBody {
        /// The body.
        body: Body,
        /// The subject Party.
        party: [u8; 16],
    },
}

/// A Claim the realm issuer is asked to issue, queued with the event that caused it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimOrder {
    /// The identity subject it is about; its Party is resolved when it is issued.
    pub subject: [u8; 16],
    /// The class.
    pub class: String,
    /// When it starts to hold, Unix milliseconds.
    pub at: u64,
    /// How long it holds.
    pub ttl_ms: u64,
    /// What it claims.
    pub content: Content,
    /// Assurance levels (§10.1.6).
    pub assurance: BTreeMap<String, u64>,
    /// What it is bound to.
    pub bind: Bind,
    /// Its line: the next Claim of the line supersedes it.
    pub line: Option<[u8; 32]>,
    /// The order only ends its line: the Claim holds for no time past `at`.
    pub retract: bool,
}

/// Why an order could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("claim order")]
pub struct BadOrder;

/// The line digest of `parts`.
#[must_use]
pub fn line(parts: &[&[u8]]) -> [u8; 32] {
    let v = Value::Array(parts.iter().map(|p| Value::Bytes(p.to_vec())).collect());
    let bytes = dcbor::encode(&v, Limits::CEILING).unwrap_or_default();
    context_digest(LINE_CONTEXT, &bytes).0
}

/// The digest of an authenticator's public material: its kind, credential id and public key
/// (§10.1.2 "credential ID özeti"; never a secret).
#[must_use]
pub fn material(kind: AuthenticatorKind, credential: &[u8], public_key: &[u8]) -> Digest {
    let v = Value::Array(vec![
        Value::text(kind_name(kind)),
        Value::Bytes(credential.to_vec()),
        Value::Bytes(public_key.to_vec()),
    ]);
    let bytes = dcbor::encode(&v, Limits::CEILING).unwrap_or_default();
    Digest(context_digest(MATERIAL_CONTEXT, &bytes).0)
}

const fn kind_name(k: AuthenticatorKind) -> &'static str {
    match k {
        AuthenticatorKind::Passkey => "passkey",
        AuthenticatorKind::DeviceKey => "device-key",
        AuthenticatorKind::Password => "password",
        AuthenticatorKind::Totp => "totp",
        AuthenticatorKind::X509 => "x509",
    }
}

/// The evidence digest of a WebAuthn assertion as received.
#[must_use]
pub fn assertion_evidence(authenticator_data: &[u8], client_data: &[u8], sig: &[u8]) -> Digest {
    let v = Value::Array(vec![
        Value::Bytes(authenticator_data.to_vec()),
        Value::Bytes(client_data.to_vec()),
        Value::Bytes(sig.to_vec()),
    ]);
    let bytes = dcbor::encode(&v, Limits::CEILING).unwrap_or_default();
    Digest(context_digest(ASSERTION_CONTEXT, &bytes).0)
}

/// The facts of a completed authentication (§10.1.2 WebAuthn row, §10.1.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthFacts {
    /// The subject.
    pub subject: [u8; 16],
    /// The method that carries the authentication.
    pub method: AuthMethod,
    /// When the user authenticated.
    pub auth_time: u64,
    /// The assurance vector as levels.
    pub assurance: BTreeMap<String, u64>,
    /// WebAuthn details, for a passkey.
    pub webauthn: Option<WebauthnDetail>,
    /// Digest of the raw assertion.
    pub evidence: Option<Digest>,
    /// What the authentication is bound to.
    pub bind: Bind,
}

/// The line of a session's `authentication` Claims: a step-up supersedes the login, and the
/// sign-out ends the line (§7.1, §12.0.3, OP-150 L6).
#[must_use]
pub fn authentication_line(session: &[u8; 16]) -> [u8; 32] {
    line(&[b"authentication", session])
}

/// The `authentication` Claim of a login, a step-up or an approval (§10.1.5, F17, TN-103). Bound
/// to an approved statement, the body carries H(AAS) too. Bound to a session, it is in that
/// session's line.
#[must_use]
pub fn authentication(f: AuthFacts) -> ClaimOrder {
    let statement = match f.bind {
        Bind::Statement { statement, .. } => Some(Digest(statement)),
        _ => None,
    };
    let line = match f.bind {
        Bind::Session(s) => Some(authentication_line(&s)),
        _ => None,
    };
    ClaimOrder {
        subject: f.subject,
        class: Class::Authentication.name(),
        at: f.auth_time,
        ttl_ms: AUTHENTICATION_TTL_MS,
        content: Content::Body {
            body: Body::Authentication(Authentication {
                method: f.method,
                auth_time: f.auth_time,
                statement,
                evidence: f.evidence,
                webauthn: f.webauthn,
                upstream: None,
            }),
            disclose: true,
        },
        assurance: f.assurance,
        bind: f.bind,
        line,
        retract: false,
    }
}

/// The order that ends a session's `authentication` line when the session ends (§12.0.3,
/// §7.1 "actor-binding tazeliği", OP-150 L6): its last Claim is superseded by one that holds
/// for no time, so the Instances the session bound meet no freshness term from it. Nothing else
/// is touched: other sessions, Instances and delegations stay (X36).
#[must_use]
pub fn authentication_ended(subject: [u8; 16], session: [u8; 16], at: u64) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: Class::Authentication.name(),
        at,
        ttl_ms: 0,
        content: Content::Scalar(EqValue::Bytes(vec![0; 32])),
        assurance: BTreeMap::new(),
        bind: Bind::Session(session),
        line: Some(authentication_line(&session)),
        retract: true,
    }
}

/// A passkey as registered: public material and attestation signal only (§10.1.2 WebAuthn
/// registration row).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyFacts<'a> {
    /// The subject.
    pub subject: [u8; 16],
    /// The credential id.
    pub credential: &'a [u8],
    /// The identity credential row that stands for it; its line is named by it.
    pub sibling: [u8; 16],
    /// The COSE public key.
    pub public_key: &'a [u8],
    /// Its COSE algorithm.
    pub alg: i64,
    /// Attestation format and verdict.
    pub attestation: Option<(String, AttestationResult)>,
    /// The AAGUID.
    pub aaguid: [u8; 16],
    /// Backup eligible.
    pub be: bool,
    /// Transports.
    pub transports: BTreeSet<String>,
    /// When it was registered.
    pub at: u64,
}

/// The line of an authenticator: one per credential.
#[must_use]
pub fn authenticator_line(kind: AuthenticatorKind, credential: &[u8]) -> [u8; 32] {
    line(&[
        b"authenticator_binding",
        kind_name(kind).as_bytes(),
        credential,
    ])
}

/// The `authenticator_binding` Claim of a new passkey (IDP-2). It binds the authenticator to the
/// Party; it opens and ends no Instance (K04).
#[must_use]
pub fn passkey_binding(p: &PasskeyFacts<'_>) -> ClaimOrder {
    ClaimOrder {
        subject: p.subject,
        class: Class::AuthenticatorBinding.name(),
        at: p.at,
        ttl_ms: BINDING_TTL_MS,
        content: Content::Body {
            body: Body::AuthenticatorBinding(AuthenticatorBinding {
                kind: AuthenticatorKind::Passkey,
                material: material(AuthenticatorKind::Passkey, p.credential, p.public_key),
                alg: Some(p.alg),
                attestation: p.attestation.clone(),
                aaguid: Some(p.aaguid),
                be: p.be,
                transports: p.transports.clone(),
            }),
            disclose: true,
        },
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(authenticator_line(AuthenticatorKind::Passkey, &p.sibling)),
        retract: false,
    }
}

/// The `authenticator_binding` Claim of a device key registered as a device Instance
/// (§10.1.3 "Cihaz anahtarı kaydı"), bound to that Instance.
#[must_use]
pub fn device_key_binding(
    subject: [u8; 16],
    public_key: &[u8],
    alg: i64,
    instance: [u8; 16],
    at: u64,
) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: Class::AuthenticatorBinding.name(),
        at,
        ttl_ms: BINDING_TTL_MS,
        content: Content::Body {
            body: Body::AuthenticatorBinding(AuthenticatorBinding {
                kind: AuthenticatorKind::DeviceKey,
                material: material(AuthenticatorKind::DeviceKey, &instance, public_key),
                alg: Some(alg),
                attestation: None,
                aaguid: None,
                be: false,
                transports: BTreeSet::new(),
            }),
            disclose: true,
        },
        assurance: BTreeMap::new(),
        bind: Bind::Instance(instance),
        line: Some(authenticator_line(AuthenticatorKind::DeviceKey, &instance)),
        retract: false,
    }
}

/// The `authenticator_binding` Claim of a new password or TOTP credential (§10.1.3 "parola
/// değişimi yeni authenticator-binding Claim'idir", OP-150 m.12 (j)): the credential named by
/// digest, never its secret; it binds to the Party and changes no Instance (K04).
#[must_use]
pub fn secret_binding(
    subject: [u8; 16],
    kind: AuthenticatorKind,
    credential: &[u8],
    at: u64,
) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: Class::AuthenticatorBinding.name(),
        at,
        ttl_ms: BINDING_TTL_MS,
        content: Content::Body {
            body: Body::AuthenticatorBinding(AuthenticatorBinding {
                kind,
                material: material(kind, credential, &[]),
                alg: None,
                attestation: None,
                aaguid: None,
                be: false,
                transports: BTreeSet::new(),
            }),
            disclose: true,
        },
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(authenticator_line(kind, credential)),
        retract: false,
    }
}

/// The order that ends an authenticator's line when it is removed: its last Claim is superseded
/// by one that holds for no time. Instances are untouched (IDP-2, K04). `credential` names the
/// line: a passkey's identity credential row, a device key's Instance.
#[must_use]
pub fn authenticator_removed(
    subject: [u8; 16],
    kind: AuthenticatorKind,
    credential: &[u8],
    at: u64,
) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: Class::AuthenticatorBinding.name(),
        at,
        ttl_ms: 0,
        content: Content::Body {
            body: Body::AuthenticatorBinding(AuthenticatorBinding {
                kind,
                material: material(kind, credential, &[]),
                alg: None,
                attestation: None,
                aaguid: None,
                be: false,
                transports: BTreeSet::new(),
            }),
            disclose: true,
        },
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(authenticator_line(kind, credential)),
        retract: true,
    }
}

/// The line of a subject's account status.
#[must_use]
pub fn status_line() -> [u8; 32] {
    line(&[b"account_status"])
}

/// The `account_status` Claim of a status change (TN-49, §12.3.1): the realm issuer's statement
/// the domain overlays; it holds until the next status supersedes it.
#[must_use]
pub fn account_status(subject: [u8; 16], status: &str, at: u64) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: Class::AccountStatus.name(),
        at,
        ttl_ms: u64::MAX,
        content: Content::Scalar(EqValue::Text(String::from(status))),
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(status_line()),
        retract: false,
    }
}

/// The line of a subject's `org_member` Claim of organization `org`.
#[must_use]
pub fn org_member_line(org: &[u8; 16]) -> [u8; 32] {
    line(&[b"org_member", org])
}

/// The `org_member` Claim that `subject` is a member of the organization whose Party is
/// `org_party` (OP-153 m.17 (c), m.25 (a)): the scalar a `Pred` holder selects one
/// organization's members by; it holds for `ttl_ms` from `at` on the organization's line.
#[must_use]
pub fn org_member(
    subject: [u8; 16],
    (org, org_party): ([u8; 16], [u8; 16]),
    (at, ttl_ms): (u64, u64),
) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: Class::OrgMember.name(),
        at,
        ttl_ms,
        content: Content::Scalar(EqValue::Bytes(org_party.to_vec())),
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(org_member_line(&org)),
        retract: false,
    }
}

/// How long an agent's `operated_by`, `agent_kind` and `sponsored_by` Claims hold before the
/// realm issuer renews them (PD, OP-154 m.3 (c)): a year; a retraction ends one at once.
pub const AGENT_CLAIM_TTL_MS: u64 = 365 * 24 * 3_600_000;

/// The line of an agent's Claim of `class` about `about`: the agent's `operated_by` and
/// `agent_kind` have one line each, its `sponsored_by` one per sponsor.
#[must_use]
pub fn agent_line(agent: &[u8; 16], class: Class, about: &[u8]) -> [u8; 32] {
    line(&[class.name().as_bytes(), agent, about])
}

/// A realm issuer Claim of `class` about the agent Party `agent` (OP-154 m.3 (c), AG-20):
/// `operated_by` and `sponsored_by` carry a Party, `agent_kind` its kind. With `retract` it only
/// ends the line, as when the last sponsor leaves (OP-154 m.3 (e)).
#[must_use]
pub fn agent_claim(
    agent: [u8; 16],
    class: Class,
    (value, line_of): (EqValue, &[u8]),
    at: u64,
    retract: bool,
) -> ClaimOrder {
    ClaimOrder {
        subject: agent,
        class: class.name(),
        at,
        ttl_ms: AGENT_CLAIM_TTL_MS,
        line: Some(agent_line(&agent, class, line_of)),
        content: Content::PartyScalar {
            value,
            party: agent,
        },
        assurance: BTreeMap::new(),
        bind: Bind::None,
        retract,
    }
}

/// How long a workload's `identity_binding_workload` Claim holds (PD, OP-154 m.3 (d)): an
/// hour from its presentation; presenting the credential again renews it.
pub const WORKLOAD_BINDING_TTL_MS: u64 = 3_600_000;

/// Digest context of a workload credential's evidence.
pub const WORKLOAD_EVIDENCE_CONTEXT: &str = "access/workload-evidence/v1";

/// The line of `agent`'s workload binding of the key `thumbprint`: one line per key.
#[must_use]
pub fn workload_line(agent: &[u8; 16], thumbprint: &[u8; 32]) -> [u8; 32] {
    line(&[
        Class::IdentityBinding(BindingKind::Workload)
            .name()
            .as_bytes(),
        agent,
        thumbprint,
    ])
}

/// OP-154 m.3 (d), U20, AG-30: the realm issuer's `identity_binding_workload` Claim about the
/// agent Party `agent`: the verified workload URI and the key it presented. The credential
/// enters as a digest only (E26); the body always travels, so the authority plane can match the
/// key of a self-signed `instance_create`.
#[must_use]
pub fn workload_binding(
    agent: [u8; 16],
    workload: access_kernel::claim::body::Workload,
    credential: &[u8],
    at: u64,
) -> ClaimOrder {
    let thumbprint = workload.thumbprint;
    ClaimOrder {
        subject: agent,
        class: Class::IdentityBinding(BindingKind::Workload).name(),
        at,
        ttl_ms: WORKLOAD_BINDING_TTL_MS,
        line: Some(workload_line(&agent, &thumbprint)),
        content: Content::PartyBody {
            body: Body::IdentityBinding(IdentityBinding {
                evidence: Digest(context_digest(WORKLOAD_EVIDENCE_CONTEXT, credential).0),
                workload: Some(workload),
            }),
            party: agent,
        },
        assurance: BTreeMap::new(),
        bind: Bind::None,
        retract: false,
    }
}

/// How long an `attestation_runtime` Claim holds (PD, OP-154 m.3 (s)): a day; the key is
/// attested again after that.
pub const RUNTIME_TTL_MS: u64 = 24 * 3_600_000;

/// §5.9, L21, Ek B 4262: the realm issuer's `attestation_runtime` Claim about `party` for the
/// attested runtime class `runtime`, bound to the Instance `instance` whose key was attested.
#[must_use]
pub fn runtime_attestation(
    party: [u8; 16],
    instance: [u8; 16],
    runtime: [u8; 32],
    at: u64,
) -> ClaimOrder {
    ClaimOrder {
        subject: party,
        class: Class::AttestationRuntime.name(),
        at,
        ttl_ms: RUNTIME_TTL_MS,
        line: Some(line(&[
            Class::AttestationRuntime.name().as_bytes(),
            &party,
            &instance,
        ])),
        content: Content::PartyScalar {
            value: EqValue::Bytes(runtime.to_vec()),
            party,
        },
        assurance: BTreeMap::new(),
        bind: Bind::Instance(instance),
        retract: false,
    }
}

/// The line of a subject's identity binding of `kind`: the next binding supersedes it.
#[must_use]
pub fn binding_line(kind: BindingKind) -> [u8; 32] {
    line(&[Class::IdentityBinding(kind).name().as_bytes()])
}

/// The `identity_binding_<kind>` Claim that binds the subject to its Party (§10.1.3 IDP-2,
/// §10.1.5): the proof the binding rests on enters as a digest only (E26). The Party itself is
/// resolved when the Claim is issued.
#[must_use]
pub fn identity_binding(subject: [u8; 16], kind: BindingKind, proof: &[u8], at: u64) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: Class::IdentityBinding(kind).name(),
        at,
        ttl_ms: BINDING_TTL_MS,
        content: Content::Body {
            body: Body::IdentityBinding(IdentityBinding {
                workload: None,
                evidence: Digest(context_digest(BINDING_EVIDENCE_CONTEXT, proof).0),
            }),
            disclose: true,
        },
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(binding_line(kind)),
        retract: false,
    }
}

/// The `posture_device` Claim of an attestation verdict (§10.1.3: attestation is a signal, a
/// posture Claim, never an Instance or a key binding). Its evidence is a digest; the body stays
/// with the identity plane unless a decision needs it (E26).
#[must_use]
pub fn posture(
    subject: [u8; 16],
    verdict: Verdict,
    source: &str,
    evidence: Option<Digest>,
    bind: Bind,
    at: u64,
) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: Class::PostureDevice.name(),
        at,
        ttl_ms: SIGNAL_TTL_MS,
        content: Content::Body {
            body: Body::DevicePosture(DevicePosture {
                verdict,
                source: String::from(source),
                observed_at: at,
                nonce: None,
                evidence,
            }),
            disclose: false,
        },
        assurance: BTreeMap::new(),
        bind,
        line: None,
        retract: false,
    }
}

/// The posture verdict an attestation result gives: only a verified statement is compliant, a
/// failed one is not, and no statement says nothing.
#[must_use]
pub const fn attestation_verdict(r: AttestationResult) -> Verdict {
    match r {
        AttestationResult::Verified => Verdict::Compliant,
        AttestationResult::Failed => Verdict::Noncompliant,
        AttestationResult::SelfAttested | AttestationResult::None => Verdict::Unknown,
    }
}

/// A `risk_signal` Claim (§7.6 TN-O4): it narrows nothing on its own and gates nothing.
#[must_use]
pub fn risk(subject: [u8; 16], signal: RiskSignal, bind: Bind, at: u64) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: String::from(RISK_SIGNAL),
        at,
        ttl_ms: SIGNAL_TTL_MS,
        content: Content::Scalar(EqValue::Text(String::from(signal.name()))),
        assurance: BTreeMap::new(),
        bind,
        line: None,
        retract: false,
    }
}

/// Where an issued order lands: the domain, the issuer and subject Parties, the Instance the
/// binding resolved to, the Claim it supersedes and the signing time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The realm's governing domain.
    pub domain: Digest,
    /// The realm's issuer Party.
    pub issuer: Id,
    /// The subject's Party.
    pub subject: Id,
    /// The Instance a session binding resolved to.
    pub instance: Option<Id>,
    /// The last Claim of the order's line.
    pub supersedes: Option<Id>,
    /// Signing time.
    pub now: u64,
}

/// A Claim ready to sign: its statement and the body that travels with it, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// What the issuer signs.
    pub statement: Statement,
    /// The disclosed body bytes.
    pub body: Option<Vec<u8>>,
}

/// How long a `recovery_result` Claim holds: the CT3 intent validity ceiling, so a self-signed
/// `instance_recover` forwarded again after the domain's time-lock still finds it (OP-153 m.3
/// (c), §13.7.3).
pub const RECOVERY_RESULT_TTL_MS: u64 = 72 * 3_600_000;

/// The line of an attempt's `recovery_result` Claims: a successor named again supersedes the
/// first (OP-153 m.3 (c)).
#[must_use]
pub fn recovery_result_line(attempt: &[u8; 16]) -> [u8; 32] {
    line(&[b"recovery_result", attempt])
}

/// The `recovery_result` Claim of an attempt at `REBIND_OPEN` (OP-153 m.3 (c), INV-40, §7.7):
/// the successor key that may self-sign `instance_recover`, the path and the AAL it reached.
/// The body travels with the Claim; its `aal` is also the Claim's assurance (§10.1.6).
#[must_use]
pub fn recovery_result(subject: [u8; 16], r: &RecoveryResult, at: u64) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: String::from(IdentityClass::RecoveryResult.name()),
        at,
        ttl_ms: RECOVERY_RESULT_TTL_MS,
        content: Content::Registry(r.to_value()),
        assurance: BTreeMap::from([(String::from("aal"), u64::from(r.achieved_aal))]),
        bind: Bind::None,
        line: Some(recovery_result_line(&r.attempt.0)),
        retract: false,
    }
}

impl ClaimOrder {
    /// The subject Party a registry order names itself, if any.
    #[must_use]
    pub const fn party(&self) -> Option<[u8; 16]> {
        match &self.content {
            Content::About { party, .. } => *party,
            Content::PartyScalar { party, .. } | Content::PartyBody { party, .. } => Some(*party),
            _ => None,
        }
    }

    /// An order of a registry class `class` about `party`, or about `subject`'s Party, holding
    /// for `ttl_ms` from `at` on its own line (OP-153 m.2 N0).
    #[must_use]
    pub fn registry(
        subject: [u8; 16],
        class: crate::domain::claim_classes::IdentityClass,
        body: Value,
        party: Option<[u8; 16]>,
        (at, ttl_ms): (u64, u64),
        line: [u8; 32],
    ) -> Self {
        Self {
            subject,
            class: String::from(class.name()),
            at,
            ttl_ms,
            content: Content::About { body, party },
            assurance: BTreeMap::new(),
            bind: Bind::None,
            line: Some(line),
            retract: false,
        }
    }

    /// The outbox kind.
    #[must_use]
    pub fn kind(&self) -> String {
        format!("{OUTBOX_PREFIX}{}", self.class)
    }

    /// The statement and disclosed body of this order at `p` (L2-CLB-1).
    ///
    /// # Errors
    /// [`BadOrder`] when the body cannot be encoded.
    pub fn prepare(&self, p: &Placement) -> Result<Prepared, BadOrder> {
        let (value, body) = match &self.content {
            Content::Scalar(v) | Content::PartyScalar { value: v, .. } => (Some(v.clone()), None),
            Content::About { body, .. } => {
                let class = crate::domain::claim_classes::IdentityClass::parse(&self.class)
                    .ok_or(BadOrder)?;
                let digest =
                    crate::domain::claim_classes::digest(class, body).map_err(|_| BadOrder)?;
                let bytes = dcbor::encode(body, Limits::CEILING).map_err(|_| BadOrder)?;
                (Some(EqValue::Bytes(digest.to_vec())), Some(bytes))
            }
            Content::PartyBody { body, .. } => {
                let class = Class::parse(&self.class).ok_or(BadOrder)?;
                let v = body.to_value();
                let digest = body_digest(class, &v).map_err(|_| BadOrder)?;
                let bytes = dcbor::encode(&v, Limits::CEILING).map_err(|_| BadOrder)?;
                (Some(EqValue::Bytes(digest.to_vec())), Some(bytes))
            }
            Content::Body { body, disclose } => {
                let class = Class::parse(&self.class).ok_or(BadOrder)?;
                let v = body.to_value();
                let digest = body_digest(class, &v).map_err(|_| BadOrder)?;
                let bytes = dcbor::encode(&v, Limits::CEILING).map_err(|_| BadOrder)?;
                (
                    Some(EqValue::Bytes(digest.to_vec())),
                    disclose.then_some(bytes),
                )
            }
            Content::Registry(v) => {
                let class = IdentityClass::parse(&self.class).ok_or(BadOrder)?;
                let digest = class_digest(class, v).map_err(|_| BadOrder)?;
                let bytes = dcbor::encode(v, Limits::CEILING).map_err(|_| BadOrder)?;
                (Some(EqValue::Bytes(digest.to_vec())), Some(bytes))
            }
        };
        let until = if self.retract {
            self.at
        } else {
            self.at.saturating_add(self.ttl_ms)
        };
        let (bound_instance, bound_intent) = match self.bind {
            Bind::None => (None, None),
            Bind::Instance(i) => (Some(Id(i)), None),
            Bind::Session(_) => (p.instance, None),
            Bind::Statement {
                statement,
                instance,
            } => (Some(Id(instance)), Some(Digest(statement))),
        };
        Ok(Prepared {
            statement: Statement {
                domain: p.domain,
                issuer: p.issuer,
                subject: p.subject,
                class: self.class.clone(),
                value,
                issued_at: p.now,
                validity: Window {
                    from: self.at.min(p.now),
                    until: until.max(self.at.min(p.now)),
                },
                assurance: self.assurance.clone(),
                bound_intent,
                bound_instance,
                bound_resource: None,
                supersedes: p.supersedes,
            },
            body,
        })
    }

    /// The outbox bytes: deterministic CBOR.
    ///
    /// # Errors
    /// [`BadOrder`] when the value is outside the structural limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>, BadOrder> {
        let (content, disclose) = match &self.content {
            Content::Scalar(v) => (
                Value::Array(vec![Value::text("scalar"), v.to_value()]),
                None,
            ),
            Content::About { body, party } => (
                Value::Array(vec![
                    Value::text("about"),
                    body.clone(),
                    Value::Bytes(party.map_or_else(Vec::new, |p| p.to_vec())),
                ]),
                None,
            ),
            Content::Body { body, disclose } => (
                Value::Array(vec![Value::text("body"), body.to_value()]),
                Some(Value::Bool(*disclose)),
            ),
            Content::Registry(v) => (Value::Array(vec![Value::text("registry"), v.clone()]), None),
            Content::PartyScalar { value, party } => (
                Value::Array(vec![
                    Value::text("party_scalar"),
                    value.to_value(),
                    Value::Bytes(party.to_vec()),
                ]),
                None,
            ),
            Content::PartyBody { body, party } => (
                Value::Array(vec![
                    Value::text("party_body"),
                    body.to_value(),
                    Value::Bytes(party.to_vec()),
                ]),
                None,
            ),
        };
        let bind = match self.bind {
            Bind::None => None,
            Bind::Instance(i) => Some(("instance", i.to_vec())),
            Bind::Session(s) => Some(("session", s.to_vec())),
            Bind::Statement {
                statement,
                instance,
            } => Some(("statement", [&statement[..], &instance[..]].concat())),
        };
        let mut entries = vec![
            (Value::text("subject"), Value::Bytes(self.subject.to_vec())),
            (Value::text("class"), Value::text(&self.class)),
            (Value::text("at"), Value::Unsigned(self.at)),
            (Value::text("ttl"), Value::Unsigned(self.ttl_ms)),
            (Value::text("content"), content),
            (
                Value::text("assurance"),
                Value::Map(
                    self.assurance
                        .iter()
                        .map(|(k, v)| (Value::text(k), Value::Unsigned(*v)))
                        .collect(),
                ),
            ),
            (Value::text("retract"), Value::Bool(self.retract)),
        ];
        if let Some((k, b)) = bind {
            entries.push((
                Value::text("bind"),
                Value::Array(vec![Value::text(k), Value::Bytes(b)]),
            ));
        }
        if let Some(d) = disclose {
            entries.push((Value::text("disclose"), d));
        }
        if let Some(l) = self.line {
            entries.push((Value::text("line"), Value::Bytes(l.to_vec())));
        }
        dcbor::encode(&Value::Map(entries), Limits::CEILING).map_err(|_| BadOrder)
    }

    /// An order from its outbox bytes.
    ///
    /// # Errors
    /// [`BadOrder`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BadOrder> {
        let map = dcbor::decode(bytes, Limits::CEILING).map_err(|_| BadOrder)?;
        let uint = |key: &str| match map.get(key) {
            Some(Value::Unsigned(n)) => Ok(*n),
            _ => Err(BadOrder),
        };
        let flag = |key: &str| match map.get(key) {
            Some(Value::Bool(b)) => Ok(*b),
            None => Ok(false),
            _ => Err(BadOrder),
        };
        let class = match map.get("class") {
            Some(Value::Text(text)) => text.clone(),
            _ => return Err(BadOrder),
        };
        let subject = match map.get("subject") {
            Some(Value::Bytes(raw)) => raw.as_slice().try_into().map_err(|_| BadOrder)?,
            _ => return Err(BadOrder),
        };
        let line = match map.get("line") {
            None => None,
            Some(Value::Bytes(raw)) => Some(raw.as_slice().try_into().map_err(|_| BadOrder)?),
            _ => return Err(BadOrder),
        };
        Ok(Self {
            subject,
            content: content_of(map.get("content"), &class, flag("disclose")?)?,
            class,
            at: uint("at")?,
            ttl_ms: uint("ttl")?,
            assurance: assurance_of(map.get("assurance"))?,
            bind: bind_of(map.get("bind"))?,
            line,
            retract: flag("retract")?,
        })
    }
}

fn content_of(value: Option<&Value>, class: &str, disclose: bool) -> Result<Content, BadOrder> {
    let Some(Value::Array(parts)) = value else {
        return Err(BadOrder);
    };
    match parts.as_slice() {
        [Value::Text(tag), inner] if tag == "scalar" => Ok(Content::Scalar(
            EqValue::from_value(inner).map_err(|_| BadOrder)?,
        )),
        [Value::Text(tag), body, about] if tag == "about" => Ok(Content::About {
            body: body.clone(),
            party: match about {
                Value::Bytes(b) if b.is_empty() => None,
                Value::Bytes(b) => Some(b.as_slice().try_into().map_err(|_| BadOrder)?),
                _ => return Err(BadOrder),
            },
        }),
        [Value::Text(tag), inner] if tag == "body" => {
            let parsed = Class::parse(class).ok_or(BadOrder)?;
            Ok(Content::Body {
                body: Body::from_value(parsed, inner).map_err(|_| BadOrder)?,
                disclose,
            })
        }
        [Value::Text(tag), inner, Value::Bytes(about)] if tag == "party_scalar" => {
            Ok(Content::PartyScalar {
                value: EqValue::from_value(inner).map_err(|_| BadOrder)?,
                party: about.as_slice().try_into().map_err(|_| BadOrder)?,
            })
        }
        [Value::Text(tag), inner, Value::Bytes(about)] if tag == "party_body" => {
            let parsed = Class::parse(class).ok_or(BadOrder)?;
            Ok(Content::PartyBody {
                body: Body::from_value(parsed, inner).map_err(|_| BadOrder)?,
                party: about.as_slice().try_into().map_err(|_| BadOrder)?,
            })
        }
        [Value::Text(tag), inner] if tag == "registry" => {
            IdentityClass::parse(class).ok_or(BadOrder)?;
            Ok(Content::Registry(inner.clone()))
        }
        _ => Err(BadOrder),
    }
}

fn bind_of(value: Option<&Value>) -> Result<Bind, BadOrder> {
    let Some(value) = value else {
        return Ok(Bind::None);
    };
    let Value::Array(parts) = value else {
        return Err(BadOrder);
    };
    let [Value::Text(tag), Value::Bytes(raw)] = parts.as_slice() else {
        return Err(BadOrder);
    };
    Ok(match tag.as_str() {
        "instance" => Bind::Instance(raw.as_slice().try_into().map_err(|_| BadOrder)?),
        "session" => Bind::Session(raw.as_slice().try_into().map_err(|_| BadOrder)?),
        "statement" => {
            let (statement, instance) = raw.split_at_checked(32).ok_or(BadOrder)?;
            Bind::Statement {
                statement: statement.try_into().map_err(|_| BadOrder)?,
                instance: instance.try_into().map_err(|_| BadOrder)?,
            }
        }
        _ => return Err(BadOrder),
    })
}

fn assurance_of(value: Option<&Value>) -> Result<BTreeMap<String, u64>, BadOrder> {
    let mut out = BTreeMap::new();
    if let Some(Value::Map(entries)) = value {
        for (key, level) in entries {
            let (Value::Text(key), Value::Unsigned(level)) = (key, level) else {
                return Err(BadOrder);
            };
            out.insert(key.clone(), *level);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
