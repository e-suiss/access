//! The Approval Surface's own contract (OP-150 m.3 (r), OP-149 m.9, §9.14.1 A, §9.14.5): a
//! coordinator pushes a typed authority request with the approver's pre-signed contribution; the
//! surface builds the Approval Act Statement from the render the decision point kept, runs the
//! approver's single assertion over H(AAS), issues the `authentication` Claim bound to it and
//! commits the contribution. The smallest hosted page that does it lives here as well; visual
//! work is Stage 8. Nothing here grants authority: the approval meets a requirement (INV-16).

use std::collections::{BTreeMap, BTreeSet};

use access_internal_api::approvals::Contributed;
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Unmet};
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, HoldingRef};
use access_kernel::model::{Id, Independence, ProofKind, Window};
use access_kernel::render::Render;
use access_kernel::schema::Reversibility;
use access_kernel::tier::Tier;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use suiss_crypto::digest::context_digest;

use super::frontend::{REQUEST_URI_PREFIX, rfc3339, unix_ms};
use super::message::TextId;
use super::schema::{object, r};

/// `POST`: a coordinator pushes a request for the surface (XI-7: a short-lived copy).
pub const REQUESTS_PATH: &str = "/v1/approve/requests";
/// `POST`: the signed-in approver opens the flow and gets the render and the assertion options.
pub const FLOWS_PATH: &str = "/v1/approve/flows";
/// `POST`: the approver's assertion finishes the flow.
pub const FLOW_PATH: &str = "/v1/approve/flows/{flow}";
/// `GET`: the page's script.
pub const APP_PATH: &str = "/v1/approve/app.js";
/// `GET`: the MCP authorization server's consent step, sent on to the Approval Surface;
/// `POST` answers 405 (§11.4.5, §11.6, OP-157 m.3 (l)).
pub const CONSENT_PATH: &str = "/consent";

/// The conformance profile this surface reports in the statement (§9.14 `surface`).
pub const SURFACE_PROFILE: &str = "suiss-approval-surface";
/// Its version.
pub const SURFACE_VERSION: u64 = 1;

/// Digest context of a pushed request's bytes: what `request=<digest>` names.
pub const REQUEST_DIGEST_CONTEXT: &str = "access/authority-request-bytes/v1";

/// Largest pushed request or contribution envelope, in bytes.
pub const MAX_PUSH_BYTES: usize = 64 * 1024;

/// The longest a pushed request is kept: the CT3 intent validity ceiling (§13.7.3).
pub const MAX_PUSH_TTL_MS: u64 = 72 * 3_600 * 1_000;

/// The `contribute` class an approval exercises when the push names none.
pub const DEFAULT_CLASS: &str = "approve";

/// The approver's basis for the contribution: a Grant it holds, or its own Anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BasisRef {
    /// A Grant over `access/contribute` the approver holds (L0-META-30).
    Holding {
        /// `GrantID`, base64url of 16 bytes.
        grant: String,
        /// The holder Party, base64url of 16 bytes.
        holder: String,
        /// Position the holding is read at.
        since: u64,
    },
    /// The approver Party's own Anchor.
    Anchor {
        /// `AnchorID`, base64url of 16 bytes.
        anchor: String,
    },
}

/// The contribution the approver's device pre-signed (§9.14.1 A step 4): its AIS over
/// `access_kernel::contribution::contribute_intent` of the request's target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionEnvelope {
    /// The contribution's Exercise nonce, base64url, 16 to 64 bytes: the AAS `exercise_ref`.
    pub nonce: String,
    /// The `contribute` class; `approve` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// The approver's basis.
    pub basis: BasisRef,
    /// The intent's validity start, RFC 3339.
    pub valid_from: String,
    /// The intent's validity end, RFC 3339.
    pub valid_until: String,
    /// The AIS (`COSE_Sign1`) by the approver's device Instance key, base64url.
    pub ais: String,
    /// The coordinator's Gate this approval answers, when one waits on it (§9.14, OP-156 m.3
    /// (t)): opaque to Access, signed into the statement so the coordinator's Declaration can
    /// cite the contribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_gate: Option<WorkGateRef>,
}

/// A Work Gate and the Declaration content an approval answers (AAS `work_gate`), base64url
/// digests of 32 bytes each.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkGateRef {
    /// The `GateRef` digest.
    pub gate: String,
    /// The digest of the Work Declaration content that would satisfy the Gate.
    pub declaration: String,
}

/// `POST /v1/approve/requests`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPush {
    /// The typed authority request (`conformance/cddl/authority-request.schema.json`) with its
    /// `require_action`.
    pub request: Value,
    /// The pre-signed contribution.
    pub contribution: ContributionEnvelope,
    /// The intent as the decision point evaluated it, base64url of its dCBOR: needed with
    /// `body`, so the surface reads the authority-opaque digests the intent digest binds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// Authority-opaque bodies the approver must see, base64url, by parameter name (§8.17.6.2,
    /// OP-157 m.3 (l)): each must match the intent's opaque digest or nothing can be approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BTreeMap<String, String>>,
}

/// What the surface keeps of a push beside the request (XI-7): the contribution, and the
/// intent and bodies when the coordinator sent them; dropped with the push.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kept {
    /// The pre-signed contribution.
    pub contribution: ContributionEnvelope,
    /// As [`ApprovalPush::intent`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// As [`ApprovalPush::body`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BTreeMap<String, String>>,
}

/// A pushed request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPushed {
    /// The `request_uri` to open the surface with.
    pub request_uri: String,
    /// The digest of the pushed request bytes, base64url; `request=<digest>` opens it too.
    pub digest: String,
    /// When the surface stops showing it, RFC 3339.
    pub expires_at: String,
}

/// `POST /v1/approve/flows`: the call's parameters, from the page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalStart {
    /// As `GET /v1/approve`.
    pub request: String,
    /// As `GET /v1/approve`.
    pub redirect_uri: String,
    /// As `GET /v1/approve`.
    pub state: String,
}

/// One line of the render the decision point produced (§9.13.3, §9.14.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldView {
    /// The field.
    pub name: String,
    /// Its text.
    pub text: String,
    /// Whether it is material.
    pub material: bool,
}

/// What the approver is shown: the decision point's render, never the surface's own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderView {
    /// The fields, in display order.
    pub fields: Vec<FieldView>,
    /// The requester's reason, from the pushed request.
    pub reason: String,
    /// The consequence tier, 0 to 3.
    pub tier: u8,
    /// When the statement expires, RFC 3339 (§13.7.3 "AAS `expires_at`").
    pub expires_at: String,
    /// "You approve as: …" (OP-157 m.3 (l), §8.17.6.1).
    pub capacity: String,
    /// The requirement lines still open, "Still needed: 1 more · not the requester · a
    /// different person" (§8.17.6.4); never the word "independent".
    pub still_needed: Vec<String>,
    /// "These count as one approval" when one Party approved twice, or is about to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts_as_one: Option<String>,
    /// What approving does, from the effect class and reversibility.
    pub does: Section,
    /// What approving doesn't do.
    pub does_not: Section,
    /// The concrete act the assurance asks for (§8.17.6.3): "Confirm with your passkey".
    pub assurance_action: String,
    /// The heading the requester's reason is shown under, second to the render (E32).
    pub requester_note: String,
    /// Authority-opaque bodies, each matched against the intent's digest (§8.17.6.2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bodies: Vec<BodyView>,
    /// Whether this viewer can approve here; otherwise `blocked` says why and there is no
    /// button.
    pub approvable: bool,
    /// Why it can't be approved here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
}

/// A titled list of lines.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Section {
    /// The heading.
    pub title: String,
    /// The lines.
    pub lines: Vec<String>,
}

/// An authority-opaque body the coordinator sent, shown after its digest matched (§8.17.6.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyView {
    /// The opaque parameter.
    pub name: String,
    /// Its text, or its size when it is not text.
    pub text: String,
}

/// A started flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalStarted {
    /// The flow handle; absent when the viewer can't approve here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// What to show.
    pub render: RenderView,
    /// `PublicKeyCredentialRequestOptionsJSON`; its challenge is H(AAS). Absent with `flow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
    /// Secure Payment Confirmation's request data, from the canonical render, when the realm
    /// decided `idp.realm.spc` and the request is a payment (OP-156 m.3 (g)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spc: Option<Value>,
}

/// `POST /v1/approve/flows/{flow}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalFinish {
    /// The `PublicKeyCredential` JSON of the assertion (`toJSON()`), as a string or an object.
    pub credential: Value,
    /// As `GET /v1/approve`: where the browser goes back.
    pub redirect_uri: String,
    /// As `GET /v1/approve`: echoed unchanged.
    pub state: String,
    /// The app-controlled factor over the same statement: an activated approver's signature
    /// (MD-11, OP-156 m.3 (e)); required for CT2 and CT3 under the TR payment profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_factor: Option<AppFactorProof>,
}

/// An activated approver's signature over `dCBOR(["access/approval-app-factor/v1", issuer,
/// H(AAS), true])`: its app checked its own PIN before signing (MD-11, OP-156 m.3 (e)).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppFactorProof {
    /// The RFC 7638 thumbprint of the approver key, base64url.
    pub device_key: String,
    /// ES256 `r ‖ s`, base64url.
    pub signature: String,
}

/// What an approver signs as the app-controlled factor of an approval.
#[must_use]
pub fn app_factor_message(issuer: &str, statement: &[u8; 32]) -> Vec<u8> {
    use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
    dcbor::encode(
        &Cbor::Array(vec![
            Cbor::text("access/approval-app-factor/v1"),
            Cbor::text(issuer),
            Cbor::Bytes(statement.to_vec()),
            Cbor::Bool(true),
        ]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// A finished flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalFinished {
    /// Where the browser goes: `redirect_uri` with `exercise`, `render_digest`, `claim` and
    /// `state`.
    pub redirect: String,
    /// The contribution `ExerciseID`, base64url.
    pub exercise: String,
    /// The render digest, base64url.
    pub render_digest: String,
    /// The approver's `authentication` Claim, base64url `ClaimID`: bound to H(AAS) and to the
    /// approver's Instance, so the product passes it as `claim_ref` when its `REQUIRE_ACTION`
    /// also left an `authentication` term unmet (OP-149 m.33 (c), §13.7.3).
    pub claim: String,
}

/// What the surface reads from a pushed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pushed {
    /// The target's domain.
    pub domain: Digest,
    /// The target's intent digest.
    pub intent: Digest,
    /// The requester's reason.
    pub reason: String,
    /// When the request expires, Unix milliseconds.
    pub expires_at: u64,
}

/// A contribution envelope in bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The nonce.
    pub nonce: Vec<u8>,
    /// The class.
    pub class: String,
    /// The basis.
    pub basis: ExerciseBasis,
    /// Capacity: `own` (FOR(P) approvals are a later stage).
    pub capacity: Capacity,
    /// The intent's validity.
    pub validity: Window,
    /// The AIS.
    pub ais: Vec<u8>,
    /// The Work Gate and Declaration digests, when a Gate waits on it.
    pub work_gate: Option<(Digest, Digest)>,
}

/// Why a push is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PushRejection {
    /// The request is not a typed authority request with a `require_action`.
    #[error("request")]
    Request,
    /// The contribution envelope does not decode.
    #[error("contribution")]
    Contribution,
    /// `expires_at` is past or beyond the ceiling.
    #[error("expiry")]
    Expiry,
}

impl PushRejection {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Request => "invalid-approval-request",
            Self::Contribution => "invalid-contribution",
            Self::Expiry => "invalid-expiry",
        }
    }
}

fn b64(v: Option<&Value>, len: usize) -> Option<Vec<u8>> {
    let b = b64url_decode(v?.as_str()?).ok()?;
    (b.len() == len).then_some(b)
}

fn ident(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && s.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Reads a pushed request: the fields the surface needs (`require_action`, `reason`,
/// `expires_at`), each checked as the JSON Schema does.
///
/// # Errors
/// [`PushRejection::Request`].
pub fn pushed(request: &Value) -> Result<Pushed, PushRejection> {
    let obj = request.as_object().ok_or(PushRejection::Request)?;
    for key in ["requester", "action", "resource", "params", "capacity"] {
        if !obj.contains_key(key) {
            return Err(PushRejection::Request);
        }
    }
    let reason = obj
        .get("reason")
        .and_then(Value::as_str)
        .filter(|r| !r.is_empty() && r.len() <= 1024 && !r.chars().any(char::is_control))
        .ok_or(PushRejection::Request)?;
    let expires_at = obj
        .get("expires_at")
        .and_then(Value::as_u64)
        .ok_or(PushRejection::Request)?;
    let ra = obj.get("require_action").ok_or(PushRejection::Request)?;
    let domain = b64(ra.get("domain"), 32).ok_or(PushRejection::Request)?;
    let intent = b64(ra.get("intent"), 32).ok_or(PushRejection::Request)?;
    let nonce = ra
        .get("nonce")
        .and_then(Value::as_str)
        .and_then(|n| b64url_decode(n).ok())
        .filter(|n| (16..=64).contains(&n.len()))
        .ok_or(PushRejection::Request)?;
    let _ = nonce;
    Ok(Pushed {
        domain: Digest(<[u8; 32]>::try_from(domain).map_err(|_| PushRejection::Request)?),
        intent: Digest(<[u8; 32]>::try_from(intent).map_err(|_| PushRejection::Request)?),
        reason: String::from(reason),
        expires_at,
    })
}

fn id16(text: &str) -> Option<Id> {
    let b = b64url_decode(text).ok()?;
    <[u8; 16]>::try_from(b).ok().map(Id)
}

/// Reads a contribution envelope.
///
/// # Errors
/// [`PushRejection::Contribution`].
pub fn envelope(e: &ContributionEnvelope) -> Result<Envelope, PushRejection> {
    let bad = PushRejection::Contribution;
    let nonce = b64url_decode(&e.nonce)
        .ok()
        .filter(|n| (16..=64).contains(&n.len()))
        .ok_or(bad)?;
    let class = e
        .class
        .clone()
        .unwrap_or_else(|| String::from(DEFAULT_CLASS));
    if !ident(&class) {
        return Err(bad);
    }
    let basis = match &e.basis {
        BasisRef::Holding {
            grant,
            holder,
            since,
        } => ExerciseBasis::Holding(HoldingRef {
            grant: id16(grant).ok_or(bad)?,
            holder: id16(holder).ok_or(bad)?,
            since: *since,
        }),
        BasisRef::Anchor { anchor } => ExerciseBasis::Anchor(id16(anchor).ok_or(bad)?),
    };
    let (from, until) = (
        unix_ms(&e.valid_from).ok_or(bad)?,
        unix_ms(&e.valid_until).ok_or(bad)?,
    );
    if from > until {
        return Err(bad);
    }
    let ais = b64url_decode(&e.ais)
        .ok()
        .filter(|a| (1..=8192).contains(&a.len()) && a.first() == Some(&0xd2))
        .ok_or(bad)?;
    // OP-156 m.3 (t)
    let work_gate = e
        .work_gate
        .as_ref()
        .map(|w| {
            let d = |t: &str| {
                b64url_decode(t)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .map(Digest)
            };
            Some((d(&w.gate)?, d(&w.declaration)?))
        })
        .map(|w| w.ok_or(bad))
        .transpose()?;
    Ok(Envelope {
        nonce,
        class,
        basis,
        capacity: Capacity::Own,
        validity: Window { from, until },
        ais,
        work_gate,
    })
}

/// The digest `request=<digest>` names: the pushed request's bytes under
/// [`REQUEST_DIGEST_CONTEXT`].
#[must_use]
pub fn request_digest(request_bytes: &[u8]) -> [u8; 32] {
    context_digest(REQUEST_DIGEST_CONTEXT, request_bytes).0
}

/// The `request_uri` of a push from 32 random bytes (RFC 9126 form).
#[must_use]
pub fn request_uri(random: &[u8; 32]) -> String {
    format!("{REQUEST_URI_PREFIX}{}", b64url_encode(random))
}

/// How long a push is kept: until its `expires_at`, at most [`MAX_PUSH_TTL_MS`] from now.
///
/// # Errors
/// [`PushRejection::Expiry`] when `expires_at` is past.
pub fn kept_until(expires_at: u64, now: u64) -> Result<u64, PushRejection> {
    if expires_at <= now {
        return Err(PushRejection::Expiry);
    }
    Ok(expires_at.min(now.saturating_add(MAX_PUSH_TTL_MS)))
}

/// The SEC18 explanation for a binding that cools until `available_ms` (§8.13, X38).
#[must_use]
pub fn cooling_text(available_ms: u64) -> String {
    format!(
        "Needs: a sign-in method added more than 24 h ago (available {})",
        rfc3339(available_ms)
    )
}

/// Digest context of an authority-opaque body (§9.14.2 body digest rule, P30, OP-157 m.3 (l)):
/// the raw bytes, as the domain computed `intent.opaque[name]`.
pub const BODY_DIGEST_CONTEXT: &str = "access/opaque-body/v1";

/// Largest authority-opaque body the surface shows, in bytes.
pub const MAX_BODY_BYTES: usize = 32 * 1024;

/// The digest an authority-opaque body must have.
#[must_use]
pub fn body_digest(body: &[u8]) -> Digest {
    Digest(context_digest(BODY_DIGEST_CONTEXT, body).0)
}

/// A text with its placeholders filled (TN-131: plain text, no markup).
#[must_use]
pub fn say(id: TextId, args: &[(&str, &str)]) -> String {
    let mut text = String::from(id.default_text());
    for (name, value) in args {
        text = text.replace(&format!("{{ ${name} }}"), value);
    }
    text
}

/// Why pushed bodies do not match the intent (PI-17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("approval-body-mismatch")]
pub struct BodyMismatch;

/// The bodies the coordinator sent, each checked against the intent's authority-opaque digest
/// (§8.17.6.2, PI-17, OP-157 m.3 (l)): the intent must decode and have `target` as its digest,
/// and every body must be named in `intent.opaque` with the digest of its bytes. Access keeps
/// neither past the push (E26).
///
/// # Errors
/// [`BodyMismatch`].
pub fn bodies(
    intent: Option<&str>,
    body: Option<&BTreeMap<String, String>>,
    target: &Digest,
) -> Result<Vec<BodyView>, BodyMismatch> {
    let Some(body) = body.filter(|b| !b.is_empty()) else {
        return Ok(Vec::new());
    };
    let envelope = intent
        .and_then(|i| b64url_decode(i).ok())
        .and_then(|b| suiss_crypto::dcbor::decode(&b, suiss_crypto::dcbor::Limits::CEILING).ok())
        .and_then(|v| IntentEnvelope::from_value(&v).ok())
        .ok_or(BodyMismatch)?;
    if intent_digest(&envelope).map_err(|_| BodyMismatch)? != *target {
        return Err(BodyMismatch);
    }
    body.iter()
        .map(|(name, b64)| {
            let bytes = b64url_decode(b64)
                .ok()
                .filter(|b| b.len() <= MAX_BODY_BYTES)
                .ok_or(BodyMismatch)?;
            if envelope.opaque.get(name) != Some(&body_digest(&bytes)) {
                return Err(BodyMismatch);
            }
            let text = String::from_utf8(bytes)
                .ok()
                .filter(|t| !t.chars().any(|c| c.is_control() && c != '\n' && c != '\t'))
                .unwrap_or_else(|| format!("{} bytes", b64url_decode(b64).map_or(0, |b| b.len())));
            Ok(BodyView {
                name: name.clone(),
                text,
            })
        })
        .collect()
}

/// Whether the render can be shown faithfully for the pushed request (§8.17.6.2, E10): the
/// decision point kept a render only for an accepted Action Schema, and a request that names a
/// typed action must name the action and major version that render shows; another version can't
/// be shown from it.
#[must_use]
pub fn faithful(shown: &Render, request: &Value) -> bool {
    let Some(action) = request.get("action").filter(|a| a.is_object()) else {
        return true;
    };
    let named = (
        action.get("namespace").and_then(Value::as_str),
        action.get("name").and_then(Value::as_str),
        action.get("major").and_then(Value::as_u64),
    );
    let (Some(namespace), Some(name), Some(major)) = named else {
        return false;
    };
    shown
        .fields
        .iter()
        .find(|f| f.name == access_kernel::render::ACTION)
        .is_some_and(|f| f.text == format!("{namespace}/{name}@{major}"))
}

/// The capacity line (OP-157 m.3 (l), §8.17.6.1): what the approver's basis makes it.
#[must_use]
pub fn capacity_text(basis: &ExerciseBasis, class: &str, realm: &str) -> String {
    let role = match (basis, class) {
        (ExerciseBasis::Anchor(_), _) => String::from("yourself, on your own account"),
        (ExerciseBasis::Public(_), _) => format!("anyone {realm} lets approve"),
        (ExerciseBasis::Holding(_), DEFAULT_CLASS) => format!("an approver for {realm}"),
        (ExerciseBasis::Holding(_), c) => format!("a {c} contributor for {realm}"),
    };
    say(TextId::ApprovalCapacity, &[("capacity", &role)])
}

/// The words of a term's independence, never "independent" (§8.17.6.3, SEC10).
fn independence_words(independence: Independence) -> Vec<TextId> {
    match independence {
        Independence::None => Vec::new(),
        Independence::DistinctParty | Independence::DistinctIssuer => vec![
            TextId::ApprovalNotRequester,
            TextId::ApprovalDifferentPerson,
        ],
        Independence::DistinctInstance => vec![
            TextId::ApprovalNotRequester,
            TextId::ApprovalDifferentDevice,
        ],
        Independence::DistinctSurface => {
            vec![TextId::ApprovalNotRequester, TextId::ApprovalDifferentApp]
        }
    }
}

/// What one counted contribution is keyed by under a term's independence: one per Party,
/// Instance, or each on its own; a surface path is not recorded, so none counts (OP-157 m.8
/// (l)).
fn counted_key(c: &Contributed, independence: Independence) -> Option<[u8; 17]> {
    let mut k = [0; 17];
    let (tag, id) = match independence {
        Independence::None | Independence::DistinctSurface => return None,
        Independence::DistinctParty | Independence::DistinctIssuer => (1, c.party),
        Independence::DistinctInstance => (2, c.instance),
    };
    k[0] = tag;
    k[1..].copy_from_slice(&id.0);
    Some(k)
}

/// The quorum lines of a waiting approval (§8.17.6.4, L13, OP-157 m.3 (l)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Quorum {
    /// "Still needed: …" per open contribution term.
    pub lines: Vec<String>,
    /// Whether one Party's approvals count once here: it approved twice, or the viewer already
    /// approved.
    pub counts_as_one: bool,
}

/// The quorum of the contribution terms of `class` the decision left unmet, given what was
/// recorded since (`counted` false counts nothing recorded): the same Party twice counts once
/// under a distinct-person term.
#[must_use]
pub fn quorum(
    unmet: &[Unmet],
    contributed: &[Contributed],
    counted: bool,
    class: &str,
    viewer: &Id,
) -> Quorum {
    let mut out = Quorum::default();
    for u in unmet {
        let term = &u.term;
        if term.proof_kind != ProofKind::Contribution || term.class != class {
            continue;
        }
        let mine: Vec<&Contributed> = contributed
            .iter()
            .filter(|c| counted && c.class == term.class)
            .collect();
        let done = if term.independence == Independence::None {
            u64::try_from(mine.len()).unwrap_or(u64::MAX)
        } else {
            let keys: BTreeSet<[u8; 17]> = mine
                .iter()
                .filter_map(|c| counted_key(c, term.independence))
                .collect();
            u64::try_from(keys.len()).unwrap_or(u64::MAX)
        };
        let parties: BTreeSet<Id> = mine.iter().map(|c| c.party).collect();
        if matches!(
            term.independence,
            Independence::DistinctParty | Independence::DistinctIssuer
        ) && (parties.len() < mine.len() || parties.contains(viewer))
        {
            out.counts_as_one = true;
        }
        let left = u.missing.saturating_sub(done);
        if left == 0 {
            continue;
        }
        let more = left.to_string();
        let mut parts = vec![say(TextId::ApprovalMore, &[("count", &more)])];
        parts.extend(
            independence_words(term.independence)
                .into_iter()
                .map(|t| String::from(t.default_text())),
        );
        out.lines.push(say(
            TextId::ApprovalStillNeeded,
            &[("needed", &parts.join(" · "))],
        ));
    }
    out
}

/// The concrete act the approval's assurance asks for (§8.17.6.3, OP-157 m.3 (l)): a security
/// key when an open term asks for a key that is not synced, else a passkey.
#[must_use]
pub fn assurance_action(unmet: &[Unmet]) -> String {
    let hardware = unmet.iter().any(|u| {
        u.term.assurance.get(access_kernel::requirement::SYNCED) == Some(&0)
            || u.term
                .assurance
                .get(access_kernel::assurance::HARDWARE_BOUND)
                .is_some_and(|f| *f >= 1)
    });
    String::from(
        if hardware {
            TextId::ApprovalConfirmSecurityKey
        } else {
            TextId::ApprovalConfirmPasskey
        }
        .default_text(),
    )
}

/// What approving does and doesn't do, from the render's effect class and reversibility
/// (OP-157 m.3 (l), X29): approving records a contribution; Access re-checks the request; the
/// domain carries it out.
#[must_use]
pub fn effect(shown: Option<&Render>, tier: Tier) -> (Section, Section) {
    let effecting = shown.is_some_and(|r| {
        r.reversibility.is_some()
            || r.fields.iter().any(|f| {
                f.material
                    && ![
                        access_kernel::render::ACTION,
                        access_kernel::render::RESOURCE,
                        access_kernel::render::RECIPIENT,
                        access_kernel::render::VALIDITY,
                    ]
                    .contains(&f.name.as_str())
            })
    });
    let mut does = vec![String::from(
        "Records your approval. Access then re-checks the request.",
    )];
    if effecting {
        let by = shown
            .and_then(|r| r.fields.first())
            .and_then(|f| f.text.split('/').next())
            .unwrap_or("the requesting service");
        does.push(format!("If it is allowed, {by} carries it out."));
    }
    match shown.and_then(|r| r.reversibility) {
        Some(Reversibility::Reversible) => {
            does.push(String::from(TextId::ApprovalReversible.default_text()));
        }
        Some(Reversibility::Irreversible) => {
            does.push(String::from(TextId::ApprovalIrreversible.default_text()));
        }
        Some(Reversibility::Compensable) => {
            does.push(String::from("It can't be undone, only offset afterwards."));
        }
        None if tier >= Tier::Ct3 => {
            does.push(String::from(TextId::ApprovalIrreversible.default_text()));
        }
        None => {}
    }
    (
        Section {
            title: String::from(TextId::ApprovalDoes.default_text()),
            lines: does,
        },
        Section {
            title: String::from(TextId::ApprovalDoesNot.default_text()),
            lines: vec![
                String::from("Approving meets this one request only and grants nothing else."),
                String::from("It doesn't give anyone new authority."),
            ],
        },
    )
}

/// Why an Approval Surface collects no approval (§9.14.5 k.1, PI-17, OP-157 m.3 (l)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unfaithful {
    /// The render shown is not the decision point's: another digest, or not canonical.
    #[error("render")]
    Render,
    /// The statement's material fields are not the render's.
    #[error("material")]
    Material,
    /// A body does not match the intent's authority-opaque digest.
    #[error("body")]
    Body,
}

/// The Approval Surface conformance check (§9.14.5 k.1, U7, PI-17, XI-8, OP-157 m.3 (l)): the
/// render shown is canonical and has the decision point's `render_digest`, the statement names
/// exactly its material fields, and every authority-opaque body matches the digest the intent
/// (whose digest is the render's) carries for it.
///
/// # Errors
/// [`Unfaithful`].
pub fn wysiwys(
    shown: &[u8],
    render_digest: &Digest,
    material: &BTreeSet<String>,
    intent: Option<&[u8]>,
    bodies: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Unfaithful> {
    let r = access_kernel::render::decode(shown).map_err(|_| Unfaithful::Render)?;
    if access_kernel::render::encode(&r).ok().as_deref() != Some(shown)
        || Digest(context_digest(access_kernel::render::CONTEXT, shown).0) != *render_digest
    {
        return Err(Unfaithful::Render);
    }
    if access_kernel::render::material_fields(&r) != *material {
        return Err(Unfaithful::Material);
    }
    if bodies.is_empty() {
        return Ok(());
    }
    let envelope = intent
        .and_then(|b| suiss_crypto::dcbor::decode(b, suiss_crypto::dcbor::Limits::CEILING).ok())
        .and_then(|v| IntentEnvelope::from_value(&v).ok())
        .ok_or(Unfaithful::Body)?;
    if intent_digest(&envelope).ok() != Some(r.intent) {
        return Err(Unfaithful::Body);
    }
    if bodies
        .iter()
        .all(|(name, body)| envelope.opaque.get(name) == Some(&body_digest(body)))
    {
        Ok(())
    } else {
        Err(Unfaithful::Body)
    }
}

/// The page (OP-150 m.3 (r)): one element the script fills. Its script is [`PAGE_JS`] at
/// [`APP_PATH`], so the hosted login's CSP (`script-src 'self'`) holds.
pub const PAGE_HTML: &str = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Approve</title>\n</head>\n<body>\n<main id=\"approve\"><p>Loading the request…</p></main>\n<script src=\"/v1/approve/app.js\"></script>\n</body>\n</html>\n";

/// The page's script: starts the flow with the call's parameters, shows the render the decision
/// point produced, runs one assertion over H(AAS) and follows the redirect (§9.14.1 A steps 2
/// to 4; X29: it says the approval grants nothing beyond this request).
pub const PAGE_JS: &str = r#"(async () => {
  const q = new URLSearchParams(location.search);
  const el = (tag, text) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; return e; };
  const list = (lines) => { const ul = el("ul"); for (const line of lines) ul.append(el("li", line)); return ul; };
  const section = (cls, s) => { const e = el("section"); e.className = cls; e.append(el("h2", s.title), list(s.lines)); return e; };
  const root = document.getElementById("approve");
  const say = (text) => root.replaceChildren(el("p", text));
  const headers = () => ({ "content-type": "application/json", "idempotency-key": crypto.randomUUID() });
  const call = (path, body) => fetch(path, { method: "POST", headers: headers(), body: JSON.stringify(body), credentials: "same-origin" });
  const started = await call("/v1/approve/flows", { request: q.get("request"), redirect_uri: q.get("redirect_uri"), state: q.get("state") });
  if (started.status === 401) { say("Sign in first, then open this request again."); return; }
  const s = await started.json().catch(() => ({}));
  if (!started.ok) { say(s.title || "This request cannot be approved."); return; }
  const v = s.render;
  const fields = el("dl"); fields.className = "render";
  for (const f of v.fields) { const dd = el("dd", f.text); if (f.material) dd.className = "material"; fields.append(el("dt", f.name), dd); }
  const parts = [el("h1", "Approve this request?"), fields];
  if (v.bodies && v.bodies.length) { const b = el("dl"); b.className = "bodies"; for (const x of v.bodies) b.append(el("dt", x.name), el("dd", x.text)); parts.push(b); }
  const capacity = el("p", v.capacity); capacity.className = "capacity"; parts.push(capacity);
  if (v.still_needed.length) { const n = list(v.still_needed); n.className = "still-needed"; parts.push(n); }
  if (v.counts_as_one) { const c = el("p", v.counts_as_one); c.className = "counts-as-one"; parts.push(c); }
  parts.push(section("does", v.does), section("does-not", v.does_not));
  const note = el("section"); note.className = "requester-note"; note.append(el("h2", v.requester_note), el("p", v.reason)); parts.push(note);
  parts.push(el("p", "The statement expires at " + v.expires_at + "."));
  if (!s.flow) { const why = el("p", v.blocked || "This request cannot be approved here."); why.className = "blocked"; why.setAttribute("role", "status"); root.replaceChildren(...parts, why); return; }
  const button = el("button", v.assurance_action);
  root.replaceChildren(...parts, button);
  const confirmPayment = async () => {
    const b64 = (t) => Uint8Array.from(atob(t.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const data = Object.assign({}, s.spc, { rpId: s.options.rpId, challenge: b64(s.options.challenge), credentialIds: s.options.allowCredentials.map((c) => b64(c.id)), timeout: s.options.timeout });
    const total = data.total; delete data.total;
    const request = new PaymentRequest([{ supportedMethods: "secure-payment-confirmation", data }], { total: { label: "Total", amount: total } });
    const response = await request.show().catch(() => null);
    if (!response) return null;
    await response.complete("success").catch(() => undefined);
    return response.details;
  };
  button.onclick = async () => {
    button.disabled = true;
    const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(s.options);
    const cred = s.spc && window.PaymentRequest ? await confirmPayment() : await navigator.credentials.get({ publicKey }).catch(() => null);
    if (!cred) { button.disabled = false; return; }
    const r = await call("/v1/approve/flows/" + encodeURIComponent(s.flow), { credential: cred.toJSON(), redirect_uri: q.get("redirect_uri"), state: q.get("state") });
    const out = await r.json().catch(() => ({}));
    if (r.ok) { location.assign(out.redirect); } else { say(out.title || "The approval was not recorded."); }
  };
})();
"#;

fn b64_schema(description: &str) -> Value {
    json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]*$", "description": description })
}

fn time_field(description: &str) -> Value {
    json!({ "type": "string", "format": "date-time", "description": description })
}

/// The schemas of this contract.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one schema table, read top to bottom"
)]
pub fn components() -> Value {
    json!({
        "BasisRef": {
            "oneOf": [
                object(
                    &json!({
                        "grant": b64_schema("GrantID over access/contribute the approver holds, 16 bytes (L0-META-30)."),
                        "holder": b64_schema("The holder Party, 16 bytes."),
                        "since": { "type": "integer", "minimum": 0 },
                    }),
                    &["grant", "holder", "since"],
                ),
                object(&json!({ "anchor": b64_schema("The approver Party's own AnchorID, 16 bytes.") }), &["anchor"]),
            ],
        },
        "ContributionEnvelope": object(
            &json!({
                "nonce": b64_schema("The contribution's Exercise nonce, 16 to 64 bytes: the statement's exercise_ref."),
                "class": { "type": "string", "pattern": "^[a-z][a-z0-9_]{0,62}$", "description": "The contribute class; approve when absent." },
                "basis": r("BasisRef"),
                "valid_from": time_field("Intent validity start."),
                "valid_until": time_field("Intent validity end."),
                "ais": b64_schema("AIS (tagged COSE_Sign1) by the approver's device Instance key over the contribute intent of the request's target (Kernel contribution::contribute_intent; the committed example is conformance/cddl/examples/contribute-intent.json), mode commit, capacity own, pep access-identity."),
                "work_gate": object(
                    &json!({
                        "gate": b64_schema("The coordinator's GateRef digest, 32 bytes."),
                        "declaration": b64_schema("The digest of the Work Declaration content that would satisfy the Gate, 32 bytes."),
                    }),
                    &["gate", "declaration"],
                ),
            }),
            &["nonce", "basis", "valid_from", "valid_until", "ais"],
        ),
        "ApprovalPush": object(
            &json!({
                "request": { "type": "object", "description": "The typed authority request (conformance/cddl/authority-request.schema.json) with its require_action." },
                "contribution": r("ContributionEnvelope"),
                "intent": b64_schema("The intent envelope as the decision point evaluated it, dCBOR (kernel.cddl intent-envelope); required with body. Its digest must be require_action.intent."),
                "body": {
                    "type": "object",
                    "additionalProperties": b64_schema("The authority-opaque body, at most 32 KiB."),
                    "description": "Authority-opaque bodies the approver must see, by opaque parameter name (§8.17.6.2, OP-157 m.3 (l)). Each must hash to intent.opaque[name] under access/opaque-body/v1, or the request can't be approved; Access drops them with the push.",
                },
            }),
            &["request", "contribution"],
        ),
        "ApprovalPushed": object(
            &json!({
                "request_uri": { "type": "string", "description": "urn:ietf:params:oauth:request_uri:… to open GET /v1/approve with." },
                "digest": b64_schema("Digest of the pushed request bytes under access/authority-request-bytes/v1, 32 bytes; request=<digest> opens it too."),
                "expires_at": time_field("When the surface stops showing it: the request's expires_at, at most 72 h from the push."),
            }),
            &["request_uri", "digest", "expires_at"],
        ),
        "ApprovalStart": object(
            &json!({
                "request": { "type": "string" },
                "redirect_uri": { "type": "string" },
                "state": { "type": "string" },
            }),
            &["request", "redirect_uri", "state"],
        ),
        "FieldView": object(
            &json!({
                "name": { "type": "string" },
                "text": { "type": "string" },
                "material": { "type": "boolean" },
            }),
            &["name", "text", "material"],
        ),
        "Section": object(
            &json!({
                "title": { "type": "string" },
                "lines": { "type": "array", "items": { "type": "string" } },
            }),
            &["title", "lines"],
        ),
        "BodyView": object(
            &json!({
                "name": { "type": "string", "description": "The authority-opaque parameter." },
                "text": { "type": "string", "description": "The body as text, or its size when it is not text." },
            }),
            &["name", "text"],
        ),
        "RenderView": object(
            &json!({
                "fields": { "type": "array", "items": r("FieldView"), "description": "The render the decision point produced from the accepted Action Schema (§9.13.3); the surface shows nothing else. Empty when it can't be shown faithfully." },
                "reason": { "type": "string", "description": "The requester's note, shown second under requester_note (E32)." },
                "tier": { "type": "integer", "minimum": 0, "maximum": 3 },
                "expires_at": time_field("When the statement expires: CT1 15 min, CT2/CT3 5 min after it was built (§13.7.3)."),
                "capacity": { "type": "string", "description": "You approve as: … (OP-157 m.3 (l))." },
                "still_needed": { "type": "array", "items": { "type": "string" }, "description": "One line per open contribution term: how many more, not the requester, a different person, device or approval app (§8.17.6.4)." },
                "counts_as_one": { "type": "string", "description": "Present when one Party's approvals count once here." },
                "does": r("Section"),
                "does_not": r("Section"),
                "assurance_action": { "type": "string", "description": "The concrete act: Confirm with your passkey, or with your security key (§8.17.6.3)." },
                "requester_note": { "type": "string" },
                "bodies": { "type": "array", "items": r("BodyView") },
                "approvable": { "type": "boolean" },
                "blocked": { "type": "string", "description": "Why this viewer can't approve here: not shown faithfully (E10), a body that doesn't match (PI-17), or not eligible (E26)." },
            }),
            &["fields", "reason", "tier", "expires_at", "capacity", "still_needed", "does", "does_not", "assurance_action", "requester_note", "approvable"],
        ),
        "ApprovalStarted": object(
            &json!({
                "flow": { "type": "string", "description": "Absent when the viewer can't approve here; render.blocked says why." },
                "render": r("RenderView"),
                "options": { "type": "object", "description": "PublicKeyCredentialRequestOptionsJSON; the challenge is H(AAS) (§9.14.1 step 3). userVerification is required from CT2." },
                "spc": { "type": "object", "description": "Secure Payment Confirmation's request data (payeeName, payeeOrigin, total, instrument) from the canonical render, when the realm decided idp.realm.spc and the request is a payment; a payment.get assertion counts only when it shows exactly these (OP-156 m.3 (g))." },
            }),
            &["render"],
        ),
        "ApprovalFinish": object(
            &json!({
                "credential": { "description": "The PublicKeyCredential JSON of the assertion (toJSON()), as a string or an object." },
                "redirect_uri": { "type": "string", "description": "As GET /v1/approve; checked against the realm's clients again." },
                "state": { "type": "string", "description": "As GET /v1/approve." },
                "app_factor": r("AppFactorProof"),
            }),
            &["credential", "redirect_uri", "state"],
        ),
        "AppFactorProof": object(
            &json!({
                "device_key": b64_schema("The RFC 7638 thumbprint of an activated approver's key, 32 bytes."),
                "signature": b64_schema("ES256 r||s over dCBOR([\"access/approval-app-factor/v1\", issuer, H(AAS), true]): the app checked its own PIN; required for CT2 and CT3 under the TR payment profile (MD-11, OP-156 m.3 (e))."),
            }),
            &["device_key", "signature"],
        ),
        "ApprovalFinished": object(
            &json!({
                "redirect": { "type": "string", "description": "redirect_uri with exercise, render_digest, claim and state (OP-149 m.9, m.33 (c))." },
                "exercise": b64_schema("The contribution ExerciseID, 32 bytes."),
                "render_digest": b64_schema("The render digest, 32 bytes."),
                "claim": b64_schema("The approver's authentication ClaimID, 16 bytes: bound to H(AAS) and to the approver's Instance; passed as claim_ref when the REQUIRE_ACTION also left an authentication term unmet (OP-149 m.33 (c))."),
            }),
            &["redirect", "exercise", "render_digest", "claim"],
        ),
    })
}

fn json_response(description: &str, schema: &str) -> Value {
    json!({
        "description": description,
        "content": { "application/json": { "schema": r(schema) } },
    })
}

fn problem(description: &str) -> Value {
    json!({
        "description": description,
        "content": { "application/problem+json": { "schema": r("Problem") } },
    })
}

fn idempotency() -> Value {
    json!({
        "name": "Idempotency-Key",
        "in": "header",
        "required": true,
        "schema": { "type": "string", "maxLength": 255 },
    })
}

fn body(schema: &str) -> Value {
    json!({ "required": true, "content": { "application/json": { "schema": r(schema) } } })
}

/// The paths of this contract.
pub fn paths(paths: &mut Map<String, Value>) {
    paths.insert(
        REQUESTS_PATH.to_owned(),
        json!({ "post": {
            "operationId": "pushApprovalRequest",
            "summary": "A coordinator pushes a typed authority request that got REQUIRE_ACTION, with the approver's pre-signed contribution, for the realm's Approval Surface (OP-149 m.9, §9.14.1 A). Access keeps a copy until the request expires (72 h at most) and names it by request_uri and by the digest of the pushed bytes; the request stays the coordinator's (XI-7). No session is needed; the push binds nothing.",
            "parameters": [idempotency()],
            "requestBody": body("ApprovalPush"),
            "responses": {
                "201": json_response("Pushed.", "ApprovalPushed"),
                "400": problem("invalid-approval-request, invalid-contribution, invalid-expiry or invalid-request."),
                "413": problem("The request or the contribution is larger than 64 KiB."),
                "503": problem("Temporarily unavailable."),
            },
        }}),
    );
    paths.insert(
        FLOWS_PATH.to_owned(),
        json!({ "post": {
            "operationId": "startApproval",
            "summary": "Opens the approval for the signed-in approver (§9.14.1 A step 2): checks the call as GET /v1/approve does, finds the pushed request, asks the authority plane for the render the decision point kept for the target (§9.14.5 WYSIWYS) and the tier, builds the Approval Act Statement with the approver's device Instance (the one whose key signed the contribution), and answers the render and the assertion options whose challenge is H(AAS).",
            "parameters": [idempotency()],
            "requestBody": body("ApprovalStart"),
            "responses": {
                "200": json_response("Shown, but this viewer can't approve here: no flow is opened (render.approvable false, render.blocked says why).", "ApprovalStarted"),
                "201": json_response("The render and the options.", "ApprovalStarted"),
                "400": problem("invalid-approval-request, invalid-state, invalid-redirect-uri, invalid-request or approval-domain (the request's domain is not the realm's)."),
                "401": problem("No live session (session-required)."),
                "403": problem("approver-instance: no device Instance of this user signed the contribution."),
                "404": problem("approval-request-unknown: no such or an expired push."),
                "409": problem("approval-started: the push was opened already; approval-request-changed: the authority plane keeps no REQUIRE_ACTION for the target."),
                "503": problem("Temporarily unavailable."),
            },
        }}),
    );
    paths.insert(
        FLOW_PATH.to_owned(),
        json!({
            "parameters": [{ "name": "flow", "in": "path", "required": true, "schema": { "type": "string" } }],
            "post": {
                "operationId": "finishApproval",
                "summary": "The approver's single assertion over H(AAS) (§9.14.1 A step 3, AP-6, §10.3.4 WYSIWYS): verified as a passkey assertion of the session's user; the authentication Claim bound to the statement is issued at once (SI-5) and the contribution is committed as PEP (step 4). From CT2 the credential must be older than 24 h (SEC18) and user-verified.",
                "parameters": [idempotency()],
                "requestBody": body("ApprovalFinish"),
                "responses": {
                    "200": json_response("Committed; follow redirect.", "ApprovalFinished"),
                    "400": problem("invalid-request: the credential JSON does not decode."),
                    "401": problem("No live session (session-required); assertion-rejected: the assertion does not verify."),
                    "403": problem("cooling: the sign-in method is younger than 24 h for a CT2+ approval (SEC18); the body's available_at says when."),
                    "404": problem("approval-request-unknown: no such flow for this session."),
                    "409": problem("approval-not-started, approval-finished, approval-request-changed (the request changed after you approved), approval-claim-not-admitted, approval-not-allowed (with outcome) or approval-refused (with reason)."),
                    "503": problem("Temporarily unavailable."),
                },
            },
        }),
    );
    paths.insert(
        APP_PATH.to_owned(),
        json!({ "get": {
            "operationId": "approvalApp",
            "summary": "The approval page's script.",
            "security": [],
            "responses": { "200": { "description": "text/javascript." } },
        }}),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Value {
        json!({
            "requester": { "party": b64url_encode(&[1; 16]) },
            "action": { "namespace": "shop", "name": "refund", "major": 1, "schema": b64url_encode(&[1; 32]) },
            "resource": { "namespace": "shop", "path": ["orders", "o-1"], "incarnation": 0 },
            "params": {},
            "capacity": "own",
            "reason": "Parcel arrived damaged.",
            "require_action": {
                "domain": b64url_encode(&[3; 32]),
                "nonce": b64url_encode(&[0; 16]),
                "intent": b64url_encode(&[4; 32]),
            },
            "expires_at": 1_767_225_600_000u64,
        })
    }

    // OP-149 m.9, §9.14.1 step 1
    #[test]
    fn a_push_names_its_target() {
        let p = pushed(&request()).unwrap();
        assert_eq!(p.domain, Digest([3; 32]));
        assert_eq!(p.intent, Digest([4; 32]));
        assert_eq!(p.reason, "Parcel arrived damaged.");
        let mut no_target = request();
        no_target.as_object_mut().unwrap().remove("require_action");
        assert_eq!(pushed(&no_target), Err(PushRejection::Request));
        let mut no_reason = request();
        no_reason["reason"] = json!("");
        assert_eq!(pushed(&no_reason), Err(PushRejection::Request));
        let mut short = request();
        short["require_action"]["intent"] = json!(b64url_encode(&[4; 31]));
        assert_eq!(pushed(&short), Err(PushRejection::Request));
    }

    // §9.14.1 step 4, L0-META-30
    #[test]
    fn an_envelope_decodes_to_the_exercise_shape() {
        let e = ContributionEnvelope {
            nonce: b64url_encode(&[7; 16]),
            class: None,
            basis: BasisRef::Holding {
                grant: b64url_encode(&[1; 16]),
                holder: b64url_encode(&[2; 16]),
                since: 3,
            },
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2026-01-01T00:05:00Z".into(),
            ais: b64url_encode(&[0xd2, 0x84, 0x40]),
            work_gate: None,
        };
        let env = envelope(&e).unwrap();
        assert_eq!(env.class, DEFAULT_CLASS);
        assert_eq!(env.work_gate, None);
        // §9.14, OP-156 m.3 (t)
        let mut gated = e.clone();
        gated.work_gate = Some(WorkGateRef {
            gate: b64url_encode(&[0x61; 32]),
            declaration: b64url_encode(&[0x62; 32]),
        });
        assert_eq!(
            envelope(&gated).unwrap().work_gate,
            Some((Digest([0x61; 32]), Digest([0x62; 32])))
        );
        let mut short_gate = gated.clone();
        short_gate.work_gate = Some(WorkGateRef {
            gate: b64url_encode(&[0x61; 31]),
            declaration: b64url_encode(&[0x62; 32]),
        });
        assert_eq!(envelope(&short_gate), Err(PushRejection::Contribution));
        assert_eq!(env.capacity, Capacity::Own);
        assert!(matches!(env.basis, ExerciseBasis::Holding(h) if h.since == 3));
        assert!(env.validity.from < env.validity.until);
        let mut bad_class = e.clone();
        bad_class.class = Some("Approve".into());
        assert_eq!(envelope(&bad_class), Err(PushRejection::Contribution));
        let mut not_cose = e.clone();
        not_cose.ais = b64url_encode(&[1, 2, 3]);
        assert_eq!(envelope(&not_cose), Err(PushRejection::Contribution));
        let mut anchor = e;
        anchor.basis = BasisRef::Anchor {
            anchor: b64url_encode(&[9; 16]),
        };
        assert_eq!(
            envelope(&anchor).unwrap().basis,
            ExerciseBasis::Anchor(Id([9; 16]))
        );
    }

    // §13.7.3
    #[test]
    fn a_push_is_kept_no_longer_than_its_request() {
        let now = 1_000_000;
        assert_eq!(kept_until(now + 60_000, now), Ok(now + 60_000));
        assert_eq!(
            kept_until(now + MAX_PUSH_TTL_MS + 1, now),
            Ok(now + MAX_PUSH_TTL_MS)
        );
        assert_eq!(kept_until(now, now), Err(PushRejection::Expiry));
        assert_eq!(MAX_PUSH_TTL_MS, 72 * 3_600 * 1_000);
    }

    // SEC18, §8.13, X38
    #[test]
    fn the_cooling_text_names_the_time() {
        let text = cooling_text(1_767_225_600_000);
        assert!(text.starts_with("Needs: a sign-in method added more than 24 h ago (available "));
        assert!(text.contains("2026-01-01T00:00:00Z"));
    }

    fn term(
        class: &str,
        count: u64,
        independence: Independence,
    ) -> access_kernel::model::RequirementTerm {
        access_kernel::model::RequirementTerm {
            proof_kind: ProofKind::Contribution,
            class: String::from(class),
            count,
            binding: access_kernel::model::Binding::IntentDigest,
            freshness_ms: None,
            independence,
            consumption: access_kernel::model::Consumption::SingleUse,
            source: None,
            assurance: BTreeMap::new(),
        }
    }

    fn unmet(t: access_kernel::model::RequirementTerm, missing: u64) -> Unmet {
        Unmet {
            term: t,
            missing,
            position: access_kernel::combinator::Position::Anchor,
            satisfiable_by_actor: false,
        }
    }

    fn by(party: u8, instance: u8) -> Contributed {
        Contributed {
            class: String::from(DEFAULT_CLASS),
            party: Id([party; 16]),
            instance: Id([instance; 16]),
            since: u64::from(instance),
        }
    }

    // §8.17.6.4, L13, OP-157 m.3 (l), Ek B 5555
    #[test]
    fn the_same_party_twice_counts_as_one_approval() {
        let open = [unmet(term("approve", 2, Independence::DistinctParty), 2)];
        let viewer = Id([9; 16]);
        let none = quorum(&open, &[], true, "approve", &viewer);
        assert_eq!(
            none.lines,
            ["Still needed: 2 more · not the requester · a different person"]
        );
        assert!(!none.counts_as_one);
        let twice = quorum(&open, &[by(1, 1), by(1, 2)], true, "approve", &viewer);
        assert_eq!(
            twice.lines,
            ["Still needed: 1 more · not the requester · a different person"]
        );
        assert!(twice.counts_as_one);
        let two = quorum(&open, &[by(1, 1), by(2, 2)], true, "approve", &viewer);
        assert!(two.lines.is_empty() && !two.counts_as_one);
        let mine = quorum(&open, &[by(9, 1)], true, "approve", &viewer);
        assert!(mine.counts_as_one);
        let uncounted = quorum(&open, &[by(1, 1), by(2, 2)], false, "approve", &viewer);
        assert_eq!(uncounted.lines.len(), 1);
        assert!(uncounted.lines[0].starts_with("Still needed: 2 more"));
    }

    // §8.17.6.3, SEC10, OP-157 m.3 (l), m.8 (l), Ek B 5557
    #[test]
    fn independence_is_named_in_checkable_words_only() {
        let viewer = Id([9; 16]);
        let device = quorum(
            &[unmet(term("approve", 2, Independence::DistinctInstance), 2)],
            &[by(1, 1), by(1, 1)],
            true,
            "approve",
            &viewer,
        );
        assert_eq!(
            device.lines,
            ["Still needed: 1 more · not the requester · a different device"]
        );
        let app = quorum(
            &[unmet(term("approve", 1, Independence::DistinctSurface), 1)],
            &[by(1, 1)],
            true,
            "approve",
            &viewer,
        );
        assert_eq!(
            app.lines,
            ["Still needed: 1 more · not the requester · a different approval app"]
        );
        let plain = quorum(
            &[unmet(term("approve", 3, Independence::None), 3)],
            &[by(1, 1), by(1, 1)],
            true,
            "approve",
            &viewer,
        );
        assert_eq!(plain.lines, ["Still needed: 1 more"]);
        let other = quorum(
            &[unmet(term("review", 1, Independence::None), 1)],
            &[],
            true,
            "approve",
            &viewer,
        );
        assert_eq!(other.lines, Vec::<String>::new());
        for id in TextId::ALL {
            assert!(
                !id.default_text().to_lowercase().contains("independent"),
                "{id:?}"
            );
        }
    }

    // §8.17.6.3, OP-157 m.3 (l), Ek B 5420
    #[test]
    fn the_assurance_is_a_concrete_act() {
        assert_eq!(assurance_action(&[]), "Confirm with your passkey");
        let mut t = term("approve", 1, Independence::None);
        t.proof_kind = ProofKind::Claim;
        t.assurance
            .insert(String::from(access_kernel::requirement::SYNCED), 0);
        assert_eq!(
            assurance_action(&[unmet(t, 1)]),
            "Confirm with your security key"
        );
    }

    fn shown(reversibility: Option<Reversibility>, material: bool) -> Render {
        Render {
            schema: Digest([1; 32]),
            intent: Digest([4; 32]),
            locale: String::from("en"),
            template: None,
            fields: vec![
                access_kernel::render::Field {
                    name: String::from("action"),
                    text: String::from("shop/refund@1"),
                    material: true,
                },
                access_kernel::render::Field {
                    name: String::from("amount"),
                    text: String::from("4200 eur_cent"),
                    material,
                },
            ],
            reversibility,
        }
    }

    // §9.13.3, §9.14, §8.17.6.1, OP-157 m.3 (l), Ek B 5471, 5629
    #[test]
    fn effect_and_reversibility_come_from_the_render() {
        let (does, does_not) = effect(
            Some(&shown(Some(Reversibility::Irreversible), true)),
            Tier::Ct2,
        );
        assert_eq!(does.title, "What this does");
        assert!(
            does.lines
                .iter()
                .any(|l| l == "If it is allowed, shop carries it out.")
        );
        assert!(does.lines.iter().any(|l| l == "This can't be undone"));
        assert_eq!(does_not.title, "What this doesn't do");
        assert!(
            does_not
                .lines
                .iter()
                .any(|l| l.contains("grants nothing else"))
        );
        let (none, _) = effect(Some(&shown(None, false)), Tier::Ct1);
        assert_eq!(none.lines.len(), 1);
        let (reversible, _) = effect(
            Some(&shown(Some(Reversibility::Reversible), true)),
            Tier::Ct1,
        );
        assert!(reversible.lines.iter().any(|l| l == "This can be undone"));
        let basis = ExerciseBasis::Holding(HoldingRef {
            grant: Id([1; 16]),
            holder: Id([2; 16]),
            since: 0,
        });
        assert_eq!(
            capacity_text(&basis, "approve", "Acme"),
            "You approve as: an approver for Acme"
        );
        assert_eq!(
            capacity_text(&ExerciseBasis::Anchor(Id([3; 16])), "approve", "Acme"),
            "You approve as: yourself, on your own account"
        );
    }

    // §8.17.6.2, E10, OP-157 m.3 (l), Ek B 5627
    #[test]
    fn only_the_render_of_the_named_action_version_is_faithful() {
        let r = shown(None, true);
        let req = request();
        assert!(faithful(&r, &req));
        let mut other = req.clone();
        other["action"]["major"] = json!(2);
        assert!(!faithful(&r, &other));
        let mut renamed = req.clone();
        renamed["action"]["name"] = json!("charge");
        assert!(!faithful(&r, &renamed));
        let mut typeless = req.clone();
        typeless["action"] = json!("payment_initiation");
        assert!(faithful(&r, &typeless));
        let mut partial = req;
        partial["action"].as_object_mut().unwrap().remove("major");
        assert!(!faithful(&r, &partial));
    }

    // PI-17, §8.17.6.2, P30, OP-157 m.3 (l), Ek B 5628
    #[test]
    fn a_body_must_match_the_intents_opaque_digest() {
        let text = b"Dear supplier, the payment is on its way.";
        let mut env = IntentEnvelope {
            action: access_kernel::model::ActionRef {
                namespace: String::from("mail"),
                name: String::from("send"),
                major: 1,
                schema: Digest([1; 32]),
            },
            resources: vec![access_kernel::model::ResourceRef {
                namespace: String::from("mail"),
                path: vec![String::from("outbox")],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::from([(String::from("body"), body_digest(text))]),
            recipient: None,
            purpose: None,
            context: access_kernel::intent::ContextRefs::default(),
            provenance: BTreeMap::new(),
            validity: Window { from: 0, until: 1 },
        };
        let target = intent_digest(&env).unwrap();
        let encoded = b64url_encode(&env.to_bytes().unwrap());
        let sent = BTreeMap::from([(String::from("body"), b64url_encode(text))]);
        let shown = bodies(Some(&encoded), Some(&sent), &target).unwrap();
        assert_eq!(shown[0].text, String::from_utf8(text.to_vec()).unwrap());
        assert_eq!(bodies(None, None, &target), Ok(Vec::new()));
        let changed = BTreeMap::from([(String::from("body"), b64url_encode(b"Pay someone else."))]);
        assert_eq!(
            bodies(Some(&encoded), Some(&changed), &target),
            Err(BodyMismatch)
        );
        let unnamed = BTreeMap::from([(String::from("note"), b64url_encode(text))]);
        assert_eq!(
            bodies(Some(&encoded), Some(&unnamed), &target),
            Err(BodyMismatch)
        );
        assert_eq!(bodies(None, Some(&sent), &target), Err(BodyMismatch));
        env.validity.until = 2;
        let other = b64url_encode(&env.to_bytes().unwrap());
        assert_eq!(
            bodies(Some(&other), Some(&sent), &target),
            Err(BodyMismatch)
        );
    }

    // OP-146 m.12 (f)
    #[test]
    fn the_page_fits_the_hosted_csp() {
        assert!(PAGE_HTML.contains("<script src=\"/v1/approve/app.js\"></script>"));
        assert!(!PAGE_HTML.contains("<script>"));
        assert!(!PAGE_JS.contains("innerHTML") && !PAGE_JS.contains("eval("));
        assert!(PAGE_JS.contains("v.does_not") && PAGE_JS.contains("v.blocked"));
        assert!(PAGE_JS.contains("v.requester_note") && !PAGE_JS.contains("ndependent"));
        assert!(PAGE_JS.contains("\"/v1/approve/flows\""));
        let d = request_digest(b"{}");
        assert_eq!(d, context_digest(REQUEST_DIGEST_CONTEXT, b"{}").0);
        assert!(request_uri(&[5; 32]).starts_with(REQUEST_URI_PREFIX));
    }
}
