//! The Approval Surface's own contract (OP-150 m.3 (r), OP-149 m.9, §9.14.1 A, §9.14.5): a
//! coordinator pushes a typed authority request with the approver's pre-signed contribution; the
//! surface builds the Approval Act Statement from the render the decision point kept, runs the
//! approver's single assertion over H(AAS), issues the `authentication` Claim bound to it and
//! commits the contribution. The smallest hosted page that does it lives here as well; visual
//! work is Stage 8. Nothing here grants authority: the approval meets a requirement (INV-16).

use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, HoldingRef};
use access_kernel::model::{Id, Window};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use suiss_crypto::digest::context_digest;

use super::frontend::{REQUEST_URI_PREFIX, rfc3339, unix_ms};
use super::schema::{object, r};

/// `POST`: a coordinator pushes a request for the surface (XI-7: a short-lived copy).
pub const REQUESTS_PATH: &str = "/v1/approve/requests";
/// `POST`: the signed-in approver opens the flow and gets the render and the assertion options.
pub const FLOWS_PATH: &str = "/v1/approve/flows";
/// `POST`: the approver's assertion finishes the flow.
pub const FLOW_PATH: &str = "/v1/approve/flows/{flow}";
/// `GET`: the page's script.
pub const APP_PATH: &str = "/v1/approve/app.js";

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
}

/// A started flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalStarted {
    /// The flow handle.
    pub flow: String,
    /// What to show.
    pub render: RenderView,
    /// `PublicKeyCredentialRequestOptionsJSON`; its challenge is H(AAS).
    pub options: Value,
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
    Ok(Envelope {
        nonce,
        class,
        basis,
        capacity: Capacity::Own,
        validity: Window { from, until },
        ais,
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

/// The page (OP-150 m.3 (r)): one element the script fills. Its script is [`PAGE_JS`] at
/// [`APP_PATH`], so the hosted login's CSP (`script-src 'self'`) holds.
pub const PAGE_HTML: &str = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Approve</title>\n</head>\n<body>\n<main id=\"approve\"><p>Loading the request…</p></main>\n<script src=\"/v1/approve/app.js\"></script>\n</body>\n</html>\n";

/// The page's script: starts the flow with the call's parameters, shows the render the decision
/// point produced, runs one assertion over H(AAS) and follows the redirect (§9.14.1 A steps 2
/// to 4; X29: it says the approval grants nothing beyond this request).
pub const PAGE_JS: &str = r#"(async () => {
  const q = new URLSearchParams(location.search);
  const el = (tag, text) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; return e; };
  const root = document.getElementById("approve");
  const say = (text) => root.replaceChildren(el("p", text));
  const headers = () => ({ "content-type": "application/json", "idempotency-key": crypto.randomUUID() });
  const call = (path, body) => fetch(path, { method: "POST", headers: headers(), body: JSON.stringify(body), credentials: "same-origin" });
  const started = await call("/v1/approve/flows", { request: q.get("request"), redirect_uri: q.get("redirect_uri"), state: q.get("state") });
  if (started.status === 401) { say("Sign in first, then open this request again."); return; }
  const s = await started.json().catch(() => ({}));
  if (!started.ok) { say(s.title || "This request cannot be approved."); return; }
  const list = el("dl");
  for (const f of s.render.fields) { const dd = el("dd", f.text); if (f.material) dd.className = "material"; list.append(el("dt", f.name), dd); }
  const button = el("button", "Approve with your passkey");
  root.replaceChildren(el("h1", "Approve this request?"), list, el("p", s.render.reason),
    el("p", "Approving meets this one request only and grants nothing else. The statement expires at " + s.render.expires_at + "."), button);
  button.onclick = async () => {
    button.disabled = true;
    const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(s.options);
    const cred = await navigator.credentials.get({ publicKey }).catch(() => null);
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
            }),
            &["nonce", "basis", "valid_from", "valid_until", "ais"],
        ),
        "ApprovalPush": object(
            &json!({
                "request": { "type": "object", "description": "The typed authority request (conformance/cddl/authority-request.schema.json) with its require_action." },
                "contribution": r("ContributionEnvelope"),
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
        "RenderView": object(
            &json!({
                "fields": { "type": "array", "items": r("FieldView"), "description": "The render the decision point produced from the accepted Action Schema (§9.13.3); the surface shows nothing else." },
                "reason": { "type": "string" },
                "tier": { "type": "integer", "minimum": 0, "maximum": 3 },
                "expires_at": time_field("When the statement expires: CT1 15 min, CT2/CT3 5 min after it was built (§13.7.3)."),
            }),
            &["fields", "reason", "tier", "expires_at"],
        ),
        "ApprovalStarted": object(
            &json!({
                "flow": { "type": "string" },
                "render": r("RenderView"),
                "options": { "type": "object", "description": "PublicKeyCredentialRequestOptionsJSON; the challenge is H(AAS) (§9.14.1 step 3). userVerification is required from CT2." },
            }),
            &["flow", "render", "options"],
        ),
        "ApprovalFinish": object(
            &json!({
                "credential": { "description": "The PublicKeyCredential JSON of the assertion (toJSON()), as a string or an object." },
                "redirect_uri": { "type": "string", "description": "As GET /v1/approve; checked against the realm's clients again." },
                "state": { "type": "string", "description": "As GET /v1/approve." },
            }),
            &["credential", "redirect_uri", "state"],
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

    // OP-149 m.9, §9.14.1 A step 1: the surface reads the target from the request's
    // require_action; a request without one, or without a reason, is no approval request
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

    // §9.14.1 A step 4, L0-META-30: the contribution envelope names the nonce, the basis and
    // the AIS; capacity is own in Stage 6
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
        };
        let env = envelope(&e).unwrap();
        assert_eq!(env.class, DEFAULT_CLASS);
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

    // §13.7.3: a push is kept until its expires_at, at most 72 h (the CT3 intent validity
    // ceiling); a past expires_at is refused
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

    // SEC18, §8.13, X38: the cooling refusal names when the method becomes usable
    #[test]
    fn the_cooling_text_names_the_time() {
        let text = cooling_text(1_767_225_600_000);
        assert!(text.starts_with("Needs: a sign-in method added more than 24 h ago (available "));
        assert!(text.contains("2026-01-01T00:00:00Z"));
    }

    // OP-146 m.12 (f): the page loads its script from the realm host only, so the hosted CSP
    // (script-src 'self', no inline scripts) holds, and the script uses no HTML sinks
    #[test]
    fn the_page_fits_the_hosted_csp() {
        assert!(PAGE_HTML.contains("<script src=\"/v1/approve/app.js\"></script>"));
        assert!(!PAGE_HTML.contains("<script>"));
        assert!(!PAGE_JS.contains("innerHTML") && !PAGE_JS.contains("eval("));
        assert!(PAGE_JS.contains("grants nothing else"));
        assert!(PAGE_JS.contains("\"/v1/approve/flows\""));
        let d = request_digest(b"{}");
        assert_eq!(d, context_digest(REQUEST_DIGEST_CONTEXT, b"{}").0);
        assert!(request_uri(&[5; 32]).starts_with(REQUEST_URI_PREFIX));
    }
}
