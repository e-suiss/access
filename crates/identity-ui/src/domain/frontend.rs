//! The Frontend API for products (OP-149 m.6, m.8, m.9): device Instances from a stepped-up
//! session, the `auth_context` artifact and the approval call contract. The wire types live
//! here and the `OpenAPI` document is generated from them (OP-65, TN-112), committed as
//! `sdks/openapi/frontend.json`.

use access_kernel::json::{b64url_decode, b64url_encode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::schema::{object, r, string_enum};

/// Version of this contract.
pub const CONTRACT_VERSION: u64 = 1;

/// `POST`: a challenge for a device key.
pub const CHALLENGES_PATH: &str = "/v1/me/instances/challenges";
/// `POST`: registers a device Instance.
pub const INSTANCES_PATH: &str = "/v1/me/instances";
/// `DELETE`: ends a device Instance.
pub const INSTANCE_PATH: &str = "/v1/me/instances/{instance}";
/// `POST`: the session's `auth_context`.
pub const AUTH_CONTEXT_PATH: &str = "/v1/me/auth-context";
/// `GET`: the approval call (OP-149 m.9).
pub const APPROVE_PATH: &str = "/v1/approve";

/// The PEP name the identity plane forwards a termination as: the `pep` an AIS over
/// `access/instance_terminate` names.
pub const IDENTITY_PEP: &str = access_internal_api::instances::IDENTITY_PEP;

/// Longest `state` accepted, in bytes.
pub const MAX_STATE: usize = 512;

/// The `request_uri` prefix of a pushed request (RFC 9126).
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// A challenge for a device key, with what the device's Exercises name (OP-149 m.16 (a)).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceChallenge {
    /// 32 bytes, base64url: the nonce of the device's `instance_create`; `party_register` uses
    /// it followed by the byte `0x01`.
    pub challenge: String,
    /// When it stops being accepted, RFC 3339.
    pub expires_at: String,
    /// The realm's governing `DomainID`, base64url of its 32 bytes.
    pub domain: String,
    /// The basis both Exercises name: `public` with this Genesis bootstrap `GrantID`, base64url
    /// of its 16 bytes (L0-META-7).
    pub basis: String,
    /// The PEP name both AIS name.
    pub pep: String,
    /// The user's Party, base64url of its 16 bytes, once its first device registered it; absent
    /// before, when the device registers a new Party too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<String>,
}

/// `POST /v1/me/instances` (OP-149 m.16 (a)): the device's own `instance_create` Exercise, and
/// its `party_register` when the user has no Party yet, both signed by the device key. Each
/// intent is `access/<action>` on `access.party:[hex(party)]` with the payload digest in
/// `opaque["payload"]`, over `[valid_from, valid_until]`; mode commit, capacity own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceRegistration {
    /// The challenge this registration answers, base64url.
    pub challenge: String,
    /// The `PartyID`, base64url of its 16 bytes: the user's Party, or a new one with
    /// [`Self::register_ais`].
    pub party: String,
    /// The device key as a `COSE_Key`, base64url: Ed25519 or P-256.
    pub key: String,
    /// The intents' validity start, RFC 3339 with at most millisecond precision.
    pub valid_from: String,
    /// The intents' validity end, RFC 3339 with at most millisecond precision.
    pub valid_until: String,
    /// The AIS (`COSE_Sign1`) of `instance_create` by the device key, base64url; its nonce is
    /// the challenge. Its signature is the proof of possession.
    pub ais: String,
    /// The AIS of `party_register` (the Party roots itself, actor kind `human`) by the device
    /// key, base64url; required exactly when the user has no Party yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_ais: Option<String>,
}

/// A registered device Instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceRegistered {
    /// The `InstanceID`, base64url of its 16 bytes: the ADP JSON encoding of Kernel ids
    /// (OP-149 m.16 (f)), as key lookup answers it.
    pub instance: String,
    /// The key's RFC 7638 thumbprint, base64url (CR-24).
    pub kid: String,
    /// The `PartyID`, base64url of its 16 bytes.
    pub party: String,
}

/// `DELETE /v1/me/instances/{instance}`: an `instance_terminate` Exercise the user's own
/// Instance signed (OP-146 m.4 (i)). The intent is `access/instance_terminate` on
/// `access.instance:[hex(instance)]` with the payload digest in `opaque["payload"]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceTermination {
    /// The Exercise nonce, base64url, 16 to 64 bytes.
    pub nonce: String,
    /// The actor Party's self-anchor, base64url of its 16-byte id.
    pub basis: String,
    /// The intent's validity start, RFC 3339 with at most millisecond precision.
    pub valid_from: String,
    /// The intent's validity end, RFC 3339 with at most millisecond precision.
    pub valid_until: String,
    /// The AIS (`COSE_Sign1`), base64url.
    pub ais: String,
}

/// A recorded termination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceTerminated {
    /// The `ExerciseID`, base64url (TN-110).
    pub exercise: String,
}

/// `POST /v1/me/auth-context`: optional content binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthContextRequest {
    /// A lower-case `type/subtype` media type.
    pub content_type: String,
    /// SHA-256 of the content, base64url.
    pub content_digest: String,
}

/// The signed artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthContextIssued {
    /// The tagged `COSE_Sign1` of the artifact, base64url.
    pub auth_context: String,
    /// `SHA-256("suiss/auth-context/v1" ‖ 0x00 ‖ payload)`, base64url.
    pub digest: String,
}

/// `GET /v1/approve` query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveQuery {
    /// The authority request's digest (base64url, 32 bytes) or a pushed `request_uri`.
    pub request: String,
    /// Where the browser goes back; exactly a redirect URI a client of the realm registered.
    pub redirect_uri: String,
    /// Echoed unchanged.
    pub state: String,
}

/// What an approval call names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalRequest {
    /// The typed authority request's digest.
    Digest([u8; 32]),
    /// A pushed request.
    RequestUri(String),
}

/// Why an approval call is refused before anything is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApproveRejection {
    /// `request` is neither a digest nor a `request_uri`.
    #[error("request")]
    Request,
    /// `state` is empty, too long or not printable ASCII.
    #[error("state")]
    State,
    /// `redirect_uri` is not exactly one active client's registered redirect URI.
    #[error("redirect_uri")]
    RedirectUri,
}

impl ApproveRejection {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Request => "invalid-approval-request",
            Self::State => "invalid-state",
            Self::RedirectUri => "invalid-redirect-uri",
        }
    }
}

/// Checks the call's own parameters; the redirect URI is checked against the realm's clients
/// by the caller.
///
/// # Errors
/// [`ApproveRejection`].
pub fn approval_request(q: &ApproveQuery) -> Result<ApprovalRequest, ApproveRejection> {
    let state_ok = !q.state.is_empty()
        && q.state.len() <= MAX_STATE
        && q.state.bytes().all(|c| (0x20..=0x7e).contains(&c));
    if !state_ok {
        return Err(ApproveRejection::State);
    }
    if let Some(token) = q.request.strip_prefix(REQUEST_URI_PREFIX) {
        let ok = (16..=128).contains(&token.len())
            && token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
        return if ok {
            Ok(ApprovalRequest::RequestUri(q.request.clone()))
        } else {
            Err(ApproveRejection::Request)
        };
    }
    b64url_decode(&q.request)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(ApprovalRequest::Digest)
        .ok_or(ApproveRejection::Request)
}

fn percent(s: &str) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Where a completed approval sends the browser: `redirect_uri` with `exercise` and
/// `render_digest` (base64url) and the echoed `state` (OP-149 m.9).
#[must_use]
pub fn approval_redirect(
    redirect_uri: &str,
    exercise: &[u8; 32],
    render_digest: &[u8; 32],
    state: &str,
) -> String {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    format!(
        "{redirect_uri}{sep}exercise={}&render_digest={}&state={}",
        b64url_encode(exercise),
        b64url_encode(render_digest),
        percent(state)
    )
}

/// Unix milliseconds as RFC 3339 UTC.
#[must_use]
pub fn rfc3339(ms: u64) -> String {
    i128::from(ms)
        .checked_mul(1_000_000)
        .and_then(|ns| OffsetDateTime::from_unix_timestamp_nanos(ns).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

/// RFC 3339 as Unix milliseconds; `None` for anything finer than a millisecond or before
/// 1970.
#[must_use]
pub fn unix_ms(text: &str) -> Option<u64> {
    let t = OffsetDateTime::parse(text, &Rfc3339).ok()?;
    let ns = t.unix_timestamp_nanos();
    if ns % 1_000_000 != 0 {
        return None;
    }
    u64::try_from(ns / 1_000_000).ok()
}

fn b64(description: &str) -> Value {
    json!({
        "type": "string",
        "pattern": "^[A-Za-z0-9_-]*$",
        "description": description,
    })
}

fn id16(description: &str) -> Value {
    json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]{22}$", "description": description })
}

fn time_field(description: &str) -> Value {
    json!({ "type": "string", "format": "date-time", "description": description })
}

/// The stable problem codes of this contract.
fn problem_codes() -> Value {
    string_enum(&[
        "session-required",
        "step-up-required",
        "invalid-challenge",
        "invalid-instance-key",
        "invalid-proof-of-possession",
        "invalid-party",
        "instance-not-registered",
        "instance-exists",
        "instance-not-terminated",
        "invalid-contribution",
        "invalid-expiry",
        "approval-domain",
        "approval-request-unknown",
        "approval-request-changed",
        "approval-started",
        "approval-not-started",
        "approval-finished",
        "approval-expired",
        "approver-instance",
        "approver-passkey",
        "assertion-rejected",
        "cooling",
        "approval-claim-not-admitted",
        "approval-not-allowed",
        "approval-refused",
        "invalid-request",
        "invalid-content",
        "invalid-approval-request",
        "invalid-state",
        "invalid-redirect-uri",
        "approval-surface-unavailable",
        "unavailable",
    ])
}

fn components() -> Value {
    json!({
        "InstanceChallenge": object(
            &json!({
                "challenge": b64("32 bytes: the nonce of the device's instance_create; party_register uses it followed by the byte 0x01."),
                "expires_at": time_field("When it stops being accepted."),
                "domain": b64("The realm's governing DomainID, 32 bytes."),
                "basis": b64("GrantID of the Genesis bootstrap Grant, 16 bytes: both Exercises name the basis public with it (L0-META-7)."),
                "pep": { "type": "string", "const": "access-identity", "description": "The PEP name both AIS name." },
                "party": id16("The user's Party once its first device registered it; absent before."),
            }),
            &["challenge", "expires_at", "domain", "basis", "pep"],
        ),
        "InstanceRegistration": object(
            &json!({
                "challenge": b64("The challenge this registration answers."),
                "party": id16("The user's Party, or a new one registered with register_ais."),
                "key": b64("COSE_Key (RFC 9052 §7): OKP Ed25519 or EC2 P-256."),
                "valid_from": time_field("Intent validity start, millisecond precision at most."),
                "valid_until": time_field("Intent validity end, millisecond precision at most."),
                "ais": b64("AIS (tagged COSE_Sign1) by the device key over the access/instance_create intent on access.party:[hex(party)], nonce the challenge, mode commit, capacity own, the challenge's basis and pep (OP-149 m.16 (a)). Its signature is the proof of possession."),
                "register_ais": b64("AIS by the device key over the access/party_register intent (the Party roots itself, actor kind human), nonce the challenge followed by 0x01; required exactly when the user has no Party yet."),
            }),
            &["challenge", "party", "key", "valid_from", "valid_until", "ais"],
        ),
        "InstanceRegistered": object(
            &json!({
                "instance": { "type": "string", "pattern": "^[A-Za-z0-9_-]{22}$", "description": "InstanceID, base64url of its 16 bytes (ADP JSON encoding, OP-149 m.16 (f))." },
                "kid": b64("RFC 7638 thumbprint of the key (CR-24)."),
                "party": id16("The Party the Instance belongs to."),
            }),
            &["instance", "kid", "party"],
        ),
        "InstanceTermination": object(
            &json!({
                "nonce": b64("Exercise nonce, 16 to 64 bytes."),
                "basis": b64("The actor Party's self-anchor id, 16 bytes."),
                "valid_from": time_field("Intent validity start, millisecond precision at most."),
                "valid_until": time_field("Intent validity end, millisecond precision at most."),
                "ais": b64("AIS (COSE_Sign1) by one of the user's own Instances over the access/instance_terminate intent, mode commit, capacity own, pep \"access-identity\"."),
            }),
            &["nonce", "basis", "valid_from", "valid_until", "ais"],
        ),
        "InstanceTerminated": object(
            &json!({ "exercise": b64("ExerciseID, 32 bytes (TN-110).") }),
            &["exercise"],
        ),
        "AuthContextRequest": object(
            &json!({
                "content_type": {
                    "type": "string",
                    "pattern": "^[a-z0-9!#$&^_.+-]{1,63}/[a-z0-9!#$&^_.+-]{1,63}$",
                },
                "content_digest": b64("SHA-256 of the content, 32 bytes."),
            }),
            &["content_type", "content_digest"],
        ),
        "AuthContextIssued": object(
            &json!({
                "auth_context": b64("Tagged COSE_Sign1 of the auth-context (conformance/cddl/auth-context.cddl) by the realm's identity signer key; content type application/access-auth-context+cbor. The payload names the device Instance the session is bound to as `instance` when it registered one (OP-149 m.30 (c))."),
                "digest": b64("SHA-256(\"suiss/auth-context/v1\" || 0x00 || payload), 32 bytes."),
            }),
            &["auth_context", "digest"],
        ),
        "Problem": {
            "type": "object",
            "required": ["type", "title", "status"],
            "properties": {
                "type": { "type": "string" },
                "title": { "type": "string" },
                "status": { "type": "integer" },
                "detail": { "type": "string" },
                "code": { "type": "string", "description": "The stable code the type URI names." },
                "reason": { "type": "string", "description": "A stable, non-secret reason that narrows the code (OP-149 m.24 (b))." },
                "errors": {
                    "type": "array",
                    "description": "What the problem is about: a stable code each and, when the request body names it, a JSON Pointer; never a request value (OP-149 m.24 (b), m.30 (b)).",
                    "items": {
                        "type": "object",
                        "required": ["code"],
                        "properties": {
                            "code": { "type": "string" },
                            "pointer": { "type": "string" },
                        },
                    },
                },
            },
        },
        "ProblemCode": problem_codes(),
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

fn body(schema: &str, required: bool) -> Value {
    json!({
        "required": required,
        "content": { "application/json": { "schema": r(schema) } },
    })
}

/// The `OpenAPI` document of this contract.
#[must_use]
pub fn openapi() -> Value {
    let step_up = "The session is below AAL2 or its last authentication or step-up is older than five minutes (OP-149 m.6); step up and retry.";
    let mut paths = Map::new();
    paths.insert(
        CHALLENGES_PATH.to_owned(),
        json!({ "post": {
            "operationId": "createInstanceChallenge",
            "summary": "A single-use challenge for a device key, bound to this session, with the governing domain, basis and PEP the device's Exercises name (OP-149 m.6, m.16 (a)).",
            "parameters": [idempotency()],
            "responses": {
                "201": json_response("The challenge.", "InstanceChallenge"),
                "401": problem("No live session (session-required)."),
                "503": problem("Temporarily unavailable."),
            },
        }}),
    );
    paths.insert(
        INSTANCES_PATH.to_owned(),
        json!({ "post": {
            "operationId": "registerInstance",
            "summary": "Registers the device key as an Instance of the user's Party with the device's own instance_create, and party_register for a new Party (OP-149 m.6, m.16 (a), L0-META-7). Access binds the key to the session's Party and forwards the Exercises. The challenge is used up by any answer.",
            "parameters": [idempotency()],
            "requestBody": body("InstanceRegistration", true),
            "responses": {
                "201": json_response("The Instance and its kid.", "InstanceRegistered"),
                "400": problem("invalid-challenge, invalid-instance-key, invalid-proof-of-possession, invalid-party or invalid-request."),
                "401": problem("No live session (session-required)."),
                "403": problem(step_up),
                "409": problem("The session already has an active device Instance (instance-exists; INV-13: one per session and realm), or the authority plane did not open the Instance (instance-not-registered)."),
                "503": problem("Temporarily unavailable."),
            },
        }}),
    );
    paths.insert(
        INSTANCE_PATH.to_owned(),
        json!({
            "parameters": [{
                "name": "instance",
                "in": "path",
                "required": true,
                "description": "InstanceID, base64url of its 16 bytes (ADP JSON encoding, OP-149 m.16 (f)).",
                "schema": { "type": "string", "pattern": "^[A-Za-z0-9_-]{22}$" },
            }],
            "delete": {
                "operationId": "terminateInstance",
                "summary": "Ends a device Instance with an instance_terminate the user's own Instance signed (OP-149 m.6, OP-146 m.4 (i)); Access forwards it as PEP.",
                "parameters": [idempotency()],
                "requestBody": body("InstanceTermination", true),
                "responses": {
                    "200": json_response("Recorded.", "InstanceTerminated"),
                    "400": problem("invalid-request."),
                    "401": problem("No live session (session-required)."),
                    "403": problem(step_up),
                    "409": problem("Denied or refused by the authority plane (instance-not-terminated)."),
                    "503": problem("Temporarily unavailable."),
                },
            },
        }),
    );
    paths.insert(
        AUTH_CONTEXT_PATH.to_owned(),
        json!({ "post": {
            "operationId": "issueAuthContext",
            "summary": "The session's auth_context artifact, signed by the realm's identity signer key (OP-149 m.8).",
            "parameters": [idempotency()],
            "requestBody": body("AuthContextRequest", false),
            "responses": {
                "200": json_response("The signed artifact and its digest.", "AuthContextIssued"),
                "400": problem("invalid-content or invalid-request."),
                "401": problem("No live session (session-required)."),
                "503": problem("Temporarily unavailable."),
            },
        }}),
    );
    paths.insert(APPROVE_PATH.to_owned(), approve());
    super::approval::paths(&mut paths);
    let mut schemas = components();
    if let (Some(all), Some(extra)) = (
        schemas.as_object_mut(),
        super::approval::components().as_object(),
    ) {
        for (k, v) in extra {
            all.insert(k.clone(), v.clone());
        }
    }
    json!({
        "openapi": "3.1.1",
        "info": {
            "title": "Access Frontend API: device Instances, auth_context and approval",
            "version": format!("{CONTRACT_VERSION}"),
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
        },
        "paths": paths,
        "components": { "schemas": schemas },
    })
}

fn approve() -> Value {
    let q = |name: &str, description: &str| {
        json!({
            "name": name,
            "in": "query",
            "required": true,
            "description": description,
            "schema": { "type": "string" },
        })
    };
    json!({ "get": {
            "operationId": "approve",
            "summary": "The approval call (OP-149 m.9, OP-150 m.3 (r)): the hosted Approval Surface for a request pushed to POST /v1/approve/requests; the page shows the render the decision point produced, takes one passkey assertion over H(AAS) and sends the browser back to redirect_uri with exercise, render_digest and state; the result is confirmed with GET /access/v1/exercises/{id}.",
            "parameters": [
                q("request", "The authority request's digest (base64url, 32 bytes) or a pushed request_uri (urn:ietf:params:oauth:request_uri:…)."),
                q("redirect_uri", "Exactly a redirect URI an active client of the realm registered."),
                q("state", "1 to 512 printable ASCII characters, echoed unchanged."),
            ],
            "responses": {
                "200": { "description": "The hosted approval page (text/html), which opens the flow with POST /v1/approve/flows and, once approved, goes to redirect_uri?exercise=<base64url ExerciseID>&render_digest=<base64url>&state=<state>." },
                "400": problem("invalid-approval-request, invalid-state or invalid-redirect-uri; the browser is not redirected."),
                "404": problem("approval-request-unknown: nothing was pushed under this request, or it expired."),
                "503": problem("Temporarily unavailable."),
            },
    }})
}

#[cfg(test)]
mod tests;
