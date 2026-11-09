//! RFC 9457 Problem Details (OP-64 rule 5). Internal details never reach the body.

use std::any::Any;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Prefix of every problem type URI (OP-149 m.12).
pub const TYPE_PREFIX: &str = "urn:suiss:access:problem:";

/// Codes whose response means no more than its HTTP status; their `type` stays
/// `about:blank` (OP-149 m.12).
pub const BARE: [&str; 3] = ["not-found", "internal", "unavailable"];

/// One part of a request a problem is about (RFC 9457 §3): the stable code of what is wrong
/// and, when the body names it, where.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldError {
    /// A JSON Pointer (RFC 6901) into the request body, as a URI fragment (`#/set/basis`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// The stable code of what is wrong there.
    pub code: &'static str,
}

/// An RFC 9457 problem response.
///
/// `type` is `urn:suiss:access:problem:<code>` for the stable code, which also travels in the
/// `code` extension member; a [`BARE`] code keeps `about:blank` (OP-149 m.12). The `reason`
/// extension member narrows the code with a stable, non-secret reason, and `errors` names the
/// parts of the request a protocol problem is about; neither carries request values.
#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    type_uri: String,
    title: &'static str,
    status: u16,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<FieldError>,
    #[serde(skip)]
    status_code: StatusCode,
}

impl Problem {
    /// Creates a problem with a stable `code` (named by the `type` URI) and a short title.
    #[must_use]
    pub fn new(status: StatusCode, code: &'static str, title: &'static str) -> Self {
        Self {
            type_uri: type_uri(code),
            title,
            status: status.as_u16(),
            code,
            reason: None,
            errors: Vec::new(),
            status_code: status,
        }
    }

    /// With a stable, non-secret `reason` that narrows the code.
    #[must_use]
    pub const fn with_reason(mut self, reason: Option<&'static str>) -> Self {
        self.reason = reason;
        self
    }

    /// With the parts of the request it is about.
    #[must_use]
    pub fn with_errors(mut self, errors: Vec<FieldError>) -> Self {
        self.errors = errors;
        self
    }
}

impl From<&Code> for Problem {
    fn from(c: &Code) -> Self {
        Self::new(
            StatusCode::from_u16(c.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            c.code,
            c.title,
        )
    }
}

/// One stable problem code of the catalogue (OP-65, OP-149 m.12): what it means, its status and
/// title. A code names a condition, never whether a resource the caller may not see exists
/// (TN-113): a hidden resource is [`codes::NOT_FOUND`] like a missing one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code {
    /// The stable code.
    pub code: &'static str,
    /// Its HTTP status.
    pub status: u16,
    /// Its title.
    pub title: &'static str,
    /// What it means, for the published catalogue.
    pub description: &'static str,
}

impl Code {
    /// The problem response of this code.
    #[must_use]
    pub fn problem(&self) -> Problem {
        Problem::from(self)
    }
}

/// The stable codes of the shared HTTP stack and the management API
/// (`sdks/openapi/problems.json`). To add one, add a constant here and list it in [`CODES`].
pub mod codes {
    use super::Code;

    pub mod platform;
    pub mod realm;

    const fn code(
        code: &'static str,
        status: u16,
        title: &'static str,
        description: &'static str,
    ) -> Code {
        Code {
            code,
            status,
            title,
            description,
        }
    }

    /// No such resource, or one the caller may not see (TN-113).
    pub const NOT_FOUND: Code = code(
        "not-found",
        404,
        "Not Found",
        "No such resource, or one the caller may not see (TN-113).",
    );
    /// A server failure; details stay in the logs.
    pub const INTERNAL: Code = code(
        "internal",
        500,
        "Internal Server Error",
        "A server failure; details stay in the logs.",
    );
    /// A dependency is unavailable; nothing was decided (MD-8).
    pub const UNAVAILABLE: Code = code(
        "unavailable",
        503,
        "Service Unavailable",
        "A dependency is unavailable; nothing was decided or changed (MD-8).",
    );
    /// A declared route its lane does not serve yet; nothing was read or changed (OP-153 m.4).
    pub const NOT_YET_SERVED: Code = code(
        "not-yet-served",
        501,
        "Not Implemented",
        "The route is declared in the Frontend API and not served yet; nothing was read or changed (OP-153 m.4).",
    );
    /// The request path is not in its one canonical spelling (TN-113).
    pub const PATH_NOT_CANONICAL: Code = code(
        "path-not-canonical",
        400,
        "Bad Request",
        "The request path is not in its one canonical spelling (TN-113).",
    );
    /// The body exceeds the route's limit.
    pub const BODY_TOO_LARGE: Code = code(
        "body-too-large",
        413,
        "Payload Too Large",
        "The request body exceeds the limit (R-5).",
    );
    /// The method is not served on this path.
    pub const METHOD_NOT_ALLOWED: Code = code(
        "method-not-allowed",
        405,
        "Method Not Allowed",
        "The method is not served on this path.",
    );
    /// A rate limit was reached (TN-127).
    pub const RATE_LIMITED: Code = code(
        "rate-limited",
        429,
        "Too Many Requests",
        "A rate limit was reached; the RateLimit and Retry-After headers say when to retry (TN-127).",
    );
    /// A mutating request without `Idempotency-Key` (TN-126).
    pub const IDEMPOTENCY_KEY_REQUIRED: Code = code(
        "idempotency-key-required",
        400,
        "Bad Request",
        "A mutating request carries no Idempotency-Key (TN-126).",
    );
    /// The key is empty, longer than 255 characters or not visible ASCII (TN-126).
    pub const IDEMPOTENCY_KEY_INVALID: Code = code(
        "idempotency-key-invalid",
        400,
        "Bad Request",
        "The Idempotency-Key is empty, longer than 255 characters or not visible ASCII (TN-126).",
    );
    /// A write's key is not its AIS nonce (TN-126).
    pub const IDEMPOTENCY_KEY_NOT_NONCE: Code = code(
        "idempotency-key-not-nonce",
        400,
        "Bad Request",
        "The Idempotency-Key of a write is its AIS nonce, unpadded base64url (TN-126).",
    );
    /// The key already ran another request (TN-126, TI-8).
    pub const IDEMPOTENCY_KEY_REUSED: Code = code(
        "idempotency-key-reused",
        422,
        "Idempotency-Key reused with another request",
        "The Idempotency-Key already ran another request (TN-126, TI-8).",
    );
    /// The first request under the key is still running (TN-126).
    pub const IDEMPOTENCY_KEY_IN_USE: Code = code(
        "idempotency-key-in-use",
        409,
        "A request with this Idempotency-Key is still running",
        "The first request under the Idempotency-Key is still running (TN-126).",
    );
    /// An update without `If-Match` (OP-65).
    pub const PRECONDITION_REQUIRED: Code = code(
        "precondition-required",
        428,
        "Precondition Required",
        "An update must carry If-Match with the resource's ETag (OP-65).",
    );
    /// `If-Match` does not name the current version (OP-65).
    pub const PRECONDITION_FAILED: Code = code(
        "precondition-failed",
        412,
        "Precondition Failed",
        "If-Match does not name the resource's current ETag (OP-65).",
    );
    /// The `filter` is outside the SCIM subset (TN-112).
    pub const INVALID_FILTER: Code = code(
        "invalid-filter",
        400,
        "Bad Request",
        "The filter is outside the SCIM subset: eq, ne, co, sw, pr, and, or, parentheses (TN-112).",
    );
    /// The `filter` names an attribute the endpoint does not filter on (TN-112).
    pub const UNKNOWN_FILTER_ATTRIBUTE: Code = code(
        "unknown-filter-attribute",
        400,
        "Bad Request",
        "The filter names an attribute the endpoint does not filter on; it is never ignored (TN-112).",
    );
    /// The `filter` exceeds the size, depth or term limits.
    pub const FILTER_TOO_COMPLEX: Code = code(
        "filter-too-complex",
        400,
        "Bad Request",
        "The filter exceeds its size, depth or term limits (CR-10).",
    );
    /// The cursor was not issued for this list.
    pub const INVALID_CURSOR: Code = code(
        "invalid-cursor",
        400,
        "Bad Request",
        "The cursor was not issued by this list (OP-65).",
    );
    /// `page[size]` is not 1 to 100 (§13.7.4).
    pub const INVALID_PAGE_SIZE: Code = code(
        "invalid-page-size",
        400,
        "Bad Request",
        "page[size] must be an integer from 1 to 100 (§13.7.4).",
    );
    /// A query parameter the endpoint does not take.
    pub const UNKNOWN_QUERY_PARAMETER: Code = code(
        "unknown-query-parameter",
        400,
        "Bad Request",
        "A query parameter the endpoint does not take, or one given twice.",
    );
    /// The body is not a JSON Merge Patch the resource takes (RFC 7396).
    pub const INVALID_MERGE_PATCH: Code = code(
        "invalid-merge-patch",
        400,
        "Bad Request",
        "The body is not a JSON Merge Patch the resource takes (RFC 7396).",
    );
    /// The request is malformed.
    pub const INVALID_REQUEST: Code = code(
        "invalid-request",
        400,
        "Bad Request",
        "The request is malformed.",
    );
    /// No usable read token (TN-27, TN-130).
    pub const INVALID_TOKEN: Code = code(
        "invalid-token",
        401,
        "Unauthorized",
        "No usable read token: missing, bearer, malformed, expired, revoked or not holder-bound (TN-27, TN-130).",
    );
    /// The token is for another management surface (TN-119).
    pub const WRONG_AUDIENCE: Code = code(
        "wrong-audience",
        401,
        "Unauthorized",
        "The token's audience is another management surface (TN-119).",
    );
    /// The token lives longer than 60 minutes (OP-151 m.3 (c)).
    pub const TOKEN_LIFETIME: Code = code(
        "token-lifetime",
        401,
        "Unauthorized",
        "Management read tokens live at most 60 minutes (OP-151 m.3 (c)).",
    );
    /// The token lacks the route's scope (TN-113).
    pub const INSUFFICIENT_SCOPE: Code = code(
        "insufficient-scope",
        403,
        "Forbidden",
        "The token lacks the route's scope (TN-113).",
    );
    /// A write without an AIS (TN-110, TN-130).
    pub const AIS_REQUIRED: Code = code(
        "ais-required",
        401,
        "Unauthorized",
        "A write carries the caller's AIS; no token writes (TN-110, TN-130).",
    );
    /// The AIS is not a well-formed statement (PI-7).
    pub const AIS_INVALID: Code = code(
        "ais-invalid",
        401,
        "Unauthorized",
        "The AIS is not a well-formed, signed actor intent statement (PI-7).",
    );
    /// The AIS does not verify with a live Instance key of the surface's domain (PI-7).
    pub const AIS_REJECTED: Code = code(
        "ais-rejected",
        403,
        "Forbidden",
        "The AIS does not verify with a live Instance key of this surface's domain, or names another domain or mode (PI-7, TN-119).",
    );
    /// The Exercise was decided and not allowed (OP-64: a decision, not an error).
    pub const EXERCISE_NOT_ALLOWED: Code = code(
        "exercise-not-allowed",
        403,
        "Forbidden",
        "The Exercise the write compiled to was decided and not allowed; nothing changed (TN-110).",
    );
    /// The Exercise was refused before a decision (§9.5).
    pub const EXERCISE_REFUSED: Code = code(
        "exercise-refused",
        400,
        "Bad Request",
        "The Exercise the write compiled to was refused before a decision; nothing changed (TN-110).",
    );
}

/// Every stable code, in catalogue order; `sdks/openapi/problems.json` is generated from it.
pub const CODES: &[Code] = &[
    codes::NOT_FOUND,
    codes::INTERNAL,
    codes::UNAVAILABLE,
    codes::NOT_YET_SERVED,
    codes::PATH_NOT_CANONICAL,
    codes::BODY_TOO_LARGE,
    codes::METHOD_NOT_ALLOWED,
    codes::RATE_LIMITED,
    codes::IDEMPOTENCY_KEY_REQUIRED,
    codes::IDEMPOTENCY_KEY_INVALID,
    codes::IDEMPOTENCY_KEY_NOT_NONCE,
    codes::IDEMPOTENCY_KEY_REUSED,
    codes::IDEMPOTENCY_KEY_IN_USE,
    codes::PRECONDITION_REQUIRED,
    codes::PRECONDITION_FAILED,
    codes::INVALID_FILTER,
    codes::UNKNOWN_FILTER_ATTRIBUTE,
    codes::FILTER_TOO_COMPLEX,
    codes::INVALID_CURSOR,
    codes::INVALID_PAGE_SIZE,
    codes::UNKNOWN_QUERY_PARAMETER,
    codes::INVALID_MERGE_PATCH,
    codes::INVALID_REQUEST,
    codes::INVALID_TOKEN,
    codes::WRONG_AUDIENCE,
    codes::TOKEN_LIFETIME,
    codes::INSUFFICIENT_SCOPE,
    codes::AIS_REQUIRED,
    codes::AIS_INVALID,
    codes::AIS_REJECTED,
    codes::EXERCISE_NOT_ALLOWED,
    codes::EXERCISE_REFUSED,
    codes::realm::INVALID_BODY,
    codes::realm::INVALID_VALIDITY,
    codes::realm::INVALID_CLIENT_ID,
    codes::realm::INVALID_DISPLAY_NAME,
    codes::realm::INVALID_REDIRECT_URI,
    codes::realm::INVALID_JWKS_URI,
    codes::realm::INVALID_HOST,
    codes::realm::RESERVED_CLAIM,
    codes::realm::INVALID_ATTRIBUTE,
    codes::realm::ARGON2_LOWERED,
    codes::realm::INVALID_RP_ID,
    codes::realm::PLATFORM_FIELDS_READ_ONLY,
    codes::realm::INVALID_PUBLIC_KEY,
    codes::realm::INVALID_EVENT_RECEIVER,
    codes::realm::INVALID_BRANDING,
    codes::realm::INVALID_RELATED_ORIGINS,
    codes::realm::INVALID_LOCALE_OVERRIDES,
    codes::realm::INVALID_KEY_POLICY,
    codes::realm::INVALID_NAME,
    codes::realm::INVALID_MEMBERSHIP_ISSUER,
    codes::realm::INVALID_MEMBERS,
    codes::realm::INVALID_UPSTREAM,
    codes::realm::INVALID_UPSTREAM_SUBJECT,
    codes::realm::UPSTREAM_SUBJECT_LINKED,
    codes::realm::INVALID_SIGNIN_POLICY,
    codes::realm::INVALID_SESSION_POLICY,
    codes::realm::RESOURCE_EXISTS,
    codes::realm::MEMBERSHIP_ISSUED_UPSTREAM,
    codes::realm::ACCOUNT_STATE_CONFLICT,
    codes::realm::CLIENT_HAS_NO_SECRET,
    codes::realm::PASSKEY_LOSS_NOT_ACKNOWLEDGED,
    codes::realm::CONFLICT,
    codes::realm::UNKNOWN_OPERATION,
    codes::platform::INVALID_SLUG,
    codes::platform::INVALID_PLACEMENT,
    codes::platform::INVALID_ROOT,
    codes::platform::RECOVERY_NOT_ACKNOWLEDGED,
    codes::platform::INVALID_TIME_LOCK,
    codes::platform::SLUG_TAKEN,
    codes::realm::PUBLIC_SUB_NOT_OPTED_IN,
    codes::realm::INVALID_SECTOR_IDENTIFIER_URI,
    codes::realm::RESERVED_OPERATION,
    codes::realm::INVALID_JOSE_ALG,
    codes::realm::INVALID_PROTECTION_MODE,
    codes::realm::INVALID_JOB,
    codes::realm::JOB_OPERATION_NOT_ALLOWED,
    codes::realm::JOB_INTENT_MISMATCH,
    codes::realm::FAILED_DEPENDENCY,
    codes::realm::INVALID_EXTENSION_TARGET,
    codes::realm::INVALID_HOOK,
    codes::realm::DISCLOSURE_NOT_PERMITTED,
    codes::realm::INVALID_WEBHOOK_EVENTS,
    codes::realm::INVALID_EXTENSION_POLICY,
    codes::realm::HOOK_POINT_TAKEN,
    codes::realm::CATALOG_UPGRADE_REQUIRED,
    codes::realm::LAST_OWNER,
    codes::realm::INVALID_AGENT,
    codes::realm::INVALID_AGENT_TEMPLATE,
    codes::realm::INVALID_WORKLOAD_CLIENT,
    codes::realm::INVALID_VAULT_RESOURCE,
    codes::realm::INVALID_PROTECTED_RESOURCE,
    codes::realm::INVALID_DCR_POLICY,
    codes::realm::INVALID_CROSS_APP_CONNECTION,
    codes::realm::INVALID_RECOVERY_POLICY,
    codes::realm::RECOVERY_OPTION_OFF,
    codes::realm::SELF_ISSUE_REFUSED,
    codes::realm::NOT_AN_ORGANIZATION,
    codes::realm::INVALID_INVITATION,
    codes::realm::HRD_NEEDS_VERIFIED_DOMAIN,
    codes::realm::INVALID_SOCIAL_PROVIDER,
    codes::realm::SHARED_SOCIAL_KEY_IN_PRODUCTION,
    codes::realm::RECOVERY_GRACE,
    codes::realm::INVALID_DOMAIN_CLAIM,
    codes::realm::CONSUMER_DOMAIN,
    codes::realm::DOMAIN_CONTESTED,
    codes::realm::DOMAIN_NOT_VERIFIED,
    codes::realm::INVALID_CONNECTION_DRAFT,
    codes::realm::INVALID_AUDIT_FORMAT,
    codes::realm::OWNER_ONLY,
    codes::realm::HANDOVER_WAITING,
    codes::realm::NOT_THE_HANDOVER,
];

/// The type URI of `code`.
#[must_use]
pub fn type_uri(code: &str) -> String {
    if BARE.contains(&code) {
        String::from("about:blank")
    } else {
        format!("{TYPE_PREFIX}{code}")
    }
}

/// The catalogue as published in `sdks/openapi/problems.json`.
#[must_use]
pub fn catalogue() -> serde_json::Value {
    let codes: Vec<serde_json::Value> = CODES
        .iter()
        .map(|c| {
            serde_json::json!({
                "code": c.code,
                "type": type_uri(c.code),
                "status": c.status,
                "title": c.title,
                "description": c.description,
            })
        })
        .collect();
    serde_json::json!({
        "title": "Access problem codes",
        "description": "Stable RFC 9457 problem codes of the shared HTTP stack and the management API (OP-65, OP-149 m.12).",
        "type_prefix": TYPE_PREFIX,
        "codes": codes,
    })
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&self).unwrap_or_default();
        let mut response = (self.status_code, body).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

/// Converts a caught panic into a 500 problem. The panic payload is logged, not returned.
#[allow(
    clippy::needless_pass_by_value,
    reason = "signature required by tower_http::catch_panic::ResponseForPanic"
)]
pub(crate) fn from_panic(payload: Box<dyn Any + Send + 'static>) -> Response {
    let message = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    tracing::error!(panic = %message, "request handler panicked");
    Problem::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Internal Server Error",
    )
    .into_response()
}
