//! The SCIM server's rules with no I/O (OP-63): schemas, resource checks, the PATCH engine,
//! filters, projection, paging, tolerance profiles, discovery documents and SETs.

pub mod discovery;
pub mod filter;
pub mod patch;
pub mod project;
pub mod resource;
pub mod schema;
pub mod set;
pub mod tolerance;

use serde_json::{Value, json};

/// The SCIM error message schema (RFC 7644 §3.12).
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// The SCIM media type.
pub const MEDIA_TYPE: &str = "application/scim+json";

/// A `scimType` (RFC 7644 §3.12, RFC 9865 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScimType {
    /// The filter is outside the grammar, names an attribute it may not, or is over a limit.
    InvalidFilter,
    /// The filter would select more resources than the server returns.
    TooMany,
    /// A unique value is taken.
    Uniqueness,
    /// The request writes an attribute it may not.
    Mutability,
    /// The body is not a SCIM message of the endpoint.
    InvalidSyntax,
    /// A PATCH path is outside the grammar or the schema.
    InvalidPath,
    /// A PATCH path selects nothing it may change.
    NoTarget,
    /// A value is missing, of the wrong type or not allowed.
    InvalidValue,
    /// The SCIM protocol version is not served.
    InvalidVers,
    /// The request carries what must not travel in it.
    Sensitive,
    /// The cursor is not one this list issued (RFC 9865).
    InvalidCursor,
    /// The cursor is older than its lifetime (RFC 9865).
    ExpiredCursor,
    /// `count` is outside what the server serves (RFC 9865).
    InvalidCount,
}

impl ScimType {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidFilter => "invalidFilter",
            Self::TooMany => "tooMany",
            Self::Uniqueness => "uniqueness",
            Self::Mutability => "mutability",
            Self::InvalidSyntax => "invalidSyntax",
            Self::InvalidPath => "invalidPath",
            Self::NoTarget => "noTarget",
            Self::InvalidValue => "invalidValue",
            Self::InvalidVers => "invalidVers",
            Self::Sensitive => "sensitive",
            Self::InvalidCursor => "invalidCursor",
            Self::ExpiredCursor => "expiredCursor",
            Self::InvalidCount => "invalidCount",
        }
    }
}

/// A SCIM error answer: a refusal, never an allow (RFC 7644 §3.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("scim {status}: {detail}")]
pub struct ScimError {
    /// The HTTP status.
    pub status: u16,
    /// The `scimType`, for a 400 or a 409.
    pub scim_type: Option<ScimType>,
    /// What went wrong, without any value of the request.
    pub detail: &'static str,
}

impl ScimError {
    /// A `400` of `scim_type`.
    #[must_use]
    pub const fn bad(scim_type: ScimType, detail: &'static str) -> Self {
        Self {
            status: 400,
            scim_type: Some(scim_type),
            detail,
        }
    }

    /// `401`: no live client holds the bearer secret.
    pub const UNAUTHORIZED: Self = Self {
        status: 401,
        scim_type: None,
        detail: "Authorization failure",
    };

    /// `403`: the client may not do this.
    pub const FORBIDDEN: Self = Self {
        status: 403,
        scim_type: None,
        detail: "Operation is not permitted",
    };

    /// `404`: no such resource, now or ever, for this client (TN-76, INV-32).
    pub const NOT_FOUND: Self = Self {
        status: 404,
        scim_type: None,
        detail: "Resource not found",
    };

    /// `409 uniqueness`.
    pub const UNIQUENESS: Self = Self {
        status: 409,
        scim_type: Some(ScimType::Uniqueness),
        detail: "A unique attribute value is already in use",
    };

    /// `412`: the `If-Match` version is not the resource's.
    pub const PRECONDITION: Self = Self {
        status: 412,
        scim_type: None,
        detail: "The resource changed since the version given",
    };

    /// `413`: the body is larger than the server reads.
    pub const TOO_LARGE: Self = Self {
        status: 413,
        scim_type: None,
        detail: "The request body is too large",
    };

    /// `415`: not a SCIM media type.
    pub const MEDIA: Self = Self {
        status: 415,
        scim_type: None,
        detail: "Content-Type must be application/scim+json",
    };

    /// `501`: not served (Bulk, `/Me`, sorting).
    pub const NOT_IMPLEMENTED: Self = Self {
        status: 501,
        scim_type: None,
        detail: "Not implemented",
    };

    /// `503`: a dependency did not answer; nothing changed (MD-8).
    pub const UNAVAILABLE: Self = Self {
        status: 503,
        scim_type: None,
        detail: "Service unavailable",
    };

    /// The error message body.
    #[must_use]
    pub fn body(&self) -> Value {
        let mut v = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.to_string(),
            "detail": self.detail,
        });
        if let (Some(t), Some(o)) = (self.scim_type, v.as_object_mut()) {
            o.insert(String::from("scimType"), Value::from(t.name()));
        }
        v
    }
}

impl From<access_parse::scim::FilterError> for ScimError {
    fn from(_: access_parse::scim::FilterError) -> Self {
        Self::bad(ScimType::InvalidFilter, "The filter is invalid")
    }
}
