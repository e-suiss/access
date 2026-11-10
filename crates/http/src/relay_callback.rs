//! Relay's report of an İYS consent record (`POST /relay/v1/iys-status`, OP-156 m.3 (c),
//! IDP-37 (4), B23): Relay registered, or could not register, the record it received as
//! `relay.message.iys_consent.v1`. The caller is Relay's platform product client, by the
//! RFC 7523 assertion it signs (E42 (2), OP-149 m.19 (e)), under the product name the operator
//! configured for Relay; any other caller, or every caller without that name, is refused. The
//! report changes no preference and no authority; it is kept beside the record and shown to the
//! person.

use std::future::Future;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use std::sync::Arc;

use crate::Problem;
use crate::product::ports::{AssertionRefused, ClientAssertions};

/// The route.
pub const PATH: &str = "/relay/v1/iys-status";

/// Largest report.
const MAX_BODY: usize = 4 * 1024;

/// What Relay says about one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// İYS has the record.
    Recorded,
    /// İYS refused it, or Relay gave up; Relay keeps trying unless the reason says otherwise.
    Failed,
}

impl Status {
    /// Its wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Failed => "failed",
        }
    }
}

/// One report, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The tenant's external id (`tnt_`).
    pub tenant: String,
    /// The realm's id.
    pub realm: [u8; 16],
    /// The record: the `CloudEvents` id of its Relay message.
    pub record: [u8; 16],
    /// The state.
    pub status: Status,
    /// Why it failed, a short lower-case code.
    pub reason: Option<String>,
    /// When Relay says it happened, Unix ms.
    pub at_ms: u64,
}

/// What became of a report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept {
    /// Kept.
    Kept,
    /// No such record in that realm.
    NoRecord,
}

/// The reports could not be kept now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("iys reports unavailable")]
pub struct Unavailable;

/// Keeps reports (OP-63).
pub trait IysReports: Send + Sync {
    /// Keeps `report` beside its record.
    fn keep(&self, report: &Report) -> impl Future<Output = Result<Kept, Unavailable>> + Send;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    tenant: String,
    realm: String,
    record: String,
    status: String,
    #[serde(default)]
    reason: Option<String>,
    at: u64,
}

fn uuid(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if s.len() != 36 || hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn reason_ok(r: &str) -> bool {
    (1..=64).contains(&r.len())
        && r.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// The report a body carries.
///
/// # Errors
/// `None` for a malformed one.
#[must_use]
pub fn parse(body: &[u8]) -> Option<Report> {
    let b: Body = serde_json::from_slice(body).ok()?;
    let status = match b.status.as_str() {
        "recorded" => Status::Recorded,
        "failed" => Status::Failed,
        _ => return None,
    };
    if b.reason.as_deref().is_some_and(|r| !reason_ok(r))
        || (status == Status::Recorded && b.reason.is_some())
        || !b.tenant.starts_with("tnt_")
        || b.tenant.len() > 64
    {
        return None;
    }
    Some(Report {
        tenant: b.tenant,
        realm: uuid(&b.realm)?,
        record: uuid(&b.record)?,
        status,
        reason: b.reason,
        at_ms: b.at,
    })
}

struct Shared<A, R> {
    assertions: A,
    reports: R,
    api_base: String,
    relay: Option<String>,
}

/// The route over the platform clients' `assertions` and the `reports` store; `api_base` is
/// the public origin an assertion names as its audience, `relay` the product name of Relay's
/// platform client.
pub fn router<A, R>(assertions: A, reports: R, api_base: String, relay: Option<String>) -> Router
where
    A: ClientAssertions + 'static,
    R: IysReports + 'static,
{
    Router::new()
        .route(PATH, post(report::<A, R>))
        .with_state(Arc::new(Shared {
            assertions,
            reports,
            api_base,
            relay,
        }))
}

fn problem(status: StatusCode, code: &'static str, title: &'static str) -> Response {
    Problem::new(status, code, title).into_response()
}

async fn report<A: ClientAssertions, R: IysReports>(
    State(s): State<Arc<Shared<A, R>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(assertion) = crate::platform::bearer(&headers) else {
        let mut r = problem(
            StatusCode::UNAUTHORIZED,
            "client-unauthenticated",
            "Unauthorized",
        );
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer error=\"invalid_token\""),
        );
        return r;
    };
    let endpoint = format!("{}{PATH}", s.api_base);
    let client = match s.assertions.authenticate(assertion, &endpoint).await {
        Ok(c) => c,
        Err(AssertionRefused::Unauthenticated) => {
            return problem(
                StatusCode::UNAUTHORIZED,
                "client-unauthenticated",
                "Unauthorized",
            );
        }
        Err(AssertionRefused::Unavailable) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Service Unavailable",
            );
        }
    };
    // E42 (2), B23
    if s.relay.as_deref() != Some(client.product.as_str()) {
        return problem(StatusCode::FORBIDDEN, "not-relay", "Forbidden");
    }
    if body.len() > MAX_BODY {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body-too-large",
            "Payload Too Large",
        );
    }
    let Some(r) = parse(&body) else {
        return problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request");
    };
    match s.reports.keep(&r).await {
        Ok(Kept::Kept) => StatusCode::NO_CONTENT.into_response(),
        Ok(Kept::NoRecord) => problem(StatusCode::NOT_FOUND, "not-found", "Not Found"),
        Err(Unavailable) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Service Unavailable",
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-156 m.3 (c)
    #[test]
    fn a_report_parses_only_in_its_one_shape() {
        let ok = br#"{"tenant":"tnt_x","realm":"01234567-89ab-cdef-0123-456789abcdef","record":"01234567-89ab-4def-8123-456789abcdef","status":"failed","reason":"quota","at":5}"#;
        let r = parse(ok).unwrap();
        assert_eq!(r.status, Status::Failed);
        assert_eq!(r.reason.as_deref(), Some("quota"));
        for bad in [
            &br#"{"tenant":"tnt_x","realm":"x","record":"01234567-89ab-4def-8123-456789abcdef","status":"failed","at":5}"#[..],
            br#"{"tenant":"tnt_x","realm":"01234567-89ab-cdef-0123-456789abcdef","record":"01234567-89ab-4def-8123-456789abcdef","status":"recorded","reason":"x","at":5}"#,
            br#"{"tenant":"tnt_x","realm":"01234567-89ab-cdef-0123-456789abcdef","record":"01234567-89ab-4def-8123-456789abcdef","status":"done","at":5}"#,
            br#"{"tenant":"x","realm":"01234567-89ab-cdef-0123-456789abcdef","record":"01234567-89ab-4def-8123-456789abcdef","status":"recorded","at":5}"#,
            br#"{"tenant":"tnt_x","realm":"01234567-89ab-cdef-0123-456789abcdef","record":"01234567-89ab-4def-8123-456789abcdef","status":"recorded","at":5,"address":"a@b"}"#,
        ] {
            assert!(parse(bad).is_none(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
