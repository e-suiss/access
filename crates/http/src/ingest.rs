//! `POST /access/v1/claims:ingest` (CMP-8, §9.13): the separate Claim Ingest endpoint. The
//! caller is the client certificate the TLS layer authenticated (L1-ADP-2); an `unsigned`
//! Claim's channel is that certificate and nothing the body says. The answer is the Claim's
//! disposition, or a reasoned refusal when it does not verify (§9.13 rule 3).

use std::sync::Arc;

use access_internal_api::claims::{Carrier, ClaimIngest, ClaimSubmission, ClaimVerdict};
use access_kernel::claim::Channel;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::{Value, json};

use crate::Problem;
use crate::adp::adapters::Pep;

/// The endpoint's path.
pub const PATH: &str = "/access/v1/claims:ingest";

/// Largest request body (§14.6): the largest carrier and body, base64url, with room.
pub const MAX_BODY: usize = 256 * 1024;

/// The reason codes a refusal may carry; anything else is `claim-invalid`.
const CODES: [&str; 13] = [
    "claim-signature",
    "claim-payload",
    "claim-value",
    "claim-body",
    "claim-body-digest",
    "claim-size",
    "claim-carrier",
    "claim-carrier-event",
    "claim-carrier-context",
    "claim-issuer",
    "claim-subject",
    "domain",
    "claim-invalid",
];

fn known(code: &str) -> &'static str {
    CODES
        .into_iter()
        .find(|c| *c == code)
        .unwrap_or("claim-invalid")
}

fn bad(code: &'static str) -> Response {
    Problem::new(StatusCode::BAD_REQUEST, code, "Bad Request").into_response()
}

fn bytes(v: Option<&Value>) -> Result<Option<Vec<u8>>, &'static str> {
    v.map(|v| {
        v.as_str()
            .and_then(|s| b64url_decode(s).ok())
            .ok_or("ingest-malformed")
    })
    .transpose()
}

fn domain_of(v: Option<&Value>) -> Option<Digest> {
    crate::adp::adapters::domain_id(v?.as_str()?)
}

/// Reads a `ClaimSubmission` (the contract's `ClaimSubmission` schema); `pep` is the caller's certificate
/// thumbprint.
///
/// # Errors
/// A stable code for problem details.
pub fn decode(body: &[u8], pep: &str) -> Result<ClaimSubmission, &'static str> {
    if body.len() > MAX_BODY {
        return Err("ingest-too-large");
    }
    let v: Value = serde_json::from_slice(body).map_err(|_| "ingest-malformed")?;
    let obj = v.as_object().ok_or("ingest-malformed")?;
    if obj.keys().any(|k| {
        !matches!(
            k.as_str(),
            "domain" | "carrier" | "claim" | "body" | "evidence"
        )
    }) {
        return Err("ingest-malformed");
    }
    let domain = domain_of(obj.get("domain")).ok_or("ingest-malformed")?;
    let carrier = match obj.get("carrier").and_then(Value::as_str) {
        Some("cose") => Carrier::Cose,
        Some("webauthn") => Carrier::Webauthn,
        Some("oidc") => Carrier::Oidc,
        Some("set") => Carrier::Set,
        Some("unsigned") => {
            let thumb = b64url_decode(pep)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or("pep-unauthenticated")?;
            Carrier::Unsigned(Channel::Pep(thumb))
        }
        _ => return Err("ingest-carrier"),
    };
    let claim = bytes(obj.get("claim"))?.ok_or("ingest-malformed")?;
    let evidence = bytes(obj.get("evidence"))?
        .map(|e| <[u8; 32]>::try_from(e).map(Digest))
        .transpose()
        .map_err(|_| "ingest-malformed")?;
    Ok(ClaimSubmission {
        domain,
        carrier,
        claim,
        body: bytes(obj.get("body"))?,
        evidence,
    })
}

/// The verdict as the contract's `ClaimVerdict` schema, or the refusal as a problem.
#[must_use]
pub fn respond(v: &ClaimVerdict) -> Response {
    let body = match v {
        ClaimVerdict::Admitted {
            claim,
            position,
            replayed,
        } => json!({
            "claim": b64url_encode(&claim.0),
            "position": position.to_string(),
            "disposition": "admit",
            "replayed": replayed,
        }),
        ClaimVerdict::Quarantined {
            claim,
            position,
            reason,
        } => json!({
            "claim": b64url_encode(&claim.0),
            "position": position.to_string(),
            "disposition": "quarantine",
            "reason": reason.word(),
        }),
        ClaimVerdict::Rejected { code } => return bad(known(code)),
    };
    (StatusCode::OK, axum::Json(body)).into_response()
}

struct Shared<I> {
    ingest: I,
}

/// The ingest route over `ingest`.
pub fn router<I: ClaimIngest + 'static>(ingest: I) -> Router {
    Router::new()
        .route(PATH, post(handle::<I>))
        .with_state(Arc::new(Shared { ingest }))
}

async fn handle<I: ClaimIngest>(
    State(shared): State<Arc<Shared<I>>>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(axum::Extension(Pep(pep))) = pep else {
        return Problem::new(
            StatusCode::UNAUTHORIZED,
            "pep-unauthenticated",
            "Unauthorized",
        )
        .into_response();
    };
    // OP-65
    if headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .is_none_or(str::is_empty)
    {
        return bad("idempotency-key-required");
    }
    let submission = match decode(&body, &pep) {
        Ok(s) => s,
        Err(code) => return bad(code),
    };
    match shared.ingest.ingest(submission).await {
        Ok(v) => respond(&v),
        Err(_) => Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            access_internal_api::claims::UNAVAILABLE,
            "Service Unavailable",
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests;
