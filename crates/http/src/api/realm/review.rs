//! A reviewer's keep of one campaign item (OP-157 m.3 (w), m.6 (a), LFP-18): a write signed with
//! the reviewer's own AIS over the keep digest, recorded as `review.kept` in the identity audit.
//! It is no Exercise and writes no authority; removing an item is the reviewer's own
//! `grant.revoke`, one per item.

use access_kernel::json::b64url_encode;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
use suiss_crypto::digest::context_digest;

use super::handlers::slug;
use crate::api::app::{Caller, Ctx};
use crate::api::ports::{Env, ReviewKeep};
use crate::problem::{Code, codes};

/// Context of a keep digest, the intent the reviewer's AIS signs.
pub const CONTEXT: &str = "access/review-keep/v1";

/// The keep digest of `grant` in campaign `review`: `context_digest("access/review-keep/v1",
/// dCBOR([review, grant]))`.
///
/// # Errors
/// `internal` when it does not encode.
pub fn digest(review: &str, grant: &str) -> Result<[u8; 32], &'static Code> {
    let v = Cbor::Array(vec![Cbor::text(review), Cbor::text(grant)]);
    let bytes = dcbor::encode(&v, Limits::CEILING).map_err(|_| &codes::INTERNAL)?;
    Ok(context_digest(CONTEXT, &bytes).0)
}

fn split(key: &str) -> Result<(&str, &str), &'static Code> {
    key.split_once(':')
        .filter(|(r, g)| !r.is_empty() && !g.is_empty() && !g.contains(':'))
        .ok_or(&codes::NOT_FOUND)
}

/// `POST …/intents` for `keepReviewItem`: the digest the reviewer's AIS signs (TN-110).
///
/// # Errors
/// `invalid-body` without `key` (`review:grant`).
pub(super) fn draft<E: Env>(
    ctx: &Ctx<E>,
    operation: &'static str,
    mut request: Map<String, Value>,
) -> Result<Response, &'static Code> {
    let Some(Value::String(key)) = request.remove("key") else {
        return Err(&codes::realm::INVALID_BODY);
    };
    let (review, grant) = split(&key).map_err(|_| &codes::realm::INVALID_BODY)?;
    let d = digest(review, grant)?;
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "operation": operation,
            "key": key,
            "body": {},
            "domain": b64url_encode(&ctx.domain.0),
            "intent_digest": b64url_encode(&d),
        })),
    )
        .into_response())
}

/// `POST …/reviews/{review}/items/{item}/keep` (OP-157 m.3 (w), m.6 (a)).
///
/// # Errors
/// `ais-required` without the reviewer's AIS; `job-intent-mismatch` for an AIS over another
/// digest; `404` for an item that is not one of the signer's.
pub(super) async fn keep<E: Env>(
    ctx: &Ctx<E>,
    key: &str,
    raw: &[u8],
) -> Result<Response, &'static Code> {
    let Caller::Write(reviewer) = &ctx.caller else {
        return Err(&codes::AIS_REQUIRED);
    };
    let mut body = super::handlers::object(raw)?;
    body.remove(crate::api::domain::caller::AIS_FIELD);
    if !body.is_empty() {
        return Err(&codes::realm::INVALID_BODY);
    }
    let (review, grant) = split(key)?;
    // TN-110
    if reviewer.statement.intent.0 != digest(review, grant)? {
        return Err(&codes::realm::JOB_INTENT_MISMATCH);
    }
    let kept = ctx
        .api
        .env()
        .realm()
        .keep_review(ReviewKeep {
            slug: slug(ctx),
            review: review.to_owned(),
            grant: grant.to_owned(),
            kid: reviewer.kid,
        })
        .await
        .map_err(|_| &codes::UNAVAILABLE)?;
    match kept {
        Some(true) => Ok((
            StatusCode::OK,
            axum::Json(json!({ "review": review, "grant": grant, "kept": true })),
        )
            .into_response()),
        _ => Err(&codes::NOT_FOUND),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-157 m.3 (w), m.6 (a)
    #[test]
    fn a_keep_signs_its_campaign_and_grant() {
        let d = digest("q4", "Zm9v").unwrap();
        assert_ne!(d, digest("q4", "YmFy").unwrap());
        assert_ne!(d, digest("q5", "Zm9v").unwrap());
        assert_eq!(split("q4:Zm9v").unwrap(), ("q4", "Zm9v"));
        assert!(split("q4").is_err());
        assert!(split("q4:a:b").is_err());
    }
}
