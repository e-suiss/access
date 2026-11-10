//! The verifier's HTTP surface, `/vc-verifier/v1/*` (OP-155 m.3 (p); contract in
//! [`crate::contract`]). Opening a request and reading its outcome need a configured caller key
//! as `Authorization: Bearer`; the wallet's routes are open, as OID4VP makes them, and are bound
//! to the request by its random id, nonce and state.

use std::sync::Arc;

use access_kernel::json::b64url_decode;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};
use suiss_crypto::signer::Signer;

use crate::app::{Open, Verifier, VerifierError};
use crate::domain::request::Mode;
use crate::ports::{Access, Clock, Fetch, Random};

/// The router's state.
type Shared<A, F, C, R, S> = State<Arc<Verifier<A, F, C, R, S>>>;

/// Largest request body.
pub const MAX_BODY: usize = 512 * 1024;

/// An RFC 9457 problem.
#[must_use]
pub fn problem(status: StatusCode, code: &str) -> Response {
    let body = json!({
        "type": format!("urn:suiss:access:problem:{code}"),
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "code": code,
    });
    let mut r = (status, body.to_string()).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn failed(e: &VerifierError) -> Response {
    let status = match e {
        VerifierError::Malformed(_) => StatusCode::BAD_REQUEST,
        VerifierError::Caller => StatusCode::UNAUTHORIZED,
        VerifierError::Unknown => StatusCode::NOT_FOUND,
        VerifierError::Expired => StatusCode::GONE,
        VerifierError::Answered => StatusCode::CONFLICT,
        VerifierError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    problem(status, &e.code())
}

fn ok(status: StatusCode, v: &Value) -> Response {
    let mut r = (status, v.to_string()).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn bearer(h: &HeaderMap) -> &str {
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}

fn pct_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = char::from(bytes.next()?).to_digit(16)?;
                let lo = char::from(bytes.next()?).to_digit(16)?;
                out.push(u8::try_from(hi.checked_mul(16)?.checked_add(lo)?).ok()?);
            }
            b => out.push(b),
        }
    }
    String::from_utf8(out).ok()
}

/// The value of `name` in an `application/x-www-form-urlencoded` body or query; `None` when it
/// is absent or given twice.
#[must_use]
pub fn form_value(body: &str, name: &str) -> Option<String> {
    let mut found = None;
    for pair in body.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if pct_decode(k)? == name {
            if found.is_some() {
                return None;
            }
            found = Some(pct_decode(v)?);
        }
    }
    found
}

fn open_body(body: &[u8]) -> Result<Open, VerifierError> {
    let v: Value = serde_json::from_slice(body).map_err(|_| VerifierError::Malformed("body"))?;
    let o = v.as_object().ok_or(VerifierError::Malformed("body"))?;
    if o.keys().any(|k| {
        !matches!(
            k.as_str(),
            "domain" | "subject" | "dcql_query" | "mode" | "return_uri"
        )
    }) {
        return Err(VerifierError::Malformed("body"));
    }
    let domain: [u8; 32] = o
        .get("domain")
        .and_then(Value::as_str)
        .and_then(|d| d.strip_prefix("sha-256:"))
        .and_then(|d| b64url_decode(d).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifierError::Malformed("domain"))?;
    let subject: [u8; 16] = o
        .get("subject")
        .and_then(Value::as_str)
        .and_then(|d| b64url_decode(d).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifierError::Malformed("subject"))?;
    let mode = o
        .get("mode")
        .and_then(Value::as_str)
        .and_then(Mode::parse)
        .ok_or(VerifierError::Malformed("mode"))?;
    let return_uri = match o.get("return_uri") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(VerifierError::Malformed("return-uri")),
    };
    Ok(Open {
        domain,
        subject,
        query: o
            .get("dcql_query")
            .cloned()
            .ok_or(VerifierError::Malformed("dcql-malformed"))?,
        mode,
        return_uri,
    })
}

/// The service's routes.
pub fn router<A, F, C, R, S>(v: Arc<Verifier<A, F, C, R, S>>) -> Router
where
    A: Access + 'static,
    F: Fetch + 'static,
    C: Clock + 'static,
    R: Random + 'static,
    S: Signer + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/vc-verifier/v1/presentations",
            post(
                async |State(v): Shared<A, F, C, R, S>, h: HeaderMap, body: Bytes| {
                    if body.len() > MAX_BODY {
                        return problem(StatusCode::PAYLOAD_TOO_LARGE, "body-too-large");
                    }
                    if let Err(e) = v.authenticate(bearer(&h)) {
                        return failed(&e);
                    }
                    let opened = match open_body(&body) {
                        Ok(o) => v.open(bearer(&h), o).await,
                        Err(e) => Err(e),
                    };
                    match opened {
                        Ok(o) => ok(
                            StatusCode::OK,
                            &json!({
                                "request": o.request,
                                "request_uri": o.request_uri,
                                "wallet_link": o.wallet_link,
                                "expires_ms": o.expires_ms,
                            }),
                        ),
                        Err(e) => failed(&e),
                    }
                },
            ),
        )
        .route(
            "/vc-verifier/v1/requests/{request}",
            get(
                async |State(v): Shared<A, F, C, R, S>, Path(id): Path<String>| match v
                    .request_object(&id)
                    .await
                {
                    Ok(jwt) => {
                        let mut r = (StatusCode::OK, jwt).into_response();
                        r.headers_mut().insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/oauth-authz-req+jwt"),
                        );
                        r.headers_mut()
                            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                        r
                    }
                    Err(e) => failed(&e),
                },
            ),
        )
        .route(
            "/vc-verifier/v1/responses/{request}",
            post(
                async |State(v): Shared<A, F, C, R, S>, Path(id): Path<String>, body: Bytes| {
                    if body.len() > MAX_BODY {
                        return problem(StatusCode::PAYLOAD_TOO_LARGE, "body-too-large");
                    }
                    let Some(response) = std::str::from_utf8(&body)
                        .ok()
                        .and_then(|b| form_value(b, "response"))
                    else {
                        return problem(StatusCode::BAD_REQUEST, "response-malformed");
                    };
                    match v.respond(&id, &response).await {
                        Ok(Some(uri)) => ok(StatusCode::OK, &json!({ "redirect_uri": uri })),
                        Ok(None) => ok(StatusCode::OK, &json!({})),
                        Err(e) => failed(&e),
                    }
                },
            ),
        )
        .route(
            "/vc-verifier/v1/presentations/{request}",
            get(
                async |State(v): Shared<A, F, C, R, S>,
                       h: HeaderMap,
                       Path(id): Path<String>,
                       RawQuery(q): RawQuery| {
                    let code = q.as_deref().and_then(|q| form_value(q, "response_code"));
                    match v.result(bearer(&h), &id, code.as_deref()).await {
                        Ok(body) => ok(StatusCode::OK, &body),
                        Err(e) => failed(&e),
                    }
                },
            ),
        )
        .route(
            "/vc-verifier/v1/trusted-lists",
            get(async |State(v): Shared<A, F, C, R, S>| ok(StatusCode::OK, &v.list_state())),
        )
        .with_state(v)
}
