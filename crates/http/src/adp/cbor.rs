//! ADP CBOR (§9.5.1, OP-155 m.3 (q)): `application/access-adp+cbor` is the dCBOR of the same
//! fields as the JSON form, on every ADP route. A CBOR body is read as the JSON body it
//! stands for, so both forms decode to the same request, the same intent digest and the same
//! `DecisionRecord`; a JSON answer goes back as dCBOR when the request was CBOR or asked for it.

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Number, Value as Json};
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::Problem;

/// The ADP CBOR media type.
pub const CONTENT_TYPE: &str = "application/access-adp+cbor";

/// Why a body or an answer has no form in the other encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CborError {
    /// Not deterministic CBOR within the Access profile's limits.
    #[error("cbor: {0}")]
    Decode(&'static str),
    /// A CBOR item JSON has no form for: a byte string, a tag or a non-text map key.
    #[error("cbor-type")]
    Type,
    /// A JSON value dCBOR has no form for: a float or a `null` outside an object member.
    #[error("cbor-unrepresentable")]
    Unrepresentable,
    /// Outside the dCBOR limits.
    #[error("cbor-limits")]
    Limits,
}

impl CborError {
    /// Stable code for problem details.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Decode(code) => code,
            Self::Type => "cbor-type",
            Self::Unrepresentable => "cbor-unrepresentable",
            Self::Limits => "cbor-limits",
        }
    }
}

fn to_json(v: &Value) -> Result<Json, CborError> {
    Ok(match v {
        Value::Unsigned(u) => Json::Number(Number::from(*u)),
        Value::Negative(n) => {
            let n = i64::try_from(*n).map_err(|_| CborError::Type)?;
            Json::Number(Number::from(
                n.checked_add(1)
                    .and_then(i64::checked_neg)
                    .unwrap_or(i64::MIN),
            ))
        }
        Value::Text(t) => Json::String(t.clone()),
        Value::Bool(b) => Json::Bool(*b),
        Value::Array(items) => Json::Array(items.iter().map(to_json).collect::<Result<_, _>>()?),
        Value::Map(entries) => {
            let mut m = Map::new();
            for (k, v) in entries {
                let Value::Text(k) = k else {
                    return Err(CborError::Type);
                };
                m.insert(k.clone(), to_json(v)?);
            }
            Json::Object(m)
        }
        Value::Bytes(_) | Value::Tag(..) => return Err(CborError::Type),
    })
}

fn to_cbor(v: &Json) -> Result<Value, CborError> {
    Ok(match v {
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => match (n.as_u64(), n.as_i64()) {
            (Some(u), _) => Value::Unsigned(u),
            (None, Some(i)) => Value::int(i),
            _ => return Err(CborError::Unrepresentable),
        },
        Json::String(s) => Value::Text(s.clone()),
        Json::Array(items) => Value::Array(items.iter().map(to_cbor).collect::<Result<_, _>>()?),
        Json::Object(m) => Value::Map(
            m.iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| Ok((Value::Text(k.clone()), to_cbor(v)?)))
                .collect::<Result<_, CborError>>()?,
        ),
        Json::Null => return Err(CborError::Unrepresentable),
    })
}

/// The JSON body a dCBOR body stands for.
///
/// # Errors
/// [`CborError`] for a body that is not deterministic CBOR in the profile, or holds an item
/// JSON has no form for.
pub fn json_body(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    let v = dcbor::decode(cbor, Limits::CEILING).map_err(|e| CborError::Decode(e.code()))?;
    serde_json::to_vec(&to_json(&v)?).map_err(|_| CborError::Unrepresentable)
}

/// The dCBOR form of a JSON document; an object member whose value is `null` is absent.
///
/// # Errors
/// [`CborError`] for JSON that is not I-JSON in dCBOR's terms or exceeds its limits.
pub fn cbor_body(json: &[u8]) -> Result<Vec<u8>, CborError> {
    let v: Json = serde_json::from_slice(json).map_err(|_| CborError::Unrepresentable)?;
    dcbor::encode(&to_cbor(&v)?, Limits::CEILING).map_err(|_| CborError::Limits)
}

fn media_is(value: Option<&HeaderValue>, media: &str) -> bool {
    value.and_then(|v| v.to_str().ok()).is_some_and(|v| {
        v.split(',').any(|part| {
            part.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case(media))
        })
    })
}

fn refused(e: CborError) -> Response {
    Problem::new(StatusCode::BAD_REQUEST, e.code(), "Protocol Error").into_response()
}

/// The negotiation layer of the ADP routes: a CBOR body is read as JSON, and a JSON answer is
/// sent as dCBOR when the request was CBOR or its `Accept` names the CBOR type. Problem details
/// stay `application/problem+json`.
pub async fn negotiate(State(max_body): State<usize>, request: Request, next: Next) -> Response {
    let cbor_in = media_is(request.headers().get(header::CONTENT_TYPE), CONTENT_TYPE);
    let cbor_out = cbor_in || media_is(request.headers().get(header::ACCEPT), CONTENT_TYPE);
    let request = if cbor_in {
        let (mut parts, body) = request.into_parts();
        let Ok(bytes) = to_bytes(body, max_body).await else {
            return Problem::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body-too-large",
                "Payload Too Large",
            )
            .into_response();
        };
        let json = match json_body(&bytes) {
            Ok(j) => j,
            Err(e) => return refused(e),
        };
        parts.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        parts.headers.remove(header::CONTENT_LENGTH);
        Request::from_parts(parts, Body::from(json))
    } else {
        request
    };
    let response = next.run(request).await;
    if !cbor_out
        || !media_is(
            response.headers().get(header::CONTENT_TYPE),
            "application/json",
        )
    {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, usize::MAX).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match cbor_body(&bytes) {
        Ok(cbor) => {
            parts
                .headers
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
            parts.headers.remove(header::CONTENT_LENGTH);
            Response::from_parts(parts, Body::from(Bytes::from(cbor)))
        }
        Err(e) => {
            Problem::new(StatusCode::NOT_ACCEPTABLE, e.code(), "Not Acceptable").into_response()
        }
    }
}

#[cfg(test)]
mod tests;
