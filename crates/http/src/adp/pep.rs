//! PEP transport authentication by OAuth (OP-155 m.3 (q), §9.5.1 #10, Ek B 5074): next to the
//! client certificate the TLS layer names, a PEP may present a DPoP-bound `client_credentials`
//! token of a realm for this ADP with its DPoP proof. The PEP it names is the proof key's
//! thumbprint. A request carrying both a certificate PEP and a token is refused rather than
//! guessed about; one with neither reaches the routes without a PEP and is refused there.

use std::sync::Arc;

use access_identity_oauth::app::oauth::pep::PepIdentity;
use access_identity_oauth::app::oauth::{Env, OAuth};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::Problem;
use crate::adp::adapters::Pep;

/// The `DPoP-Nonce` response header (RFC 9449 §9).
const DPOP_NONCE: &str = "dpop-nonce";

struct Tokens<E> {
    oauth: Arc<OAuth<E>>,
    issuer: String,
}

/// The realm authority and path slug an issuer URL names (§17.9.6): `https://host[:port]` or
/// `https://host[:port]/realms/{slug}`.
fn realm_of(iss: &str) -> Option<(&str, Option<&str>)> {
    let rest = iss.strip_prefix("https://")?;
    match rest.split_once('/') {
        None => Some((rest, None)),
        Some((authority, path)) => Some((authority, Some(path.strip_prefix("realms/")?))),
    }
}

/// The unverified `iss` of a compact JWS: only to find whose keys verify it.
fn issuer_of(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = access_kernel::json::b64url_decode(payload).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("iss")?.as_str().map(String::from)
}

fn unauthenticated(error: &str, nonce: Option<&str>) -> Response {
    let mut r = Problem::new(
        StatusCode::UNAUTHORIZED,
        "pep-unauthenticated",
        "Unauthorized",
    )
    .into_response();
    if let Ok(v) = HeaderValue::from_str(&format!(r#"DPoP error="{error}", algs="ES256 EdDSA""#)) {
        r.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    if let Some(v) = nonce.and_then(|n| HeaderValue::from_str(n).ok()) {
        r.headers_mut().insert(DPOP_NONCE, v);
    }
    r
}

async fn authenticate<E: Env>(
    State(tokens): State<Arc<Tokens<E>>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(authorization) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
    else {
        return next.run(request).await;
    };
    if request.extensions().get::<Pep>().is_some() {
        return Problem::new(StatusCode::BAD_REQUEST, "ambiguous-pep", "Bad Request")
            .into_response();
    }
    let proofs: Vec<String> = request
        .headers()
        .get_all("dpop")
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();
    let proofs: Vec<&str> = proofs.iter().map(String::as_str).collect();
    let token = authorization.split_once(' ').map_or("", |(_, t)| t.trim());
    let Some(iss) = issuer_of(token) else {
        return unauthenticated("invalid_token", None);
    };
    let Some((authority, slug)) = realm_of(&iss) else {
        return unauthenticated("invalid_token", None);
    };
    let realm = match tokens.oauth.realm(authority, slug).await {
        Ok(Some(r)) => r,
        Ok(None) => return unauthenticated("invalid_token", None),
        Err(_) => return crate::problem::codes::UNAVAILABLE.problem().into_response(),
    };
    let uri = format!("{}{}", tokens.issuer, request.uri().path());
    let method = request.method().as_str().to_owned();
    match tokens
        .oauth
        .pep_identity(&realm, &method, &uri, &authorization, &proofs)
        .await
    {
        Ok(PepIdentity::Pep { jkt, nonce }) => {
            request.extensions_mut().insert(Pep(jkt));
            let mut r = next.run(request).await;
            if let Some(v) = nonce.and_then(|n| HeaderValue::from_str(&n).ok()) {
                r.headers_mut().insert(DPOP_NONCE, v);
            }
            r
        }
        Ok(PepIdentity::Refused { error, nonce }) => unauthenticated(error, nonce.as_deref()),
        Err(_) => crate::problem::codes::UNAVAILABLE.problem().into_response(),
    }
}

/// `adp` that also hears PEPs presenting a DPoP-bound PEP token of a realm `oauth` serves; the
/// proof's `htu` is `issuer` followed by the request path.
pub fn with_tokens<E: Env + 'static>(
    adp: axum::Router,
    oauth: Arc<OAuth<E>>,
    issuer: String,
) -> axum::Router {
    adp.layer(axum::middleware::from_fn_with_state(
        Arc::new(Tokens { oauth, issuer }),
        authenticate::<E>,
    ))
}

#[cfg(test)]
mod tests {
    use super::realm_of;

    // OP-155 m.3 (q)
    #[test]
    fn an_issuer_names_its_realm_by_host_or_path() {
        assert_eq!(
            realm_of("https://acme.access.test"),
            Some(("acme.access.test", None))
        );
        assert_eq!(
            realm_of("https://access.test:9443/realms/acme"),
            Some(("access.test:9443", Some("acme")))
        );
        assert_eq!(realm_of("http://access.test/realms/acme"), None);
        assert_eq!(realm_of("https://access.test/other/acme"), None);
    }
}
