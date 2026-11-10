//! Certificate, PIV and CAC sign-in on axum (§10.2.5, OP-155 m.3 (k), (m)): `GET
//! /login/certificate` at the realm's host and under `/realms/{slug}`, served on the mTLS
//! listener. The chain is the connection's [`MtlsChain`], set only by TLS that ends at
//! access-server; on any other listener there is none and the request is refused. A forwarded
//! certificate header never reaches here (`tls::FORWARDED_CERT_HEADERS`).
//!
//! The request is a top-level navigation from the realm's login page, so it is held to the same
//! site, not the same origin: a `Sec-Fetch-Site` other than `same-origin`, `same-site` or `none`
//! is refused.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::certificate::Certificates;
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};

use super::web::{Jar, problem, realm, send};
use super::{Peer, Shared};
use crate::tls::MtlsChain;

struct Svc<D, K, KI, C, M> {
    login: Shared<D, K, KI, C, M>,
    certs: Certificates,
}

type St<D, K, KI, C, M> = State<Arc<Svc<D, K, KI, C, M>>>;

/// The certificate sign-in route, at the realm's host and under `/realms/{slug}`.
pub fn router<D, K, KI, C, M>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    certs: Certificates,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
{
    let svc = Arc::new(Svc {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        certs,
    });
    let mut r = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        r = r.route(
            &format!("{prefix}/login/certificate"),
            get(sign_in::<D, K, KI, C, M>),
        );
    }
    r.with_state(svc)
}

/// OP-155 m.3 (m): a navigation from the realm's own site, or a direct one.
fn same_site(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| matches!(v, "same-origin" | "same-site" | "none"))
}

/// `GET /login/certificate` (OP-155 m.3 (m)).
async fn sign_in<D, K, KI, C, M>(
    State(s): St<D, K, KI, C, M>,
    Path(p): Path<HashMap<String, String>>,
    peer: Option<Extension<Peer>>,
    chain: Option<Extension<MtlsChain>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    K: Keys,
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if !same_site(&headers) {
        return problem(
            StatusCode::FORBIDDEN,
            "cross-site",
            "The request did not come from this site",
        );
    }
    let jar = Jar::of(&headers, peer);
    let chain = chain.map(|Extension(MtlsChain(c))| c);
    let reply = s
        .login
        .hosted
        .certificate_login(&entry, &jar.browser(), chain.as_deref(), &s.certs)
        .await;
    send(reply, &headers).await
}
