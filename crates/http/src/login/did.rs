//! The `did:web` documents on axum (OP-154 m.3 (aa)): `GET /u/{party}/did.json` at the realm's
//! host and under `/realms/{slug}`. Public, cookie-less and read-only; a DID is an identifier,
//! never authority.

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::ports::{Clock, Kits, Messages, PartyKeys};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Uri};
use axum::response::Response;
use axum::routing::get;

use super::Shared;
use super::web::{realm, send};

struct Svc<D, K, KI, C, M, P> {
    login: Shared<D, K, KI, C, M>,
    keys: P,
}

/// The `did:web` routes of lane L3.
pub fn router<D, K, KI, C, M, P>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    keys: P,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
    P: PartyKeys + 'static,
{
    let svc = Arc::new(Svc {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        keys,
    });
    let mut r = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        r = r.route(
            &format!("{prefix}/u/{{party}}/did.json"),
            get(document::<D, K, KI, C, M, P>),
        );
    }
    r.with_state(svc)
}

/// `GET /u/{party}/did.json`.
async fn document<D, K, KI, C, M, P>(
    State(s): State<Arc<Svc<D, K, KI, C, M, P>>>,
    Path(p): Path<HashMap<String, String>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    K: Keys,
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    P: PartyKeys,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let party = p.get("party").map(String::as_str).unwrap_or_default();
    let party = if party.len() <= 32 { party } else { "" };
    let reply = s.login.hosted.did_document(&entry, party, &s.keys).await;
    send(reply, &headers).await
}
