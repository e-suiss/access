//! The token vault on axum (OP-154 m.3 (t)): the `frontend-v1` routes of lane L5. The person's
//! connected accounts use the login surface's session, cookies and same-origin rule; the
//! upstream's redirect back is a top-level navigation to the connections list, bound to this
//! browser's flow cookie. `POST /v1/vault/releases` is for registered executors only: the PEP is
//! the one the TLS layer named by its client certificate, and nobody else has a route (§11.13).

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::vault::{Callback, StartBody};
use access_identity_ui::ports::{Clock, Kits, Messages};
use access_identity_vault::app::Vault;
use access_identity_vault::ports::{Exercises, ProviderHttp, Random, SocialSecrets};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;

use super::web::{Jar, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared, idempotency};
use crate::adp::adapters::Pep;

struct Svc<D, K, KI, C, M, H, S, X, R> {
    login: Shared<D, K, KI, C, M>,
    vault: Arc<Vault<H, S, X, R>>,
}

type St<D, K, KI, C, M, H, S, X, R> = State<Arc<Svc<D, K, KI, C, M, H, S, X, R>>>;
type Params0 = Path<HashMap<String, String>>;

/// Longest `code` or `state`.
const MAX_CODE: usize = 2048;

/// Largest request body.
const MAX_BODY: usize = 32 * 1024;

/// The routes of lane L5, at the realm's host and under `/realms/{slug}`.
pub fn router<D, K, KI, C, M, H, S, X, R>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    vault: impl Into<Arc<Vault<H, S, X, R>>>,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
    H: ProviderHttp + 'static,
    S: SocialSecrets + 'static,
    X: Exercises + 'static,
    R: Random + 'static,
{
    let svc = Arc::new(Svc {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        vault: vault.into(),
    });
    let mut writes = Router::new();
    let mut reads = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        writes = writes.route(
            &format!("{prefix}/v1/account/vault/connections"),
            post(start::<D, K, KI, C, M, H, S, X, R>),
        );
        reads = reads
            .route(
                &format!("{prefix}/v1/account/vault/connections"),
                get(list::<D, K, KI, C, M, H, S, X, R>),
            )
            .route(
                &format!("{prefix}/v1/account/vault/connections/{{connection}}"),
                get(one::<D, K, KI, C, M, H, S, X, R>)
                    .delete(disconnect::<D, K, KI, C, M, H, S, X, R>),
            )
            .route(
                &format!("{prefix}/v1/vault/releases"),
                post(release::<D, K, KI, C, M, H, S, X, R>),
            );
    }
    let cache = Arc::new(idempotency::Cache::default());
    writes
        .route_layer(axum::middleware::from_fn_with_state(
            cache,
            idempotency::layer,
        ))
        .merge(reads)
        .with_state(svc)
}

fn bad() -> Response {
    problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request")
}

fn bounded(text: &str, max: usize) -> Result<&str, Response> {
    if text.is_empty() || text.len() > max || text.chars().any(char::is_control) {
        return Err(bad());
    }
    Ok(text)
}

macro_rules! handler {
    (
        $(#[$doc:meta])*
        $name:ident($s:ident, $entry:ident, $jar:ident, $p:ident, $bytes:ident, $headers:ident, $uri:ident, $pep:ident) $write:literal $body:block
    ) => {
        $(#[$doc])*
        #[allow(clippy::too_many_arguments, reason = "axum extractors")]
        async fn $name<D, K, KI, C, M, H, S, X, R>(
            State($s): St<D, K, KI, C, M, H, S, X, R>,
            Path($p): Params0,
            peer: Option<Extension<Peer>>,
            $pep: Option<Extension<Pep>>,
            $uri: Uri,
            $headers: HeaderMap,
            $bytes: Bytes,
        ) -> Response
        where
            D: Directory,
            K: Keys,
            KI: Kits,
            C: Clock + Sync,
            M: Messages,
            H: ProviderHttp,
            S: SocialSecrets,
            X: Exercises,
            R: Random,
        {
            let $entry = match realm(&$s.login, &$p, &$uri, &$headers).await {
                Ok(e) => e,
                Err(r) => return r,
            };
            if $write && let Err(r) = same_origin(&$headers) {
                return r;
            }
            if !$bytes.is_empty() && let Err(r) = json_only(&$headers) {
                return r;
            }
            if $bytes.len() > MAX_BODY {
                return bad();
            }
            let $jar = Jar::of(&$headers, peer);
            let reply = async { $body }.await;
            match reply {
                Ok(r) => send(r, &$headers).await,
                Err(r) => r,
            }
        }
    };
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectBody {
    resource: String,
    client_id: String,
    scopes: Option<Vec<String>>,
}

handler! {
    /// `GET /v1/account/vault/connections` (§8.8, §8.9), and the upstream's redirect back.
    list(s, entry, jar, p, bytes, headers, uri, pep) false {
        let _ = (&p, &bytes, &pep);
        let params = Params::parse(uri.query().unwrap_or_default()).map_err(|_| bad())?;
        let callback = match params.get("state") {
            Some(state) => Some(Callback {
                code: params.get("code").map(|c| bounded(c, MAX_CODE)).transpose()?,
                state: bounded(state, MAX_CODE)?,
            }),
            None => None,
        };
        Ok(s.login.hosted.vault_connections(&entry, &jar.browser(), callback, &s.vault).await)
    }
}

handler! {
    /// `POST /v1/account/vault/connections` (AS-M15).
    start(s, entry, jar, p, bytes, headers, uri, pep) true {
        let _ = (&p, &uri, &pep);
        let req: ConnectBody = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let ask = StartBody {
            resource: String::from(bounded(&req.resource, 64)?),
            client_id: String::from(bounded(&req.client_id, 2048)?),
            scopes: req.scopes,
        };
        Ok(s.login.hosted.start_vault_connection(&entry, &jar.browser(), &ask, &s.vault).await)
    }
}

handler! {
    /// `GET /v1/account/vault/connections/{connection}`.
    one(s, entry, jar, p, bytes, headers, uri, pep) false {
        let _ = (&bytes, &uri, &pep);
        let c = bounded(p.get("connection").map(String::as_str).unwrap_or_default(), 64)?;
        Ok(s.login.hosted.vault_connection(&entry, &jar.browser(), c, &s.vault).await)
    }
}

handler! {
    /// `DELETE /v1/account/vault/connections/{connection}` (OP-73).
    disconnect(s, entry, jar, p, bytes, headers, uri, pep) true {
        let _ = (&bytes, &uri, &pep);
        let c = bounded(p.get("connection").map(String::as_str).unwrap_or_default(), 64)?;
        Ok(s.login.hosted.disconnect_vault_connection(&entry, &jar.browser(), c, &s.vault).await)
    }
}

handler! {
    /// `POST /v1/vault/releases` (G59, U66, EI-26): the executor's own TLS identity, no session.
    release(s, entry, jar, p, bytes, headers, uri, pep) false {
        let _ = (&p, &uri, &jar);
        let body: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let pep = pep.as_ref().map(|Extension(Pep(p))| p.as_str());
        Ok(s.login.hosted.release_vault_token(&entry, pep, &body, &s.vault).await)
    }
}
