//! The Frontend API for products on axum (OP-149 m.6, m.8, m.9): `sdks/openapi/frontend.json`.
//! Realm selection, cookies and replies are the login surface's.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::{Devices, Hosted, Reply};
use access_identity_ui::domain::approval::{
    APP_PATH, ApprovalFinish, ApprovalPush, ApprovalStart, FLOW_PATH, FLOWS_PATH, PAGE_JS,
    REQUESTS_PATH,
};
use access_identity_ui::domain::frontend::{
    APPROVE_PATH, AUTH_CONTEXT_PATH, ApproveQuery, AuthContextRequest, BINDINGS_PATH,
    CHALLENGES_PATH, INSTANCE_PATH, INSTANCES_PATH, InstanceBinding, InstanceRecovery,
    InstanceRegistration, InstanceTermination, RECOVER_PATH,
};
use access_identity_ui::ports::{
    ApprovalClaims, Approvals, ArtifactSigner, Clock, DeviceInstances, Kits, Messages,
};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::de::DeserializeOwned;

use super::web::{Jar, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared, idempotency};

struct Me<D, K, KI, C, M, A, I, P, Q> {
    login: Shared<D, K, KI, C, M>,
    devices: Devices<A, I, P, Q>,
}

type St<D, K, KI, C, M, A, I, P, Q> = State<Arc<Me<D, K, KI, C, M, A, I, P, Q>>>;
type Params0 = Path<HashMap<String, String>>;

fn body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Response> {
    serde_json::from_slice(bytes)
        .map_err(|_| problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request"))
}

/// The product-facing routes, at the realm's host and under `/realms/{slug}`.
pub fn router<D, K, KI, C, M, A, I, P, Q>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    devices: Devices<A, I, P, Q>,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
    A: ArtifactSigner + 'static,
    I: DeviceInstances + 'static,
    P: Approvals + 'static,
    Q: ApprovalClaims + 'static,
{
    let me = Arc::new(Me {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        devices,
    });
    let mut writes = Router::new();
    let mut reads = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        writes = writes
            .route(
                &format!("{prefix}{CHALLENGES_PATH}"),
                post(challenge::<D, K, KI, C, M, A, I, P, Q>),
            )
            .route(
                &format!("{prefix}{INSTANCES_PATH}"),
                post(register::<D, K, KI, C, M, A, I, P, Q>),
            )
            .route(
                &format!("{prefix}{BINDINGS_PATH}"),
                post(bind::<D, K, KI, C, M, A, I, P, Q>),
            )
            // OP-153 m.3 (c)
            .route(
                &format!("{prefix}{RECOVER_PATH}"),
                post(recover::<D, K, KI, C, M, A, I, P, Q>),
            )
            .route(
                &format!("{prefix}{INSTANCE_PATH}"),
                axum::routing::delete(terminate::<D, K, KI, C, M, A, I, P, Q>),
            )
            .route(
                &format!("{prefix}{AUTH_CONTEXT_PATH}"),
                post(auth_context::<D, K, KI, C, M, A, I, P, Q>),
            )
            .route(
                &format!("{prefix}{REQUESTS_PATH}"),
                post(push_approval::<D, K, KI, C, M, A, I, P, Q>),
            )
            .route(
                &format!("{prefix}{FLOWS_PATH}"),
                post(start_approval::<D, K, KI, C, M, A, I, P, Q>),
            )
            .route(
                &format!("{prefix}{FLOW_PATH}"),
                post(finish_approval::<D, K, KI, C, M, A, I, P, Q>),
            );
        reads = reads
            .route(
                &format!("{prefix}{APPROVE_PATH}"),
                get(approve::<D, K, KI, C, M, A, I, P, Q>),
            )
            .route(
                &format!("{prefix}{APP_PATH}"),
                get(approval_app::<D, K, KI, C, M, A, I, P, Q>),
            );
    }
    let cache = Arc::new(idempotency::Cache::default());
    writes
        .route_layer(axum::middleware::from_fn_with_state(
            cache,
            idempotency::layer,
        ))
        .merge(reads)
        .with_state(me)
}

macro_rules! handler {
    (
        $(#[$doc:meta])*
        $name:ident($s:ident, $entry:ident, $jar:ident, $p:ident, $bytes:ident, $headers:ident, $uri:ident) $write:literal $body:block
    ) => {
        $(#[$doc])*
        async fn $name<D, K, KI, C, M, A, I, P, Q>(
            State($s): St<D, K, KI, C, M, A, I, P, Q>,
            Path($p): Params0,
            peer: Option<Extension<Peer>>,
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
            A: ArtifactSigner,
            I: DeviceInstances,
            P: Approvals,
            Q: ApprovalClaims,
        {
            let $entry = match realm(&$s.login, &$p, &$uri, &$headers).await {
                Ok(e) => e,
                Err(r) => return r,
            };
            if $write && let Err(r) = same_origin(&$headers) {
                return r;
            }
            if $write && !$bytes.is_empty() && let Err(r) = json_only(&$headers) {
                return r;
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

handler! {
    /// `POST /v1/me/instances/challenges`.
    challenge(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &bytes, &uri);
        Ok::<_, Response>(s.login.hosted.instance_challenge(&s.devices, &entry, &jar.browser()).await)
    }
}

handler! {
    /// `POST /v1/me/instances`.
    register(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        json_only(&headers)?;
        let req: InstanceRegistration = body(&bytes)?;
        Ok(s.login.hosted.register_instance(&s.devices, &entry, &jar.browser(), &req).await)
    }
}

handler! {
    /// `POST /v1/me/instances/bindings` (OP-149 m.32).
    bind(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        json_only(&headers)?;
        let req: InstanceBinding = body(&bytes)?;
        Ok(s.login.hosted.bind_instance(&entry, &jar.browser(), &req).await)
    }
}

handler! {
    /// `POST /v1/me/instances/recover` (OP-153 m.3 (c)).
    recover(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        json_only(&headers)?;
        let req: InstanceRecovery = body(&bytes)?;
        Ok(s.login.hosted.recover_instance(&s.devices, &entry, &jar.browser(), &req).await)
    }
}

handler! {
    /// `DELETE /v1/me/instances/{instance}`.
    terminate(s, entry, jar, p, bytes, headers, uri) true {
        let _ = &uri;
        json_only(&headers)?;
        let req: InstanceTermination = body(&bytes)?;
        let instance = p.get("instance").map_or("", String::as_str);
        Ok(s.login
            .hosted
            .terminate_instance(&s.devices, &entry, &jar.browser(), instance, &req)
            .await)
    }
}

handler! {
    /// `POST /v1/me/auth-context`; the body is optional.
    auth_context(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        let req: Option<AuthContextRequest> = if bytes.is_empty() { None } else { Some(body(&bytes)?) };
        Ok(s.login
            .hosted
            .auth_context(&s.devices, &entry, &jar.browser(), req.as_ref())
            .await)
    }
}

handler! {
    /// `GET /v1/approve`.
    approve(s, entry, jar, p, bytes, headers, uri) false {
        let _ = (&p, &bytes, &jar);
        let bad = || problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request");
        let params = Params::parse(uri.query().unwrap_or_default()).map_err(|_| bad())?;
        let field = |name: &str| params.get(name).map(String::from).ok_or_else(bad);
        let query = ApproveQuery {
            request: field("request")?,
            redirect_uri: field("redirect_uri")?,
            state: field("state")?,
        };
        Ok(s.login.hosted.approve(&entry, &query).await)
    }
}

handler! {
    /// `POST /v1/approve/requests`: a coordinator's push; no session.
    push_approval(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri, &jar);
        json_only(&headers)?;
        let req: ApprovalPush = body(&bytes)?;
        Ok(s.login.hosted.push_approval(&entry, &req).await)
    }
}

handler! {
    /// `POST /v1/approve/flows`.
    start_approval(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        json_only(&headers)?;
        let req: ApprovalStart = body(&bytes)?;
        Ok(s.login.hosted.start_approval(&s.devices, &entry, &jar.browser(), &req).await)
    }
}

handler! {
    /// `POST /v1/approve/flows/{flow}`: the redirect parameters come again with the assertion.
    finish_approval(s, entry, jar, p, bytes, headers, uri) true {
        let _ = &uri;
        json_only(&headers)?;
        let req: ApprovalFinish = body(&bytes)?;
        let flow = p.get("flow").map_or("", String::as_str);
        Ok(s.login
            .hosted
            .finish_approval(&s.devices, &entry, &jar.browser(), flow, &req)
            .await)
    }
}

handler! {
    /// `GET /v1/approve/app.js`: the page's script.
    approval_app(s, entry, jar, p, bytes, headers, uri) false {
        let _ = (&s, &entry, &p, &bytes, &jar, &uri);
        Ok::<_, Response>(Reply::script(PAGE_JS))
    }
}
