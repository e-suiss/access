//! The hosted login surface of the identity plane (CMP-15.6, OP-146 m.12): the login flow
//! endpoints of the node contract (`sdks/openapi/login.json`), magic link confirmation, the
//! signed-in user's sessions and methods, `/.well-known/webauthn`, and the built login app.
//! The request's `Host` selects the realm exactly as for discovery; an unknown host gets the
//! router's plain 404 (§17.9.6). [`me_router`] adds the product-facing endpoints of OP-149
//! (`sdks/openapi/frontend.json`).

pub mod assets;
mod idempotency;
mod me;
mod web;

use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::Router;
use axum::routing::{get, post};

pub use assets::{Assets, AssetsError};
pub use idempotency::{CAPACITY as IDEMPOTENCY_CAPACITY, RETENTION as IDEMPOTENCY_RETENTION};
pub use me::router as me_router;

/// The client's address, set by the connection layer.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub std::net::IpAddr);

pub(crate) struct Shared<D, K, KI, C, M> {
    discovery: Discovery<D, K>,
    hosted: Arc<Hosted<KI, C, M>>,
    assets: Option<Assets>,
}

/// The login routes. `assets` is the built login app; without it only the API is served.
pub fn router<D, K, KI, C, M>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    assets: Option<Assets>,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
{
    let shared = Arc::new(Shared {
        discovery,
        hosted: hosted.into(),
        assets,
    });
    let mut writes = Router::new();
    let mut reads = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        writes = writes
            .route(
                &format!("{prefix}/v1/login/flows"),
                post(web::create::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/login/flows/{{flow}}"),
                post(web::submit::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/login/link/preview"),
                post(web::preview_link::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/login/link/confirm"),
                post(web::confirm_link::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/sessions/current/sign-out"),
                post(web::sign_out::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/sessions/sign-out-everywhere"),
                post(web::sign_out_everywhere::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/totp"),
                post(web::begin_totp::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/totp/{{enrollment}}"),
                post(web::confirm_totp::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/recovery-codes"),
                post(web::recovery_codes::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/passkeys"),
                post(web::begin_passkey::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/passkeys/{{registration}}"),
                post(web::finish_passkey::<D, K, KI, C, M>),
            );
        reads = reads
            .route(
                &format!("{prefix}/v1/login/flows/{{flow}}"),
                get(web::get_flow::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/sessions/current"),
                get(web::current_session::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/sessions"),
                get(web::sessions::<D, K, KI, C, M>),
            );
    }
    let reads = reads
        .route(
            "/.well-known/webauthn",
            get(web::related_origins::<D, K, KI, C, M>),
        )
        .route("/login", get(web::page::<D, K, KI, C, M>))
        .route("/login/{*rest}", get(web::page::<D, K, KI, C, M>))
        .route("/assets/{*path}", get(web::asset::<D, K, KI, C, M>));
    let cache = Arc::new(idempotency::Cache::default());
    writes
        .route_layer(axum::middleware::from_fn_with_state(
            cache,
            idempotency::layer,
        ))
        .merge(reads)
        .with_state(shared)
}
