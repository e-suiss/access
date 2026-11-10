//! The hosted login surface of the identity plane (CMP-15.6, OP-146 m.12): the login flow
//! endpoints of the node contract (`sdks/openapi/login.json`), magic link confirmation, the
//! signed-in user's sessions and methods, `/.well-known/webauthn`, and the built login app.
//! The request's `Host` selects the realm exactly as for discovery; an unknown host gets the
//! router's plain 404 (§17.9.6). [`me_router`] adds the product-facing endpoints of OP-149
//! (`sdks/openapi/frontend.json`).

pub mod assets;
mod certificate;
mod did;
mod idempotency;
mod me;
mod recovery;
mod saml;
mod social;
mod vault;
pub(crate) mod web;
mod workloads;

use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::domain::frontend_v1::{ROUTES, Verb};
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::Router;
use axum::routing::{delete, get, patch, post, put};

pub use assets::{Assets, AssetsError};
pub use certificate::router as certificate_router;
pub use did::router as did_router;
pub use idempotency::{CAPACITY as IDEMPOTENCY_CAPACITY, RETENTION as IDEMPOTENCY_RETENTION};
pub use me::router as me_router;
pub use saml::{Opening as SamlOpening, Outcome as SamlOutcome, SamlFront, router as saml_router};
pub use social::router as social_router;
pub use vault::router as vault_router;
pub use workloads::router as workloads_router;

/// The client's address, set by the connection layer.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub std::net::IpAddr);

pub(crate) struct Shared<D, K, KI, C, M> {
    discovery: Discovery<D, K>,
    hosted: Arc<Hosted<KI, C, M>>,
    assets: Option<Assets>,
}

/// The login routes. `assets` is the built login app; without it only the API is served.
#[expect(clippy::too_many_lines, reason = "one route table, read top to bottom")]
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
                &format!("{prefix}/v1/login/step-up"),
                post(web::step_up::<D, K, KI, C, M>),
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
                &format!("{prefix}/v1/account/recovery-codes/acknowledgement"),
                post(web::acknowledge_recovery_codes::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/credential-export"),
                post(web::export_credentials::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/passkeys"),
                post(web::begin_passkey::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/passkeys/{{registration}}"),
                post(web::finish_passkey::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/preferences"),
                put(web::set_preferences::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/documents"),
                post(web::accept_document::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/deletion"),
                delete(web::cancel_deletion::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/email"),
                post(web::start_email_change::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/email/{{change}}"),
                post(web::confirm_email_change::<D, K, KI, C, M>),
            )
            // OP-153 m.2 N2
            .route(
                &format!("{prefix}/v1/recovery"),
                post(recovery::start::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/recovery/{{attempt}}"),
                post(recovery::prove::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/recovery/{{attempt}}/extension"),
                post(recovery::extend::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/recovery/intents/{{token}}"),
                post(recovery::redeem::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/recovery-contacts"),
                put(recovery::set_contacts::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/link-codes"),
                post(recovery::link_code::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/invitations/{{code}}"),
                post(web::accept_invitation::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/organizations/{{organization}}/access-requests"),
                post(web::request_access::<D, K, KI, C, M>),
            )
            // TN-91, E53, E47
            .route(
                &format!("{prefix}/v1/organizations/{{organization}}/handovers/{{handover}}"),
                delete(web::cancel_handover::<D, K, KI, C, M>),
            )
            .route(
                &format!(
                    "{prefix}/v1/organizations/{{organization}}/handovers/{{handover}}/contribution"
                ),
                post(web::contribute_handover::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/guardian-consents"),
                post(web::ask_consent::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/guardian-consents/{{consent}}"),
                post(web::decide_consent::<D, K, KI, C, M>),
            )
            // OP-153 m.2 N5
            .route(
                &format!("{prefix}/v1/sessions/{{session}}/end"),
                post(web::end_sign_in::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/methods/{{credential}}"),
                delete(web::remove_sign_in_method::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/password"),
                put(web::set_password::<D, K, KI, C, M>),
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
            )
            .route(
                &format!("{prefix}/v1/account/preferences"),
                get(web::preferences::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/documents"),
                get(web::documents::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/security-history"),
                get(web::security_history::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/deletion"),
                get(web::deletion::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/data-requests"),
                get(web::data_requests::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/recovery/{{attempt}}"),
                get(recovery::get::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/recovery-contacts"),
                get(recovery::contacts::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/invitations/{{code}}"),
                get(web::invitation::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/organizations"),
                get(web::organizations::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/organizations/{{organization}}/sign-in"),
                get(web::organization_sign_in::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/handovers"),
                get(web::handovers::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/account/guardian-consents/{{consent}}"),
                get(web::consent::<D, K, KI, C, M>),
            )
            // OP-153 m.2 N5
            .route(
                &format!("{prefix}/v1/account/methods"),
                get(web::sign_in_methods::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/login/branding"),
                get(web::branding::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/login/messages"),
                get(web::message_overrides::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/dbsc/register"),
                post(web::dbsc_register::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/v1/dbsc/refresh"),
                post(web::dbsc_refresh::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/csp-reports"),
                post(web::csp_report::<D, K, KI, C, M>),
            )
            .route(
                &format!("{prefix}/login/theme.css"),
                get(web::theme_css::<D, K, KI, C, M>),
            );
    }
    // OP-153 m.4
    for r in ROUTES.iter().filter(|r| !r.live) {
        for prefix in ["", "/realms/{slug}"] {
            let path = format!("{prefix}{}", r.path);
            reads = match r.verb {
                Verb::Get => reads.route(&path, get(web::not_yet_served::<D, K, KI, C, M>)),
                Verb::Post => reads.route(&path, post(web::not_yet_served::<D, K, KI, C, M>)),
                Verb::Put => reads.route(&path, put(web::not_yet_served::<D, K, KI, C, M>)),
                Verb::Delete => reads.route(&path, delete(web::not_yet_served::<D, K, KI, C, M>)),
                Verb::Patch => reads.route(&path, patch(web::not_yet_served::<D, K, KI, C, M>)),
            };
        }
    }
    let reads = reads
        .route(
            "/.well-known/webauthn",
            get(web::related_origins::<D, K, KI, C, M>),
        )
        .route("/login", get(web::page::<D, K, KI, C, M>))
        .route("/login/{*rest}", get(web::page::<D, K, KI, C, M>))
        // OP-154 m.3 (p), m.7 (f)
        .route("/device", get(web::page::<D, K, KI, C, M>))
        .route("/realms/{slug}/device", get(web::page::<D, K, KI, C, M>))
        .route("/assets/{*path}", get(web::asset::<D, K, KI, C, M>))
        // OP-153 m.2
        .route("/realms/{slug}/login", get(web::page::<D, K, KI, C, M>))
        .route(
            "/realms/{slug}/login/{*rest}",
            get(web::page::<D, K, KI, C, M>),
        )
        .route(
            "/realms/{slug}/assets/{*path}",
            get(web::asset::<D, K, KI, C, M>),
        );
    let cache = Arc::new(idempotency::Cache::default());
    writes
        .route_layer(axum::middleware::from_fn_with_state(
            cache,
            idempotency::layer,
        ))
        .merge(reads)
        .with_state(shared)
}
