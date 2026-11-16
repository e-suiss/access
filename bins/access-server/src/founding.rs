//! A tenant founder's routes on the environment issuer (OP-159 m.47 (c), TN-141): the founding a link
//! token names, the proof of the founder's address with the magic code, and the completion that opens
//! the management environment with the founder's device Party as its root, makes the founder's
//! account with its password and closes the founding. The routes live before the management
//! environment does, so they resolve the founding by its token, never by an environment. Every answer
//! is `no-store` and sent on as no referrer (TN-89 (8)). The login app's founding screen calls them.

use std::sync::Arc;

use access_crypto::Secret;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::Environment;
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_admin::app::Admin;
use access_identity_admin::app::founding::{FoundingError, device_party};
use access_identity_admin::ports::{Decider, Governance, Instances};
use access_identity_oauth::adapters::outbound::DeclaredTargets;
use access_identity_oauth::domain::issuer::EnvironmentBase;
use access_identity_session::domain::device::instance_key;
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::Pool;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::json;

use crate::idp::EnvironmentKeyring;
use access_identity_events::adapters::EnvironmentKek as _;

use crate::login::EnvironmentKeks;

/// Largest founding request body.
const MAX_BODY: usize = 8 * 1024;

/// What the founder routes need.
pub(crate) struct Founding<P> {
    pub(crate) app: Pool,
    pub(crate) ids: Arc<crate::ids::CellIds>,
    pub(crate) plane: P,
    pub(crate) base: EnvironmentBase,
    pub(crate) keys: Arc<EnvironmentKeyring>,
    pub(crate) keks: EnvironmentKeks,
}

type St<P> = State<Arc<Founding<P>>>;

fn reply(status: StatusCode, body: &serde_json::Value) -> Response {
    let mut r = (status, axum::Json(body)).into_response();
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    r
}

fn problem(status: u16, code: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    let mut r = reply(
        status,
        &json!({
            "type": format!("urn:suiss:access:problem:{code}"),
            "title": status.canonical_reason().unwrap_or("Error"),
            "status": status.as_u16(),
            "code": code,
        }),
    );
    if let Ok(v) = HeaderValue::from_str("application/problem+json") {
        r.headers_mut().insert(header::CONTENT_TYPE, v);
    }
    r
}

fn refused(e: &FoundingError) -> Response {
    if matches!(e, FoundingError::Admin(_)) {
        tracing::warn!(event = "founding.refused", outcome = "error", error = %e, "founding step failed");
    }
    let (status, code) = e.problem();
    problem(status, code)
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> Founding<P> {
    fn admin<'a>(
        &'a self,
        ids: &'a access_crypto::opaque_id::IdKey,
    ) -> Admin<'a, P, P, EnvironmentKeyring> {
        Admin {
            app: &self.app,
            ids,
            decider: &self.plane,
            governance: &self.plane,
            pep: IDENTITY_PEP,
            base: &self.base,
            keys: self.keys.as_ref(),
            platform_tenant: None,
            declared: DeclaredTargets::default(),
            vault: None,
        }
    }
}

/// `GET /env/{slug}/v1/foundings/{token}`: the founding's tenant name, its management environment and
/// its state; never the founder's address.
async fn view<P: Decider + Governance + Instances + Clone + Send + Sync + 'static>(
    State(f): St<P>,
    Path((slug, token)): Path<(String, String)>,
) -> Response {
    let Some(ids) = f.ids.key() else {
        return problem(503, "unavailable");
    };
    match f.admin(&ids).founding(&slug, &token).await {
        Ok(v) => reply(
            StatusCode::OK,
            &json!({
                "display_name": v.display_name,
                "environment": { "slug": v.route.slug, "kind": "management" },
                "expires_at": access_identity_admin::app::rest::rfc3339(v.route.expires_ms),
                "verified": v.route.verified,
                "completed": v.route.completed,
            }),
        ),
        Err(e) => refused(&e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    email: String,
    code: String,
}

/// `POST /env/{slug}/v1/foundings/{token}/verify`: `{email, code}` proves the founder's address
/// (TN-89 (5), (7)).
async fn verify<P: Decider + Governance + Instances + Clone + Send + Sync + 'static>(
    State(f): St<P>,
    Path((slug, token)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let Ok(p) = serde_json::from_slice::<Proof>(&body) else {
        return problem(400, "invalid-request");
    };
    let Some(ids) = f.ids.key() else {
        return problem(503, "unavailable");
    };
    match f
        .admin(&ids)
        .verify_founding(&slug, &token, (&p.email, &p.code))
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => refused(&e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    email: String,
    code: String,
    password: String,
    /// The browser's device key, a `COSE_Key`, unpadded base64url: its Party roots the tenant.
    device_key: String,
}

/// `POST /env/{slug}/v1/foundings/{token}/complete`: `{email, code, password, device_key}` opens
/// the management environment rooted in the device key's Party, makes the founder's account with
/// the password and closes the founding (TN-141). A second factor is required at the first
/// sign-in (TN-138).
async fn complete<P: Decider + Governance + Instances + Clone + Send + Sync + 'static>(
    State(f): St<P>,
    Path((slug, token)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let Ok(c) = serde_json::from_slice::<Completion>(&body) else {
        return problem(400, "invalid-request");
    };
    let Some(key) = b64url_decode(&c.device_key)
        .ok()
        .filter(|k| (1..=256).contains(&k.len()))
        .and_then(|k| instance_key(&k).ok())
    else {
        return problem(400, "key-invalid");
    };
    let Ok(identifier) = Identifier::new(IdentifierKind::Email, &c.email) else {
        return problem(400, "invalid-email");
    };
    let Some(ids) = f.ids.key() else {
        return problem(503, "unavailable");
    };
    let admin = f.admin(&ids);
    if let Err(e) = admin
        .verify_founding(&slug, &token, (&c.email, &c.code))
        .await
    {
        return refused(&e);
    }
    let founder = device_party(&key);
    let created = match admin.open_management(&slug, &token, founder).await {
        Ok(c) => c,
        Err(e) => return refused(&e),
    };
    let view = match admin.founding(&slug, &token).await {
        Ok(v) => v,
        Err(e) => return refused(&e),
    };
    let tenant = view.route.tenant;
    let (Some(kek), Some(vault)) = (
        f.keks.kek(tenant, created.environment),
        f.keks.vault(created.environment),
    ) else {
        return problem(503, "unavailable");
    };
    let scope = Environment {
        tenant,
        environment: created.environment,
        kek: &*kek,
        ids: &ids,
    };
    let accounts = PgAccounts::sealed(f.app.clone(), vault);
    let password = Secret::new(c.password);
    let subject = match crate::bootstrap::local::create_account(
        &accounts,
        &scope,
        &identifier,
        Some((&password, None)),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(event = "founding.account", outcome = "refused", error = %e, "founder account not made");
            return problem(400, "invalid-password");
        }
    };
    if let Err(e) = admin
        .finish_founding(&slug, &token, (subject, founder))
        .await
    {
        return refused(&e);
    }
    reply(
        StatusCode::CREATED,
        &json!({
            "environment": { "slug": slug, "kind": "management" },
            "issuer": created.issuer.as_str(),
            "party": b64url_encode(&founder.0),
        }),
    )
}

/// The founder routes under every environment issuer path.
pub(crate) fn router<P: Decider + Governance + Instances + Clone + Send + Sync + 'static>(
    f: Founding<P>,
) -> Router {
    Router::new()
        .route("/env/{slug}/v1/foundings/{token}", get(view::<P>))
        .route("/env/{slug}/v1/foundings/{token}/verify", post(verify::<P>))
        .route(
            "/env/{slug}/v1/foundings/{token}/complete",
            post(complete::<P>),
        )
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(Arc::new(f))
}
