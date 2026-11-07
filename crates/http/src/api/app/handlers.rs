//! The surface roots (OP-151 m.3 (a)): what each management surface is, for a caller holding
//! its read scope. Resources under them are added by their own rows.

use access_kernel::json::b64url_encode;
use axum::Extension;
use axum::response::Response;
use serde_json::json;

use super::{Ctx, json_ok};
use crate::api::domain::SurfaceScope;
use crate::api::domain::rate;
use crate::api::ports::Env;

fn surface(ctx: &Ctx<impl Env>) -> serde_json::Value {
    let s = ctx.scope.surface();
    let write = rate::actor_quota(s, true);
    let read = rate::actor_quota(s, false);
    let mut body = json!({
        "surface": s.name(),
        "audience": ctx.scope.audience(),
        "scope_namespace": format!("{}.", s.name()),
        "read_scope": s.read_scope(),
        "domain": b64url_encode(&ctx.domain.0),
        "rate_policies": [write.policy_item(), read.policy_item()],
    });
    if let (SurfaceScope::Realm(slug), Some(o)) = (&ctx.scope, body.as_object_mut()) {
        o.insert("realm".to_owned(), json!(slug));
    }
    body
}

/// `GET /admin/v1/platform`.
pub(super) async fn platform_root<E: Env>(Extension(ctx): Extension<Ctx<E>>) -> Response {
    json_ok(&surface(&ctx))
}

/// `GET /admin/v1/realms/{slug}`.
pub(super) async fn realm_root<E: Env>(Extension(ctx): Extension<Ctx<E>>) -> Response {
    json_ok(&surface(&ctx))
}
