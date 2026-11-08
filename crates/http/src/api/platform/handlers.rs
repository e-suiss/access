//! The one handler every platform resource row is served by: it reads the row's
//! [`super::spec`] and lists, gets, drafts or provisions through [`PlatformResources`].

use access_kernel::json::b64url_encode;
use axum::Extension;
use axum::body::Bytes;
use axum::extract::RawPathParams;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use super::{GENESIS_FIELDS, ROWS, Shape, project, resources, spec};
use crate::api::app::rest::{next_link, page_request};
use crate::api::app::{Caller, Committed, Ctx};
use crate::api::domain::caller::AIS_FIELD;
use crate::api::manifest::Access;
use crate::api::ports::{
    Clock, Drafted, Env, Item, PlatformKind, PlatformQuery, PlatformResources, PlatformWrite,
    Written,
};
use crate::api::realm::matches;
use crate::problem::{Code, codes};

fn problem(code: &Code) -> Response {
    code.problem().into_response()
}

fn key_of(params: &RawPathParams) -> Option<String> {
    params.iter().next().map(|(_, v)| v.to_owned())
}

fn now<E: Env>(ctx: &Ctx<E>) -> Result<u64, &'static Code> {
    let clock: &dyn Clock = ctx.api.env().clock();
    clock.now_ms().map_err(|_| &codes::UNAVAILABLE)
}

/// Serves the platform resource row of `ctx` (OP-151 m.2 M2).
pub async fn serve<E: Env>(
    Extension(ctx): Extension<Ctx<E>>,
    params: RawPathParams,
    uri: Uri,
    body: Bytes,
) -> Response {
    let Some((kind, shape)) = spec(ctx.row.operation_id) else {
        return problem(&codes::NOT_FOUND);
    };
    let key = key_of(&params);
    let answer = match shape {
        Shape::List(attrs) => list(&ctx, kind, attrs, key, &uri).await,
        Shape::Get => get(&ctx, kind, key).await,
        Shape::Draft => draft(&ctx, &body).await,
        Shape::Create => commit(&ctx, kind, key, &body).await,
    };
    answer.unwrap_or_else(problem)
}

fn port<E: Env>(ctx: &Ctx<E>) -> &dyn PlatformResources {
    resources(ctx.api.env())
}

async fn list<E: Env>(
    ctx: &Ctx<E>,
    kind: PlatformKind,
    attrs: &'static [&'static str],
    tenant: Option<String>,
    uri: &Uri,
) -> Result<Response, &'static Code> {
    let request = page_request(ctx, uri.query(), attrs)?;
    let after = request
        .after
        .as_deref()
        .map(|a| String::from_utf8(a.to_vec()).map_err(|_| &codes::INVALID_CURSOR))
        .transpose()?;
    let listing = port(ctx)
        .read(PlatformQuery {
            kind,
            tenant,
            key: None,
            after,
            limit: request.size,
        })
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::NOT_FOUND)?;
    let items: Vec<Value> = listing
        .items
        .into_iter()
        .map(|i| project(i.body, kind.fields()))
        .filter(|b| request.filter.as_ref().is_none_or(|f| matches(f, b)))
        .collect();
    let mut response = (StatusCode::OK, axum::Json(json!({ "items": items }))).into_response();
    if let Some(last) = listing.last {
        let (name, value) = next_link(ctx, &request, uri.path(), last.as_bytes())?;
        response.headers_mut().insert(name, value);
    }
    Ok(response)
}

async fn get<E: Env>(
    ctx: &Ctx<E>,
    kind: PlatformKind,
    key: Option<String>,
) -> Result<Response, &'static Code> {
    let listing = port(ctx)
        .read(PlatformQuery {
            kind,
            tenant: None,
            key,
            after: None,
            limit: 1,
        })
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::NOT_FOUND)?;
    let item = listing.items.into_iter().next().ok_or(&codes::NOT_FOUND)?;
    Ok((
        StatusCode::OK,
        axum::Json(project(item.body, kind.fields())),
    )
        .into_response())
}

fn object(body: &[u8]) -> Result<Map<String, Value>, &'static Code> {
    let bytes: &[u8] = if body.is_empty() { b"{}" } else { body };
    access_parse::json::check(bytes, bytes.len(), access_parse::json::MAX_DEPTH)
        .map_err(|_| &codes::realm::INVALID_BODY)?;
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(&codes::realm::INVALID_BODY),
    }
}

/// `POST /admin/v1/platform/intents`: `{operation, key?, body}` → the intent the provisioning
/// write compiles to (TN-110). `key` is the tenant a realm or sandbox creation is in.
async fn draft<E: Env>(ctx: &Ctx<E>, raw: &[u8]) -> Result<Response, &'static Code> {
    let mut request = object(raw)?;
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .and_then(|o| ROWS.iter().find(|r| r.operation_id == o))
        .filter(|r| r.access == Access::Write)
        .ok_or(&codes::realm::UNKNOWN_OPERATION)?;
    let key = match request.remove("key") {
        None | Some(Value::Null) => None,
        Some(Value::String(k)) => Some(k),
        Some(_) => return Err(&codes::realm::INVALID_BODY),
    };
    let mut body = match request.remove("body") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(b)) => b,
        Some(_) => return Err(&codes::realm::INVALID_BODY),
    };
    body.remove(AIS_FIELD);
    let write = PlatformWrite {
        domain: ctx.domain,
        operation: operation.operation_id,
        tenant: key.clone(),
        body: Value::Object(body),
        now_ms: now(ctx)?,
    };
    let d = match port(ctx)
        .draft(write)
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
    {
        Drafted::Draft(d) => d,
        Drafted::Rejected(code) => return Err(code),
    };
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "operation": operation.operation_id,
            "key": key,
            "body": d.body,
            "domain": b64url_encode(&d.domain.0),
            "pep": d.pep,
            "intent": b64url_encode(&d.intent),
            "intent_digest": b64url_encode(&d.intent_digest.0),
        })),
    )
        .into_response())
}

/// The created resource and, for a realm, its Genesis summary, each limited to its members.
fn created(kind: PlatformKind, item: Item, out: &mut Map<String, Value>) {
    let mut body = item.body;
    let genesis = body.as_object_mut().and_then(|o| o.remove("genesis"));
    out.insert("resource".to_owned(), project(body, kind.fields()));
    if let Some(g) = genesis {
        out.insert("genesis".to_owned(), project(g, GENESIS_FIELDS));
    }
}

async fn commit<E: Env>(
    ctx: &Ctx<E>,
    kind: PlatformKind,
    tenant: Option<String>,
    raw: &[u8],
) -> Result<Response, &'static Code> {
    let Caller::Write(caller) = &ctx.caller else {
        return Err(&codes::AIS_REQUIRED);
    };
    let mut body = object(raw)?;
    body.remove(AIS_FIELD);
    let write = PlatformWrite {
        domain: ctx.domain,
        operation: ctx.row.operation_id,
        tenant,
        body: Value::Object(body),
        now_ms: now(ctx)?,
    };
    let written = port(ctx)
        .commit(write, caller.clone())
        .await
        .map_err(|_| &codes::UNAVAILABLE)?;
    let (exercise_id, position, resource) = match written {
        Written::Committed {
            exercise_id,
            position,
            resource,
            ..
        } => (exercise_id, position, resource),
        Written::NotAllowed | Written::Accepted { .. } => return Err(&codes::EXERCISE_NOT_ALLOWED),
        Written::Rejected(code) => return Err(code),
    };
    let mut out = Map::new();
    if let Value::Object(o) = (Committed {
        exercise_id,
        position,
    })
    .json()
    {
        out = o;
    }
    if let Some(item) = resource {
        created(kind, item, &mut out);
    }
    Ok((StatusCode::CREATED, axum::Json(Value::Object(out))).into_response())
}
