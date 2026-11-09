//! The one handler every realm resource row is served by: it reads the row's [`super::spec`] and
//! lists, gets, drafts or writes through [`RealmResources`].

use access_kernel::json::b64url_encode;
use axum::Extension;
use axum::body::Bytes;
use axum::extract::RawPathParams;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use super::{Shape, matches, spec};
use crate::api::app::rest::{apply_patch, next_link, page_request, require_match};
use crate::api::app::{Caller, Committed, Ctx};
use crate::api::domain::SurfaceScope;
use crate::api::domain::caller::AIS_FIELD;
use crate::api::domain::conditional::etag;
use crate::api::ports::{
    AuditFormat, AuditProofQuery, AuditQuery, Clock, Drafted, Env, Item, RealmResources,
    ResourceKind, ResourceQuery, ResourceWrite, Written,
};
use crate::problem::{Code, codes};

/// The members a write body carries besides the resource's own.
const VALIDITY: &str = "validity";

fn problem(code: &Code) -> Response {
    code.problem().into_response()
}

pub(super) fn slug(ctx: &Ctx<impl Env>) -> String {
    match &ctx.scope {
        SurfaceScope::Realm(s) => s.clone(),
        SurfaceScope::Platform => String::new(),
    }
}

fn key_of(params: &RawPathParams) -> Option<String> {
    params
        .iter()
        .find(|(k, _)| *k != "slug")
        .map(|(_, v)| v.to_owned())
}

/// The member a created resource's server-assigned id is in.
#[must_use]
pub const fn id_member(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Hooks => "hook_id",
        ResourceKind::Webhooks => "webhook_id",
        _ => "client_id",
    }
}

/// The member a write's one-time secret is shown in: a client's secret, or the key a hook's or
/// webhook's receiver verifies with (`whpk_…` or `whsec_…`).
const fn secret_member(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Hooks | ResourceKind::Webhooks => "verification_key",
        _ => "client_secret",
    }
}

fn tag(kind: ResourceKind, key: Option<&str>, item: &Item) -> String {
    etag(kind.name(), key.unwrap_or(""), &item.version.to_be_bytes())
}

async fn one(
    realm: &dyn RealmResources,
    slug: String,
    kind: ResourceKind,
    key: Option<String>,
) -> Result<Option<Item>, &'static Code> {
    let found = realm
        .read(ResourceQuery {
            slug,
            kind,
            key,
            after: None,
            limit: 1,
        })
        .await
        .map_err(|_| &codes::UNAVAILABLE)?;
    let listing = found.ok_or(&codes::NOT_FOUND)?;
    Ok(listing.items.into_iter().next())
}

/// Serves the realm resource row of `ctx` (OP-151 m.2 M1).
pub async fn serve<E: Env>(
    Extension(ctx): Extension<Ctx<E>>,
    params: RawPathParams,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((kind, shape)) = spec(ctx.row.operation_id) else {
        return problem(&codes::NOT_FOUND);
    };
    let key = key_of(&params);
    let answer = match shape {
        Shape::List(attrs) => list(&ctx, kind, key, attrs, &uri).await,
        Shape::Get => get(&ctx, kind, key).await,
        Shape::Draft => draft(&ctx, &body).await,
        Shape::JobCreate => super::jobs::create(&ctx, &body).await,
        Shape::JobGet => match key {
            Some(k) => super::jobs::get(&ctx, k).await,
            None => Err(&codes::NOT_FOUND),
        },
        Shape::JobItems => match key {
            Some(k) => super::jobs::items(&ctx, k, &uri).await,
            None => Err(&codes::NOT_FOUND),
        },
        Shape::Write { .. } => commit(&ctx, kind, shape, key, &headers, &body).await,
        Shape::Audit => audit(&ctx, &uri).await,
        Shape::AuditProof => audit_proof(&ctx, key).await,
        Shape::Planned(_) => Err(&codes::NOT_YET_SERVED),
    };
    answer.unwrap_or_else(problem)
}

/// A page of a collection; `key` names the resource a nested collection belongs to.
async fn list<E: Env>(
    ctx: &Ctx<E>,
    kind: ResourceKind,
    key: Option<String>,
    attrs: &'static [&'static str],
    uri: &Uri,
) -> Result<Response, &'static Code> {
    let request = page_request(ctx, uri.query(), attrs)?;
    let after = request
        .after
        .as_deref()
        .map(|a| String::from_utf8(a.to_vec()).map_err(|_| &codes::INVALID_CURSOR))
        .transpose()?;
    let listing = ctx
        .api
        .env()
        .realm()
        .read(ResourceQuery {
            slug: slug(ctx),
            kind,
            key,
            after,
            limit: request.size,
        })
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::NOT_FOUND)?;
    let items: Vec<Value> = listing
        .items
        .into_iter()
        .map(|i| i.body)
        .filter(|b| request.filter.as_ref().is_none_or(|f| matches(f, b)))
        .collect();
    let mut response = (StatusCode::OK, axum::Json(json!({ "items": items }))).into_response();
    if let Some(last) = listing.last {
        let (name, value) = next_link(ctx, &request, uri.path(), last.as_bytes())?;
        response.headers_mut().insert(name, value);
    }
    Ok(response)
}

/// A page of the realm's audit stream in the asked rendering (OP-41, OP-44, §17.6.8): only for
/// a read token, oldest first; the reader is the `audit.read` event's actor.
async fn audit<E: Env>(ctx: &Ctx<E>, uri: &Uri) -> Result<Response, &'static Code> {
    let Caller::Read(reader) = &ctx.caller else {
        return Err(&codes::NOT_FOUND);
    };
    let request = page_request(ctx, uri.query(), &[])?;
    let format = match request.params.get(super::FORMAT) {
        None => AuditFormat::Ocsf,
        Some(f) => AuditFormat::parse(f).ok_or(&codes::realm::INVALID_AUDIT_FORMAT)?,
    };
    let after = request
        .after
        .as_deref()
        .map(|a| String::from_utf8(a.to_vec()).map_err(|_| &codes::INVALID_CURSOR))
        .transpose()?;
    let listing = ctx
        .api
        .env()
        .realm()
        .audit(AuditQuery {
            slug: slug(ctx),
            format,
            after,
            limit: request.size,
            reader: reader.token.subject.clone(),
        })
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::NOT_FOUND)?;
    let items: Vec<Value> = listing.items.into_iter().map(|i| i.body).collect();
    let mut response = (StatusCode::OK, axum::Json(json!({ "items": items }))).into_response();
    if let Some(last) = listing.last {
        let (name, value) = next_link(ctx, &request, uri.path(), last.as_bytes())?;
        response.headers_mut().insert(name, value);
    }
    Ok(response)
}

/// One event's inclusion proof in the realm's own audit tree (OP-152 m.7 (d)): only for a read
/// token; the reader is the `audit.read` event's actor (OP-44).
async fn audit_proof<E: Env>(
    ctx: &Ctx<E>,
    event: Option<String>,
) -> Result<Response, &'static Code> {
    let Caller::Read(reader) = &ctx.caller else {
        return Err(&codes::NOT_FOUND);
    };
    let event = event.ok_or(&codes::NOT_FOUND)?;
    let proof = ctx
        .api
        .env()
        .realm()
        .audit_proof(AuditProofQuery {
            slug: slug(ctx),
            event,
            reader: reader.token.subject.clone(),
        })
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::NOT_FOUND)?;
    Ok((StatusCode::OK, axum::Json(proof)).into_response())
}

async fn get<E: Env>(
    ctx: &Ctx<E>,
    kind: ResourceKind,
    key: Option<String>,
) -> Result<Response, &'static Code> {
    let item = one(ctx.api.env().realm(), slug(ctx), kind, key.clone())
        .await?
        .ok_or(&codes::NOT_FOUND)?;
    let mut response = (StatusCode::OK, axum::Json(&item.body)).into_response();
    if let Ok(v) = HeaderValue::from_str(&tag(kind, key.as_deref(), &item)) {
        response.headers_mut().insert(header::ETAG, v);
    }
    Ok(response)
}

pub(super) fn object(body: &[u8]) -> Result<Map<String, Value>, &'static Code> {
    let bytes: &[u8] = if body.is_empty() { b"{}" } else { body };
    access_parse::json::check(bytes, bytes.len(), access_parse::json::MAX_DEPTH)
        .map_err(|_| &codes::realm::INVALID_BODY)?;
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(&codes::realm::INVALID_BODY),
    }
}

/// The body the write compiles from: for a `PATCH`, the current view (or its settings section)
/// with the patch applied; otherwise the body itself. The validity rides along unchanged.
async fn effective<E: Env>(
    ctx: &Ctx<E>,
    kind: ResourceKind,
    shape: Shape,
    key: Option<&str>,
    mut body: Map<String, Value>,
    current: Option<&Item>,
) -> Result<Value, &'static Code> {
    body.remove(AIS_FIELD);
    let Shape::Write { patch, section, .. } = shape else {
        return Ok(Value::Object(body));
    };
    let Some(members) = patch else {
        return Ok(Value::Object(body));
    };
    let fetched;
    let current = if let Some(c) = current {
        c
    } else {
        fetched = one(
            ctx.api.env().realm(),
            slug(ctx),
            kind,
            key.map(String::from),
        )
        .await?
        .ok_or(&codes::NOT_FOUND)?;
        &fetched
    };
    let validity = body.remove(VALIDITY);
    let mut target = match section {
        Some(s) => current.body.get(s).cloned().unwrap_or(Value::Null),
        None => current.body.clone(),
    };
    if let Value::Object(t) = &mut target {
        t.retain(|k, _| members.contains(&k.as_str()));
    }
    let patch_bytes = serde_json::to_vec(&Value::Object(body)).map_err(|_| &codes::INTERNAL)?;
    apply_patch(&mut target, &patch_bytes, members)?;
    if let (Value::Object(t), Some(v)) = (&mut target, validity) {
        t.insert(VALIDITY.to_owned(), v);
    }
    Ok(target)
}

fn now<E: Env>(ctx: &Ctx<E>) -> Result<u64, &'static Code> {
    let clock: &dyn Clock = ctx.api.env().clock();
    clock.now_ms().map_err(|_| &codes::UNAVAILABLE)
}

/// `POST …/intents`: `{operation, key?, body}` → the intent the write compiles to (TN-110).
async fn draft<E: Env>(ctx: &Ctx<E>, raw: &[u8]) -> Result<Response, &'static Code> {
    let mut request = object(raw)?;
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .and_then(|o| super::ROWS.iter().find(|r| r.operation_id == o))
        .filter(|r| r.access == crate::api::manifest::Access::Write)
        .ok_or(&codes::realm::UNKNOWN_OPERATION)?;
    let (kind, shape) = spec(operation.operation_id).ok_or(&codes::realm::UNKNOWN_OPERATION)?;
    // TN-125
    if shape == Shape::JobCreate {
        let Some(Value::Object(body)) = request.remove("body") else {
            return Err(&codes::realm::INVALID_JOB);
        };
        let d = super::jobs::draft_digest(&body)?;
        return Ok((
            StatusCode::OK,
            axum::Json(json!({
                "operation": operation.operation_id,
                "key": null,
                "body": body,
                "domain": b64url_encode(&ctx.domain.0),
                "intent_digest": b64url_encode(&d),
            })),
        )
            .into_response());
    }
    let key = match request.remove("key") {
        None | Some(Value::Null) => None,
        Some(Value::String(k)) => Some(k),
        Some(_) => return Err(&codes::realm::INVALID_BODY),
    };
    let body = match request.remove("body") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(b)) => b,
        Some(_) => return Err(&codes::realm::INVALID_BODY),
    };
    let effective = effective(ctx, kind, shape, key.as_deref(), body.clone(), None).await?;
    let write = ResourceWrite {
        slug: slug(ctx),
        domain: ctx.domain,
        operation: operation.operation_id,
        key: key.clone(),
        body: effective,
        now_ms: now(ctx)?,
    };
    let drafted = ctx
        .api
        .env()
        .realm()
        .draft(write)
        .await
        .map_err(|_| &codes::UNAVAILABLE)?;
    let d = match drafted {
        Drafted::Draft(d) => d,
        Drafted::Rejected(code) => return Err(code),
    };
    let send = if matches!(shape, Shape::Write { patch: Some(_), .. }) {
        let mut b = body;
        if let Some(v) = d.body.get(VALIDITY) {
            b.insert(VALIDITY.to_owned(), v.clone());
        }
        Value::Object(b)
    } else {
        d.body.clone()
    };
    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "operation": operation.operation_id,
            "key": key,
            "body": send,
            "domain": b64url_encode(&d.domain.0),
            "pep": d.pep,
            "intent": b64url_encode(&d.intent),
            "intent_digest": b64url_encode(&d.intent_digest.0),
        })),
    )
        .into_response())
}

pub(super) async fn commit<E: Env>(
    ctx: &Ctx<E>,
    kind: ResourceKind,
    shape: Shape,
    key: Option<String>,
    headers: &HeaderMap,
    raw: &[u8],
) -> Result<Response, &'static Code> {
    let Caller::Write(caller) = &ctx.caller else {
        return Err(&codes::AIS_REQUIRED);
    };
    let Shape::Write {
        conditional,
        creates,
        patch,
        ..
    } = shape
    else {
        return Err(&codes::INTERNAL);
    };
    let body = object(raw)?;
    let current = if conditional {
        let current = one(ctx.api.env().realm(), slug(ctx), kind, key.clone()).await?;
        match &current {
            // OP-65
            Some(item) => require_match(headers, Some(&tag(kind, key.as_deref(), item)))?,
            None if patch.is_some() => return Err(&codes::NOT_FOUND),
            None if headers.contains_key(header::IF_MATCH) => {
                return Err(&codes::PRECONDITION_FAILED);
            }
            None => {}
        }
        current
    } else {
        None
    };
    let effective = effective(ctx, kind, shape, key.as_deref(), body, current.as_ref()).await?;
    let write = ResourceWrite {
        slug: slug(ctx),
        domain: ctx.domain,
        operation: ctx.row.operation_id,
        key: key.clone(),
        body: effective,
        now_ms: now(ctx)?,
    };
    let written = ctx
        .api
        .env()
        .realm()
        .commit(write, caller.clone())
        .await
        .map_err(|_| &codes::UNAVAILABLE)?;
    let (exercise_id, position, resource, secret) = match written {
        Written::Committed {
            exercise_id,
            position,
            resource,
            secret,
        } => (exercise_id, position, resource, secret),
        Written::NotAllowed | Written::Accepted { .. } => return Err(&codes::EXERCISE_NOT_ALLOWED),
        Written::Rejected(code) => return Err(code),
    };
    let committed = Committed {
        exercise_id,
        position,
    };
    let mut out = committed.json();
    if let Value::Object(o) = &mut out {
        if let Some(r) = &resource {
            o.insert("resource".to_owned(), r.body.clone());
        }
        if let Some(s) = secret {
            // CR-38, TN-135, TN-136
            let member = match ctx.row.operation_id {
                // TN-90
                "claimOrganizationDomain" => "challenge",
                // TN-86
                "exportAccounts" => "bundle",
                // OP-153 m.18 (e)
                "bindAccount" => "offer",
                _ => secret_member(kind),
            };
            o.insert(member.to_owned(), Value::String(s));
        }
        // IDI-4
        if ctx.row.operation_id == "putRpId" {
            o.insert("irreversible".to_owned(), Value::Bool(true));
        }
    }
    let status = if creates {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mut response = (status, axum::Json(out)).into_response();
    if let Some(item) = &resource {
        let id = key
            .as_deref()
            .or_else(|| item.body.get(id_member(kind)).and_then(Value::as_str));
        if let Ok(v) = HeaderValue::from_str(&tag(kind, id, item)) {
            response.headers_mut().insert(header::ETAG, v);
        }
    }
    Ok(response)
}
