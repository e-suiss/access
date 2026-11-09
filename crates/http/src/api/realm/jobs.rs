//! Bulk jobs (TN-125, X20, §12.5.4): a set of realm writes, each its own Exercise under its own
//! AIS. There is no atomicity and no bulk Exercise. The job envelope is itself a write: its AIS
//! signs the job digest, which names every item's operation, key and AIS, so the envelope
//! attributes the set and each item attributes its own change.
//!
//! `POST …/jobs` answers `202` with the job; the items then run in order. In a `sequential` job a
//! failed item fails every later one with `424` (`failed_dependency`); in a `parallel` job the
//! items are independent. Each item takes from the caller's rate budget, and a throttled item is
//! counted on the envelope (never a `200` with hidden `429`s). `GET …/jobs/{job_id}` is the
//! envelope, `GET …/jobs/{job_id}/items` the per-item file: each line is the Exercise reference
//! or the problem that refused it. Jobs are shown for 7 days and never deleted (OP-73).
//!
//! A job may also revoke or amend Grants (E17, §8.17.9.8): an item `revokeGrant` or
//! `amendGrant` keyed by the Grant carries the ADP `commit` of its own meta-action (the intent
//! and the payload the console drafted, the nonce, basis and capacity) and its own AIS, and is
//! decided as its own Exercise; the preview of the set is the `bulk-impact` search.

use access_kernel::json::b64url_decode;
use axum::body::{Bytes, to_bytes};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
use suiss_crypto::digest::context_digest;

use super::handlers::{commit, object, slug};
use super::{ROWS, Shape, spec};
use crate::api::app::rest::{next_link, page_request};
use crate::api::app::{Caller, Ctx};
use crate::api::domain::caller::{AIS_FIELD, ais_kid, verify_ais};
use crate::api::domain::rate::{self, BucketKey};
use crate::api::manifest::{Access, Answer, GROUPS};
use crate::api::ports::{Env, JobItem, JobView, NewJob, Surfaces as _};
use crate::problem::{Code, codes};

/// Most items in one job (TN-125: the envelope is bounded).
pub const MAX_ITEMS: usize = 100;

/// How long a job's results are shown (TN-125, PD): 7 days.
pub const RETENTION_MS: u64 = 7 * 24 * 3_600_000;

/// Context of a job digest, the intent the envelope's AIS signs.
pub const JOB_CONTEXT: &str = "access/admin-job/v1";

/// The member of an item that carries its `If-Match`.
const IF_MATCH: &str = "if_match";

/// The job operations that are core meta-action writes (E17), with their meta-action.
pub const META_OPERATIONS: [(&str, &str); 6] = [
    ("revokeGrant", "grant_revoke"),
    ("amendGrant", "grant_amend"),
    ("issueRoleGrant", "grant_issue"),
    ("proposeOwnershipHandover", "anchor_transfer"),
    ("completeOwnershipHandover", "anchor_transfer"),
    ("issueAutojoinGrant", "grant_issue"),
];

fn id16(text: &str) -> Option<[u8; 16]> {
    b64url_decode(text)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
}

/// The record an item names by its key (TN-89 (3), TN-91): `org:account` for a role Grant,
/// `org:from:to` for a handover's proposal, `org:handover` for its completion and `org` for
/// an autojoin role Grant (OP-153 m.25 (i) (3)).
#[must_use]
pub fn meta_target(operation: &str, key: &str) -> Option<crate::api::ports::MetaTarget> {
    use crate::api::ports::MetaTarget;
    let mut parts = key.split(':');
    let org = id16(parts.next()?)?;
    let target = match operation {
        "issueRoleGrant" => {
            let (_, account) = role_key(key)?;
            MetaTarget::Role(org, account.to_owned())
        }
        "proposeOwnershipHandover" => {
            let from = parts.next().filter(|a| !a.is_empty())?;
            let to = parts.next().filter(|a| !a.is_empty())?;
            MetaTarget::ProposeHandover(org, from.to_owned(), to.to_owned())
        }
        "completeOwnershipHandover" => MetaTarget::CompleteHandover(org, id16(parts.next()?)?),
        "issueAutojoinGrant" => MetaTarget::Autojoin(org),
        _ => return None,
    };
    (operation == "issueRoleGrant" || parts.next().is_none()).then_some(target)
}

/// The key of an `issueRoleGrant` item: the organization's id and the member's `account_id`
/// (TN-89 (3)).
#[must_use]
pub fn role_key(key: &str) -> Option<([u8; 16], &str)> {
    let (org, account) = key.split_once(':')?;
    let org = b64url_decode(org)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())?;
    (!account.is_empty()).then_some((org, account))
}

/// One item as submitted.
#[derive(Clone, Debug)]
struct Item {
    operation: &'static str,
    key: Option<String>,
    body: Map<String, Value>,
    if_match: Option<String>,
    ais: Vec<u8>,
    meta: Option<access_authority_core::domain::Request>,
}

/// A job as submitted.
#[derive(Clone, Debug)]
struct Submitted {
    mode: &'static str,
    items: Vec<Item>,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    context_digest("access/admin-job-item/v1", bytes).0
}

/// The job digest: `context_digest("access/admin-job/v1", dCBOR([mode, [[operation, [key?],
/// H(ais)], …]]))`.
fn digest(job: &Submitted) -> Result<[u8; 32], &'static Code> {
    let items = job
        .items
        .iter()
        .map(|i| {
            Cbor::Array(vec![
                Cbor::text(i.operation),
                Cbor::Array(i.key.as_deref().map(Cbor::text).into_iter().collect()),
                Cbor::Bytes(sha256(&i.ais).to_vec()),
            ])
        })
        .collect();
    let v = Cbor::Array(vec![Cbor::text(job.mode), Cbor::Array(items)]);
    let bytes = dcbor::encode(&v, Limits::CEILING).map_err(|_| &codes::INTERNAL)?;
    Ok(context_digest(JOB_CONTEXT, &bytes).0)
}

fn parse(raw: &[u8]) -> Result<Submitted, &'static Code> {
    let mut body = object(raw)?;
    body.remove(AIS_FIELD);
    let mode = match body.remove("mode") {
        Some(Value::String(m)) if m == "sequential" => "sequential",
        Some(Value::String(m)) if m == "parallel" => "parallel",
        _ => return Err(&codes::realm::INVALID_JOB),
    };
    let Some(Value::Array(ops)) = body.remove("operations") else {
        return Err(&codes::realm::INVALID_JOB);
    };
    if !body.is_empty() || ops.is_empty() || ops.len() > MAX_ITEMS {
        return Err(&codes::realm::INVALID_JOB);
    }
    let items = ops
        .into_iter()
        .map(|op| {
            let Value::Object(mut op) = op else {
                return Err(&codes::realm::INVALID_JOB);
            };
            // E17
            if let Some(item) = meta_item(&mut op)? {
                return Ok(item);
            }
            // TN-125
            let row = op
                .remove("operation")
                .and_then(|o| {
                    o.as_str()
                        .and_then(|o| ROWS.iter().find(|r| r.operation_id == o))
                })
                .filter(|r| r.access == Access::Write && r.answer == Answer::Replay)
                .filter(|r| matches!(spec(r.operation_id), Some((_, Shape::Write { .. }))))
                .ok_or(&codes::realm::JOB_OPERATION_NOT_ALLOWED)?;
            let key = match op.remove("key") {
                None | Some(Value::Null) => None,
                Some(Value::String(k)) if k.len() <= 256 => Some(k),
                Some(_) => return Err(&codes::realm::INVALID_JOB),
            };
            let if_match = match op.remove(IF_MATCH) {
                None | Some(Value::Null) => None,
                Some(Value::String(t)) => Some(t),
                Some(_) => return Err(&codes::realm::INVALID_JOB),
            };
            let mut body = match op.remove("body") {
                None | Some(Value::Null) => Map::new(),
                Some(Value::Object(b)) => b,
                Some(_) => return Err(&codes::realm::INVALID_JOB),
            };
            if !op.is_empty() {
                return Err(&codes::realm::INVALID_JOB);
            }
            let ais = body
                .remove(AIS_FIELD)
                .and_then(|a| a.as_str().and_then(|a| b64url_decode(a).ok()))
                .filter(|a| !a.is_empty())
                .ok_or(&codes::AIS_REQUIRED)?;
            Ok(Item {
                operation: row.operation_id,
                key,
                body,
                if_match,
                ais,
                meta: None,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Submitted { mode, items })
}

/// A meta-action item (E17): `{operation, key, body: {ais, intent, payload, nonce, basis,
/// capacity}}`, its intent the meta-action of the operation on the Grant `key`, its payload
/// that Grant's revoke or amend, and the intent's `opaque.payload` that payload's digest.
fn meta_item(op: &mut Map<String, Value>) -> Result<Option<Item>, &'static Code> {
    let Some((operation, action)) = op
        .get("operation")
        .and_then(Value::as_str)
        .and_then(|o| META_OPERATIONS.iter().find(|(n, _)| *n == o))
    else {
        return Ok(None);
    };
    op.remove("operation");
    let key = match op.remove("key") {
        Some(Value::String(k)) if k.len() <= 160 => k,
        _ => return Err(&codes::realm::INVALID_JOB),
    };
    let Some(Value::Object(mut body)) = op.remove("body") else {
        return Err(&codes::realm::INVALID_JOB);
    };
    if !op.is_empty() {
        return Err(&codes::realm::INVALID_JOB);
    }
    let ais = body
        .remove(AIS_FIELD)
        .and_then(|a| a.as_str().and_then(|a| b64url_decode(a).ok()))
        .filter(|a| !a.is_empty())
        .ok_or(&codes::AIS_REQUIRED)?;
    let mut context = body.clone();
    context.insert(String::from("mode"), Value::from("commit"));
    context.insert(String::from("domain"), Value::from(DOMAIN_PLACEHOLDER));
    let raw = serde_json::to_vec(&json!({ "context": context })).map_err(|_| &codes::INTERNAL)?;
    let decoded = crate::adp::domain::decode_context(&raw, 1 << 20)
        .map_err(|_| &codes::realm::INVALID_JOB)?;
    let request = decoded.request;
    let (grant, named) = if *action == "anchor_transfer" {
        // TN-91
        meta_target(operation, &key).ok_or(&codes::realm::INVALID_JOB)?;
        if !matches!(
            &request.payload,
            Some(access_kernel::meta::Payload::AnchorTransfer { .. })
        ) {
            return Err(&codes::realm::JOB_OPERATION_NOT_ALLOWED);
        }
        (
            access_kernel::model::Id([0; 16]),
            access_kernel::model::Id([0; 16]),
        )
    } else if *action == "grant_issue" {
        // TN-89 (3)
        role_key(&key).ok_or(&codes::realm::INVALID_JOB)?;
        if !matches!(
            &request.payload,
            Some(access_kernel::meta::Payload::GrantIssue(_))
        ) {
            return Err(&codes::realm::JOB_OPERATION_NOT_ALLOWED);
        }
        (
            access_kernel::model::Id([0; 16]),
            access_kernel::model::Id([0; 16]),
        )
    } else {
        let grant = b64url_decode(&key)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
            .map(access_kernel::model::Id)
            .ok_or(&codes::realm::INVALID_JOB)?;
        let named = match &request.payload {
            Some(
                access_kernel::meta::Payload::GrantRevoke { grant: g }
                | access_kernel::meta::Payload::GrantAmend { grant: g, .. },
            ) => *g,
            _ => return Err(&codes::realm::JOB_OPERATION_NOT_ALLOWED),
        };
        (grant, named)
    };
    let digest = request
        .payload
        .as_ref()
        .and_then(|p| p.digest().ok())
        .ok_or(&codes::realm::INVALID_JOB)?;
    if named != grant
        || request
            .payload
            .as_ref()
            .map(access_kernel::meta::Payload::action)
            != Some(*action)
        || request.intent.action != access_kernel::meta::core_action(action)
        || request
            .intent
            .opaque
            .get(access_kernel::meta::PAYLOAD_PARAM)
            != Some(&digest)
    {
        return Err(&codes::realm::JOB_OPERATION_NOT_ALLOWED);
    }
    Ok(Some(Item {
        operation,
        key: Some(key),
        body,
        if_match: None,
        ais,
        meta: Some(request),
    }))
}

/// The domain a meta item is decoded with before the realm's own replaces it.
const DOMAIN_PLACEHOLDER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// The intent digest a job's envelope AIS signs, for `POST …/intents` (TN-110).
///
/// # Errors
/// `invalid-job`, `job-operation-not-allowed` or `ais-required`.
pub fn draft_digest(body: &Map<String, Value>) -> Result<[u8; 32], &'static Code> {
    let raw = serde_json::to_vec(body).map_err(|_| &codes::INTERNAL)?;
    digest(&parse(&raw)?)
}

fn rfc3339(ms: u64) -> String {
    let nanos = i128::from(ms).saturating_mul(1_000_000);
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

fn job_json(j: &JobView) -> Value {
    json!({
        "job_id": j.id,
        "mode": j.mode,
        "status": j.status,
        "items": j.items,
        "committed": j.committed,
        "failed": j.failed,
        "throttled": j.throttled,
        "created_at": rfc3339(j.created_ms),
        "finished_at": j.finished_ms.map(rfc3339),
        "expires_at": rfc3339(j.expires_ms),
    })
}

fn item_json(i: &JobItem) -> Value {
    json!({
        "index": i.index,
        "operation": i.operation,
        "key": i.key,
        "status": i.status,
        "http_status": i.http_status,
        "problem": i.problem,
        "exercise_id": i.exercise_id,
        "position": i.position.map(|p| p.to_string()),
    })
}

fn now<E: Env>(ctx: &Ctx<E>) -> Result<u64, &'static Code> {
    ctx.api
        .env()
        .clock()
        .now_ms()
        .map_err(|_| &codes::UNAVAILABLE)
}

/// `POST …/jobs`.
pub(super) async fn create<E: Env>(ctx: &Ctx<E>, raw: &[u8]) -> Result<Response, &'static Code> {
    let Caller::Write(caller) = &ctx.caller else {
        return Err(&codes::AIS_REQUIRED);
    };
    let job = parse(raw)?;
    // TN-110
    if caller.statement.intent.0 != digest(&job)? {
        return Err(&codes::realm::JOB_INTENT_MISMATCH);
    }
    let now_ms = now(ctx)?;
    let new = NewJob {
        mode: job.mode,
        actor: caller.kid,
        items: job
            .items
            .iter()
            .map(|i| (i.operation.to_owned(), i.key.clone()))
            .collect(),
        created_ms: now_ms,
        expires_ms: now_ms.saturating_add(RETENTION_MS),
    };
    let jobs = ctx.api.env().jobs();
    let id = jobs
        .create(slug(ctx), new)
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::NOT_FOUND)?;
    let view = jobs
        .read(slug(ctx), id.clone(), now_ms)
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::UNAVAILABLE)?;
    let runner = ctx.clone();
    let run_id = id.clone();
    tokio::spawn(async move { run(runner, run_id, job).await });
    let mut response = (StatusCode::ACCEPTED, axum::Json(job_json(&view))).into_response();
    let location = format!("/admin/v1/realms/{}/jobs/{id}", slug(ctx));
    if let Ok(v) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, v);
    }
    Ok(response)
}

/// What one item did.
fn outcome(index: u32, item: &Item, status: &str, http: u16, problem: Option<&str>) -> JobItem {
    JobItem {
        index,
        operation: item.operation.to_owned(),
        key: item.key.clone(),
        status: status.to_owned(),
        http_status: Some(http),
        problem: problem.map(String::from),
        exercise_id: None,
        position: None,
    }
}

fn refused(index: u32, item: &Item, code: &Code) -> JobItem {
    let status = if code == &codes::EXERCISE_NOT_ALLOWED {
        "not_allowed"
    } else if code == &codes::UNAVAILABLE {
        "unavailable"
    } else if code == &codes::RATE_LIMITED {
        "throttled"
    } else {
        "rejected"
    };
    outcome(index, item, status, code.status, Some(code.code))
}

/// Runs one meta-action item (E17): its own Exercise under its own verified AIS.
async fn meta_one<E: Env>(
    ctx: &Ctx<E>,
    index: u32,
    item: &Item,
    request: &access_authority_core::domain::Request,
    caller: crate::api::domain::caller::WriteCaller,
) -> JobItem {
    let mut request = request.clone();
    request.domain = ctx.domain;
    let write = crate::api::ports::MetaWrite {
        slug: slug(ctx),
        target: item
            .key
            .as_deref()
            .and_then(|k| meta_target(item.operation, k)),
        request,
    };
    match ctx.api.env().realm().exercise(write, caller).await {
        Ok(crate::api::ports::Written::Committed {
            exercise_id,
            position,
            ..
        }) => JobItem {
            exercise_id: Some(access_kernel::json::b64url_encode(&exercise_id.0)),
            position: Some(position),
            ..outcome(index, item, "committed", 200, None)
        },
        Ok(crate::api::ports::Written::NotAllowed) => {
            refused(index, item, &codes::EXERCISE_NOT_ALLOWED)
        }
        // TN-91
        Ok(crate::api::ports::Written::Accepted { .. }) => {
            outcome(index, item, "accepted", 202, None)
        }
        Ok(crate::api::ports::Written::Rejected(code)) => refused(index, item, code),
        Err(_) => refused(index, item, &codes::UNAVAILABLE),
    }
}

/// Runs one item as its own write under its own AIS (TN-125).
async fn one<E: Env>(ctx: &Ctx<E>, index: u32, item: &Item, actor: [u8; 32]) -> JobItem {
    let Caller::Write(_) = &ctx.caller else {
        return refused(index, item, &codes::AIS_REQUIRED);
    };
    let env = ctx.api.env();
    let Ok(now_ms) = env.clock().now_ms() else {
        return refused(index, item, &codes::UNAVAILABLE);
    };
    // TN-127, E17
    let row = match (
        &item.meta,
        ROWS.iter().find(|r| r.operation_id == item.operation),
    ) {
        (Some(_), _) => ctx.row,
        (None, Some(row)) => row,
        (None, None) => return refused(index, item, &codes::realm::JOB_OPERATION_NOT_ALLOWED),
    };
    let bucket = BucketKey {
        layer: "actor",
        scope: ctx.scope.key(),
        method: row.verb.method().as_str().to_owned(),
        group: rate::group_of(row.path, GROUPS),
        caller: Some(actor),
    };
    if !env
        .limiter()
        .take(&bucket, rate::actor_quota(row.surface, true), now_ms)
        .allowed
    {
        return refused(index, item, &codes::RATE_LIMITED);
    }
    // TN-110, PI-7
    let Ok(kid) = ais_kid(&item.ais) else {
        return refused(index, item, &codes::AIS_INVALID);
    };
    if kid != actor {
        return refused(index, item, &codes::AIS_REJECTED);
    }
    let key = match env.surfaces().instance_key(ctx.domain, kid, now_ms).await {
        Ok(Some(k)) => k,
        Ok(None) => return refused(index, item, &codes::AIS_REJECTED),
        Err(_) => return refused(index, item, &codes::UNAVAILABLE),
    };
    let Ok(caller) = verify_ais(item.ais.clone(), kid, &key, &ctx.domain, now_ms) else {
        return refused(index, item, &codes::AIS_REJECTED);
    };
    // E17
    if let Some(request) = &item.meta {
        return meta_one(ctx, index, item, request, caller).await;
    }
    let Some((resource, shape)) = spec(item.operation) else {
        return refused(index, item, &codes::realm::JOB_OPERATION_NOT_ALLOWED);
    };
    let item_ctx = Ctx {
        row,
        caller: Caller::Write(caller),
        ..ctx.clone()
    };
    let mut headers = HeaderMap::new();
    if let Some(tag) = item
        .if_match
        .as_deref()
        .and_then(|t| HeaderValue::from_str(t).ok())
    {
        headers.insert(header::IF_MATCH, tag);
    }
    let Ok(raw) = serde_json::to_vec(&Value::Object(item.body.clone())) else {
        return refused(index, item, &codes::INTERNAL);
    };
    let response = match commit(&item_ctx, resource, shape, item.key.clone(), &headers, &raw).await
    {
        Ok(r) => r,
        Err(code) => return refused(index, item, code),
    };
    let http = response.status().as_u16();
    let body: Bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    let answer: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let exercise = answer.get("exercise_id").and_then(Value::as_str);
    let position = answer
        .get("position")
        .and_then(Value::as_str)
        .and_then(|p| p.parse().ok());
    match exercise {
        Some(e) => JobItem {
            exercise_id: Some(e.to_owned()),
            position,
            ..outcome(index, item, "committed", http, None)
        },
        None => refused(index, item, &codes::UNAVAILABLE),
    }
}

/// Runs the job's items in order and records each, then finishes the job.
async fn run<E: Env>(ctx: Ctx<E>, id: String, job: Submitted) {
    let Caller::Write(caller) = &ctx.caller else {
        return;
    };
    let actor = caller.kid;
    let jobs = ctx.api.env().jobs();
    let (mut committed, mut total) = (0_u32, 0_u32);
    let mut blocked = false;
    for (i, item) in job.items.iter().enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        total = total.saturating_add(1);
        let result = if blocked {
            // TN-125
            outcome(
                index,
                item,
                "failed_dependency",
                424,
                Some(codes::realm::FAILED_DEPENDENCY.code),
            )
        } else {
            one(&ctx, index, item, actor).await
        };
        if result.status == "committed" || result.status == "accepted" {
            committed = committed.saturating_add(1);
        } else if job.mode == "sequential" {
            blocked = true;
        }
        if jobs.record(slug(&ctx), id.clone(), result).await.is_err() {
            tracing::warn!(
                event = "api.job.unrecorded",
                outcome = "error",
                "a job item's outcome was not recorded"
            );
        }
    }
    let status = if committed == total {
        "succeeded"
    } else if committed == 0 {
        "failed"
    } else {
        "partial"
    };
    let now_ms = ctx.api.env().clock().now_ms().unwrap_or_default();
    if jobs.finish(slug(&ctx), id, status, now_ms).await.is_err() {
        tracing::warn!(
            event = "api.job.unrecorded",
            outcome = "error",
            "a job's end was not recorded"
        );
    }
}

/// `GET …/jobs/{job_id}`.
pub(super) async fn get<E: Env>(ctx: &Ctx<E>, id: String) -> Result<Response, &'static Code> {
    let view = ctx
        .api
        .env()
        .jobs()
        .read(slug(ctx), id, now(ctx)?)
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::NOT_FOUND)?;
    Ok((StatusCode::OK, axum::Json(job_json(&view))).into_response())
}

/// `GET …/jobs/{job_id}/items`: the per-item file, in item order.
pub(super) async fn items<E: Env>(
    ctx: &Ctx<E>,
    id: String,
    uri: &Uri,
) -> Result<Response, &'static Code> {
    let request = page_request(ctx, uri.query(), &["status", "operation"])?;
    let after = request
        .after
        .as_deref()
        .map(|a| {
            <[u8; 4]>::try_from(a)
                .map(u32::from_be_bytes)
                .map_err(|_| &codes::INVALID_CURSOR)
        })
        .transpose()?;
    let jobs = ctx.api.env().jobs();
    jobs.read(slug(ctx), id.clone(), now(ctx)?)
        .await
        .map_err(|_| &codes::UNAVAILABLE)?
        .ok_or(&codes::NOT_FOUND)?;
    let page = jobs
        .items(slug(ctx), id, after, request.size)
        .await
        .map_err(|_| &codes::UNAVAILABLE)?;
    let last = (u32::try_from(page.len()).ok() == Some(request.size))
        .then(|| page.last().map(|i| i.index))
        .flatten();
    let items: Vec<Value> = page
        .iter()
        .map(item_json)
        .filter(|b| request.filter.as_ref().is_none_or(|f| super::matches(f, b)))
        .collect();
    let mut response = (StatusCode::OK, axum::Json(json!({ "items": items }))).into_response();
    if let Some(last) = last {
        let (name, value) = next_link(ctx, &request, uri.path(), &last.to_be_bytes())?;
        response.headers_mut().insert(name, value);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use access_kernel::json::b64url_encode;

    use super::*;

    fn body(ops: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"mode": "sequential", "operations": ops})).unwrap_or_default()
    }

    // TN-125
    #[test]
    fn a_job_names_bounded_replayable_writes_each_with_its_ais() {
        let ais = b64url_encode(b"x");
        let ok = json!([{"operation": "suspendAccount", "key": "acc_1", "body": {"ais": ais}}]);
        assert!(parse(&body(&ok)).is_ok());
        let secret = json!([{"operation": "rotateClientSecret", "key": "c", "body": {"ais": ais}}]);
        assert_eq!(
            parse(&body(&secret)).err(),
            Some(&codes::realm::JOB_OPERATION_NOT_ALLOWED)
        );
        let read = json!([{"operation": "getClient", "key": "c", "body": {"ais": ais}}]);
        assert_eq!(
            parse(&body(&read)).err(),
            Some(&codes::realm::JOB_OPERATION_NOT_ALLOWED)
        );
        let no_ais = json!([{"operation": "suspendAccount", "key": "acc_1"}]);
        assert_eq!(parse(&body(&no_ais)).err(), Some(&codes::AIS_REQUIRED));
        let many: Vec<Value> = (0..=MAX_ITEMS)
            .map(|_| json!({"operation": "suspendAccount", "key": "a", "body": {"ais": ais}}))
            .collect();
        assert_eq!(
            parse(&body(&Value::Array(many))).err(),
            Some(&codes::realm::INVALID_JOB)
        );
        assert_eq!(
            parse(&serde_json::to_vec(&json!({"mode": "atomic", "operations": ok})).unwrap()).err(),
            Some(&codes::realm::INVALID_JOB)
        );
    }

    // TN-110, TN-125
    #[test]
    fn the_job_digest_binds_every_item() {
        let a = b64url_encode(b"a");
        let b = b64url_encode(b"b");
        let item = |ais: &str, key: &str| json!({"operation": "suspendAccount", "key": key, "body": {"ais": ais}});
        let d = |ops: Value, mode: &str| {
            let raw = serde_json::to_vec(&json!({"mode": mode, "operations": ops})).unwrap();
            digest(&parse(&raw).unwrap()).unwrap()
        };
        let base = d(json!([item(&a, "k1"), item(&b, "k2")]), "sequential");
        assert_ne!(
            base,
            d(json!([item(&b, "k2"), item(&a, "k1")]), "sequential")
        );
        assert_ne!(
            base,
            d(json!([item(&a, "k1"), item(&a, "k2")]), "sequential")
        );
        assert_ne!(
            base,
            d(json!([item(&a, "k1"), item(&b, "k3")]), "sequential")
        );
        assert_ne!(base, d(json!([item(&a, "k1"), item(&b, "k2")]), "parallel"));
        assert_eq!(
            base,
            d(json!([item(&a, "k1"), item(&b, "k2")]), "sequential")
        );
    }

    fn revoke_item(key: [u8; 16], payload_grant: [u8; 16], action: &str) -> Value {
        let payload = access_kernel::meta::Payload::GrantRevoke {
            grant: access_kernel::model::Id(payload_grant),
        };
        let intent = access_kernel::intent::IntentEnvelope {
            provenance: std::collections::BTreeMap::new(),
            action: access_kernel::meta::core_action(action),
            resources: vec![access_kernel::model::ResourceRef {
                namespace: String::from("access.grant"),
                path: vec![String::from("g")],
                incarnation: 0,
            }],
            params: std::collections::BTreeMap::new(),
            opaque: std::collections::BTreeMap::from([(
                String::from("payload"),
                payload.digest().unwrap(),
            )]),
            recipient: None,
            purpose: None,
            context: access_kernel::intent::ContextRefs::default(),
            validity: access_kernel::model::Window { from: 0, until: 9 },
        };
        let mut wire = crate::console::drafts::wire(&intent);
        wire["validity"] = json!({ "from": 0, "until": 9 });
        json!({
            "operation": "revokeGrant",
            "key": b64url_encode(&key),
            "body": {
                "ais": b64url_encode(b"x"),
                "intent": wire,
                "payload": b64url_encode(&access_kernel::codec::Canonical::to_bytes(&payload).unwrap()),
                "nonce": b64url_encode(&[7; 16]),
                "basis": { "anchor": b64url_encode(&[1; 16]) },
                "capacity": "own",
            },
        })
    }

    // E17, TN-125, TN-110
    #[test]
    fn a_grant_item_names_its_own_meta_action_on_its_grant() {
        let ok = json!([revoke_item([5; 16], [5; 16], "grant_revoke")]);
        let job = parse(&body(&ok)).unwrap();
        assert_eq!(job.items[0].operation, "revokeGrant");
        assert!(
            job.items[0]
                .meta
                .as_ref()
                .is_some_and(|r| r.payload.is_some())
        );
        for refused in [
            revoke_item([6; 16], [5; 16], "grant_revoke"),
            revoke_item([5; 16], [5; 16], "grant_amend"),
        ] {
            assert_eq!(
                parse(&body(&json!([refused]))).err(),
                Some(&codes::realm::JOB_OPERATION_NOT_ALLOWED)
            );
        }
        let mut amend = revoke_item([5; 16], [5; 16], "grant_revoke");
        amend["operation"] = json!("amendGrant");
        assert_eq!(
            parse(&body(&json!([amend]))).err(),
            Some(&codes::realm::JOB_OPERATION_NOT_ALLOWED)
        );
        let mut no_ais = revoke_item([5; 16], [5; 16], "grant_revoke");
        no_ais["body"].as_object_mut().unwrap().remove("ais");
        assert_eq!(
            parse(&body(&json!([no_ais]))).err(),
            Some(&codes::AIS_REQUIRED)
        );
    }

    // TN-91, TN-89 (3)
    #[test]
    fn a_meta_items_key_names_its_role_or_handover() {
        use crate::api::ports::MetaTarget;
        let org = access_kernel::json::b64url_encode(&[0x0a; 16]);
        let h = access_kernel::json::b64url_encode(&[0x0b; 16]);
        assert_eq!(
            meta_target("issueRoleGrant", &format!("{org}:usr_1")),
            Some(MetaTarget::Role([0x0a; 16], String::from("usr_1")))
        );
        assert_eq!(
            meta_target("proposeOwnershipHandover", &format!("{org}:usr_1:usr_2")),
            Some(MetaTarget::ProposeHandover(
                [0x0a; 16],
                String::from("usr_1"),
                String::from("usr_2")
            ))
        );
        assert_eq!(
            meta_target("completeOwnershipHandover", &format!("{org}:{h}")),
            Some(MetaTarget::CompleteHandover([0x0a; 16], [0x0b; 16]))
        );
        // OP-153 m.25 (i) (3)
        assert_eq!(
            meta_target("issueAutojoinGrant", &org),
            Some(MetaTarget::Autojoin([0x0a; 16]))
        );
        assert_eq!(
            meta_target("issueAutojoinGrant", &format!("{org}:usr_1")),
            None
        );
        assert_eq!(
            meta_target("proposeOwnershipHandover", &format!("{org}:usr_1")),
            None
        );
        assert_eq!(
            meta_target("proposeOwnershipHandover", &format!("{org}:a:b:c")),
            None
        );
        assert_eq!(
            meta_target("completeOwnershipHandover", &format!("{org}:x")),
            None
        );
        assert_eq!(meta_target("revokeGrant", &org), None);
    }
}
