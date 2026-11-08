//! Schema publication on the ADP router (L1-ADP-18, §8.17.10.2, E10–E12, X21): a publisher,
//! known only by its `check` AIS, publishes a typed Schema Publication Package and offers it to
//! the domains it names, and reads where its own publication stands. Nothing here accepts a
//! package: a domain accepts only with its own reserved `acceptance.amend` naming the exact
//! fingerprint, so there is no accept path even for a publisher who administers a target domain.

use std::collections::{BTreeMap, BTreeSet};

use access_authority_core::app::Incoming;
use access_authority_core::app::publishing::{
    Affects, Compatibility, Draft, PACKAGE_CONTEXT, ParamClass, PublishError, Relation,
};
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::adp::app::{Reply, Service, bad, failed};
use crate::adp::domain::{AdpError, Body, decode_context};
use crate::adp::payload::{action_ref_from_json, action_schema_from_json};
use crate::adp::ports::Pdp;
use crate::problem::Problem;

/// The publish route.
pub const PUBLISH_PATH: &str = "/access/v1/publications";

/// The status route.
pub const STATUS_PATH: &str = "/access/v1/publications:status";

/// Most domains one request names.
pub const MAX_DOMAINS: usize = 16;

/// `SHA-256("access/schema-package/v1" ‖ 0x00 ‖ JSON(package))`, members sorted by name and
/// no insignificant whitespace: what a publish intent's `opaque.package` names.
#[must_use]
pub fn package_digest(package: &Value) -> Digest {
    let bytes = serde_json::to_vec(&sorted(package)).unwrap_or_default();
    Digest(suiss_crypto::digest::context_digest(PACKAGE_CONTEXT, &bytes).0)
}

/// `v` with every object's members in name order, whatever order the map keeps.
fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .filter_map(|k| m.get(k).map(|x| (k.clone(), sorted(x))))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn domains(v: Option<&Value>) -> Result<Vec<Digest>, AdpError> {
    let items = v.and_then(Value::as_array).ok_or(AdpError("domains"))?;
    if items.is_empty() || items.len() > MAX_DOMAINS {
        return Err(AdpError("domains"));
    }
    let out: Vec<Digest> = items
        .iter()
        .map(|d| {
            d.as_str()
                .and_then(|s| b64url_decode(s).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .map(Digest)
                .ok_or(AdpError("domains"))
        })
        .collect::<Result<_, _>>()?;
    let unique: BTreeSet<_> = out.iter().collect();
    if unique.len() != out.len() {
        return Err(AdpError("domains"));
    }
    Ok(out)
}

fn class(word: &str) -> Option<ParamClass> {
    if word == "opaque" {
        return Some(ParamClass::Opaque);
    }
    Affects::parse(word).map(ParamClass::Relevant)
}

/// The draft a `package` member names (L1-ADP-18).
///
/// # Errors
/// [`AdpError`] `package` for anything outside its form.
pub fn draft_of(package: &Value) -> Result<Draft, AdpError> {
    let bad = || AdpError("package");
    let o = package.as_object().ok_or_else(bad)?;
    if o.keys().any(|k| {
        !matches!(
            k.as_str(),
            "namespace"
                | "catalog_version"
                | "actions"
                | "classes"
                | "retirements"
                | "core_spec_min"
                | "compatibility"
        )
    }) {
        return Err(bad());
    }
    let namespace = o.get("namespace").and_then(Value::as_str).ok_or_else(bad)?;
    let catalog_version = o
        .get("catalog_version")
        .and_then(Value::as_u64)
        .ok_or_else(bad)?;
    let actions = o
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(bad)?
        .iter()
        .map(|a| action_schema_from_json(a).map_err(|_| bad()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut classes = BTreeMap::new();
    for c in o.get("classes").and_then(Value::as_array).ok_or_else(bad)? {
        let m = c.as_object().filter(|m| m.len() == 3).ok_or_else(bad)?;
        let text = |k: &str| m.get(k).and_then(Value::as_str).ok_or_else(bad);
        let key = (text("action")?.to_owned(), text("parameter")?.to_owned());
        let value = class(text("class")?).ok_or_else(bad)?;
        if classes.insert(key, value).is_some() {
            return Err(bad());
        }
    }
    let retirements = match o.get("retirements") {
        None => BTreeSet::new(),
        Some(r) => r
            .as_array()
            .ok_or_else(bad)?
            .iter()
            .map(|a| action_ref_from_json(a).map_err(|_| bad()))
            .collect::<Result<_, _>>()?,
    };
    let core_spec_min = match o.get("core_spec_min") {
        None => None,
        Some(v) => Some(v.as_u64().ok_or_else(bad)?),
    };
    let compatibility = match o.get("compatibility") {
        None => None,
        Some(c) => {
            let m = c.as_object().filter(|m| m.len() == 2).ok_or_else(bad)?;
            Some(Compatibility {
                from: m.get("from").and_then(Value::as_u64).ok_or_else(bad)?,
                relation: m
                    .get("relation")
                    .and_then(Value::as_str)
                    .and_then(Relation::parse)
                    .ok_or_else(bad)?,
            })
        }
    };
    Ok(Draft {
        namespace: namespace.to_owned(),
        catalog_version,
        actions,
        classes,
        retirements,
        core_spec_min,
        compatibility,
    })
}

fn incoming(decoded: crate::adp::domain::Decoded, pep: String) -> Incoming {
    Incoming {
        request: decoded.request,
        ais: decoded.ais,
        pep,
        requester: None,
        explain: false,
        status: None,
        context: None,
    }
}

fn refused(e: &PublishError) -> Response {
    match e {
        PublishError::Unmappable(w) => {
            let warnings: Vec<Value> = w
                .iter()
                .map(|w| {
                    json!({
                        "action": w.action,
                        "parameter": w.parameter,
                        "reason": w.reason,
                        "suggestion": w.suggestion,
                    })
                })
                .collect();
            let mut r = (
                StatusCode::UNPROCESSABLE_ENTITY,
                axum::Json(json!({
                    "type": format!("{}publication-unmappable", crate::problem::TYPE_PREFIX),
                    "title": "Unprocessable Content",
                    "status": 422,
                    "code": "publication-unmappable",
                    "warnings": warnings,
                })),
            )
                .into_response();
            r.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/problem+json"),
            );
            r
        }
        PublishError::Version { .. } => {
            Problem::new(StatusCode::CONFLICT, "publication-version", "Conflict").into_response()
        }
        _ => Problem::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "publication-invalid",
            "Unprocessable Content",
        )
        .into_response(),
    }
}

fn core_refused(e: access_authority_core::CoreError, headers: &HeaderMap) -> Response {
    match &e {
        access_authority_core::CoreError::Protocol("anonymous") => {
            Problem::new(StatusCode::UNAUTHORIZED, "ais-required", "Unauthorized").into_response()
        }
        access_authority_core::CoreError::Protocol("publication-version") => {
            Problem::new(StatusCode::CONFLICT, "publication-version", "Conflict").into_response()
        }
        _ => crate::adp::adapters::respond(failed(e, Body::Context), headers),
    }
}

/// `POST /access/v1/publications`.
pub async fn publish<P: Pdp>(
    service: &Service<P>,
    body: &[u8],
    pep: Option<String>,
    headers: &HeaderMap,
) -> Response {
    let Some(pep) = pep else {
        return crate::adp::adapters::respond(Reply::Unauthenticated, headers);
    };
    let parsed = (|| {
        let root: Value = serde_json::from_slice(body).map_err(|_| AdpError("json"))?;
        let o = root.as_object().ok_or(AdpError("json"))?;
        if o.keys()
            .any(|k| !matches!(k.as_str(), "context" | "package" | "domains"))
        {
            return Err(AdpError("unknown-member"));
        }
        let package = o.get("package").ok_or(AdpError("package"))?;
        let draft = draft_of(package)?;
        let domains = domains(o.get("domains"))?;
        let decoded = decode_context(body, service.max_body())?;
        Ok((draft, package_digest(package), domains, decoded))
    })();
    let (draft, digest, domains, decoded) = match parsed {
        Ok(p) => p,
        Err(e) => return crate::adp::adapters::respond(bad(e, Body::Context), headers),
    };
    match service
        .pdp()
        .publish(incoming(decoded, pep), draft, digest, domains)
        .await
    {
        Ok(Ok((p, new))) => (
            StatusCode::CREATED,
            axum::Json(json!({
                "fingerprint": b64url_encode(&p.fingerprint.0),
                "publisher": b64url_encode(&p.publication.spp.publisher.0),
                "namespace": p.publication.spp.namespace,
                "catalog_version": p.publication.spp.catalog_version,
                "new": new,
                "existing_grants_unchanged": p.notes.existing_grants_unchanged,
                "new_actions": p.notes.new_actions,
                "text": p.notes.text,
            })),
        )
            .into_response(),
        Ok(Err(e)) => refused(&e),
        Err(e) => core_refused(e, headers),
    }
}

/// `POST /access/v1/publications:status`.
pub async fn status<P: Pdp>(
    service: &Service<P>,
    body: &[u8],
    pep: Option<String>,
    headers: &HeaderMap,
) -> Response {
    let Some(pep) = pep else {
        return crate::adp::adapters::respond(Reply::Unauthenticated, headers);
    };
    let parsed = (|| {
        let root: Value = serde_json::from_slice(body).map_err(|_| AdpError("json"))?;
        let o = root.as_object().ok_or(AdpError("json"))?;
        if o.keys()
            .any(|k| !matches!(k.as_str(), "context" | "fingerprint" | "domains"))
        {
            return Err(AdpError("unknown-member"));
        }
        let fingerprint = o
            .get("fingerprint")
            .and_then(Value::as_str)
            .and_then(|s| b64url_decode(s).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .map(Digest)
            .ok_or(AdpError("fingerprint"))?;
        let domains = domains(o.get("domains"))?;
        let decoded = decode_context(body, service.max_body())?;
        let namespace = decoded
            .request
            .intent
            .resources
            .first()
            .and_then(|r| r.path.first())
            .cloned()
            .ok_or(AdpError("intent"))?;
        Ok((fingerprint, domains, namespace, decoded))
    })();
    let (fingerprint, domains, namespace, decoded) = match parsed {
        Ok(p) => p,
        Err(e) => return crate::adp::adapters::respond(bad(e, Body::Context), headers),
    };
    match service
        .pdp()
        .publication_status(incoming(decoded, pep), namespace, fingerprint, domains)
        .await
    {
        Ok(Some(s)) => (
            StatusCode::OK,
            axum::Json(json!({
                "fingerprint": b64url_encode(&s.fingerprint.0),
                "pending_acceptance": s.pending_acceptance.iter().map(|d| b64url_encode(&d.0)).collect::<Vec<_>>(),
                "accepted_in": s.accepted_in.iter().map(|d| b64url_encode(&d.0)).collect::<Vec<_>>(),
                "existing_grants_unchanged": s.notes.existing_grants_unchanged,
                "new_actions": s.notes.new_actions,
                "text": s.notes.text,
            })),
        )
            .into_response(),
        Ok(None) => Problem::new(StatusCode::NOT_FOUND, "not-found", "Not Found").into_response(),
        Err(e) => core_refused(e, headers),
    }
}

#[cfg(test)]
mod tests;
