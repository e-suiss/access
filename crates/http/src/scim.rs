//! The SCIM 2.0 server on axum (RFC 7644; OP-155 m.3 (g), IDP-23): `/scim/v2/` at the realm's
//! host and under `/realms/{slug}`. Every endpoint, discovery included, needs the bearer secret
//! of a live client of that realm; anything else is `401`. Bodies are `application/scim+json`
//! (plain JSON only for a client whose tolerance profile allows it), at most [`MAX_BODY`] bytes.
//! `/Bulk` answers `501` and `/Me` is not served (Ek B 4928, 5037).

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_oauth::ports::Directory;
use access_identity_scim::app::{Answer, Clock, ListQuery, RealmRef, Scim, Vaults};
use access_identity_scim::domain::schema::Kind;
use access_identity_scim::domain::tolerance::Rule;
use access_identity_scim::domain::{MEDIA_TYPE, ScimError, ScimType, discovery};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::Value;

/// Largest request body.
pub const MAX_BODY: usize = 1024 * 1024;

/// The query parameters a list or read takes.
const PARAMS: [&str; 7] = [
    "filter",
    "startIndex",
    "count",
    "cursor",
    "attributes",
    "excludedAttributes",
    "sortBy",
];

/// Entra's feature flag parameter (OP-155 m.3 (g)).
const AAD_FLAG: &str = "aadOptscim062020";

struct Shared<D, V, C> {
    directory: D,
    scim: Scim<V, C>,
}

type St<D, V, C> = State<Arc<Shared<D, V, C>>>;

fn answer(e: &ScimError) -> Response {
    let mut r = (
        StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        e.body().to_string(),
    )
        .into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    if e.status == 401 {
        r.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    r
}

fn ok(a: Answer, etags: bool) -> Response {
    let status = StatusCode::from_u16(a.status).unwrap_or(StatusCode::OK);
    let mut r = if a.body.is_null() {
        status.into_response()
    } else {
        (status, a.body.to_string()).into_response()
    };
    let h = r.headers_mut();
    if !a.body.is_null() {
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    }
    let mut put = |name: header::HeaderName, v: Option<String>| {
        if let Some(v) = v.and_then(|v| HeaderValue::from_str(&v).ok()) {
            h.insert(name, v);
        }
    };
    if etags {
        put(header::ETAG, a.etag);
    }
    put(header::LOCATION, a.location);
    if let Some(t) = a.txn.and_then(|t| HeaderValue::from_str(&t).ok()) {
        h.insert("set-txn", t);
    }
    r
}

/// The SCIM routes over `directory` and `scim`.
pub fn router<D, V, C>(directory: D, scim: Scim<V, C>) -> Router
where
    D: Directory + 'static,
    V: Vaults + 'static,
    C: Clock + 'static,
{
    let shared = Arc::new(Shared { directory, scim });
    let mut r = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        let base = format!("{prefix}/scim/v2");
        for endpoint in ["Users", "Groups", "Devices"] {
            r = r
                .route(
                    &format!("{base}/{endpoint}"),
                    get(collection::<D, V, C>).post(collection::<D, V, C>),
                )
                .route(
                    &format!("{base}/{endpoint}/{{id}}"),
                    get(one::<D, V, C>)
                        .put(one::<D, V, C>)
                        .patch(one::<D, V, C>)
                        .delete(one::<D, V, C>),
                );
        }
        r = r
            .route(
                &format!("{base}/ServiceProviderConfig"),
                get(discover::<D, V, C>),
            )
            .route(&format!("{base}/ResourceTypes"), get(discover::<D, V, C>))
            .route(
                &format!("{base}/ResourceTypes/{{id}}"),
                get(discover::<D, V, C>),
            )
            .route(&format!("{base}/Schemas"), get(discover::<D, V, C>))
            .route(&format!("{base}/Schemas/{{id}}"), get(discover::<D, V, C>))
            .route(&format!("{base}/Bulk"), post(bulk));
    }
    r.with_state(shared)
}

async fn bulk() -> Response {
    answer(&ScimError::NOT_IMPLEMENTED)
}

fn host(uri: &Uri, headers: &HeaderMap) -> String {
    let raw = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
        .unwrap_or_default();
    let h = raw.rsplit_once(':').map_or(raw, |(h, port)| {
        if port.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            raw
        }
    });
    h.to_ascii_lowercase()
}

struct Request {
    client: access_identity_scim::app::Client,
    query: HashMap<String, String>,
}

async fn admit<D: Directory, V: Vaults, C: Clock>(
    s: &Shared<D, V, C>,
    p: &HashMap<String, String>,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Request, ScimError> {
    let entry = match p.get("slug") {
        Some(slug) => s.directory.by_slug(slug).await,
        None => s.directory.by_host(&host(uri, headers)).await,
    }
    .map_err(|_| ScimError::UNAVAILABLE)?
    .ok_or(ScimError::NOT_FOUND)?;
    let realm = RealmRef {
        tenant: entry.tenant,
        realm: entry.realm,
        base: format!("{}/scim/v2", entry.issuer.as_str().trim_end_matches('/')),
    };
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split_once(' ')
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                .map(|(_, t)| t.trim())
        })
        .ok_or(ScimError::UNAUTHORIZED)?;
    let client = s.scim.authenticate(&realm, bearer).await?;
    let mut query = HashMap::new();
    if let Some(q) = uri.query() {
        if q.len() > 8192 {
            return Err(ScimError::bad(
                ScimType::InvalidValue,
                "The query is too long",
            ));
        }
        let malformed = || ScimError::bad(ScimType::InvalidSyntax, "The query is malformed");
        for part in q.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            let k = access_identity_oauth::domain::client::form_decode(k).ok_or_else(malformed)?;
            let v = access_identity_oauth::domain::client::form_decode(v).ok_or_else(malformed)?;
            if k == AAD_FLAG && client.profile.has(Rule::AadOptScim062020) {
                continue;
            }
            if !PARAMS.contains(&k.as_str()) {
                return Err(ScimError::bad(
                    ScimType::InvalidSyntax,
                    "The query names a parameter the server does not take",
                ));
            }
            if query.insert(k, v).is_some() {
                return Err(malformed());
            }
        }
    }
    Ok(Request { client, query })
}

fn body(r: &Request, headers: &HeaderMap, bytes: &Bytes) -> Result<Value, ScimError> {
    let media = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let json_ok = media == "application/json" && r.client.profile.has(Rule::ContentTypeJson);
    if media != MEDIA_TYPE && !json_ok {
        return Err(ScimError::MEDIA);
    }
    if bytes.len() > MAX_BODY {
        return Err(ScimError::TOO_LARGE);
    }
    access_parse::json::check(bytes, MAX_BODY, 32)
        .map_err(|_| ScimError::bad(ScimType::InvalidSyntax, "The body is not bounded JSON"))?;
    serde_json::from_slice(bytes)
        .map_err(|_| ScimError::bad(ScimType::InvalidSyntax, "The body is not JSON"))
}

fn kind_of(uri: &Uri) -> Option<Kind> {
    let path = uri.path();
    let after = path.split("/scim/v2/").nth(1)?;
    let endpoint = after.split('/').next()?;
    Kind::ALL.into_iter().find(|k| k.endpoint() == endpoint)
}

fn list_query(q: &HashMap<String, String>) -> ListQuery {
    let g = |k: &str| q.get(k).cloned();
    ListQuery {
        filter: g("filter"),
        start_index: g("startIndex"),
        count: g("count"),
        cursor: g("cursor"),
        attributes: g("attributes"),
        excluded: g("excludedAttributes"),
        sort_by: g("sortBy"),
    }
}

async fn collection<D: Directory, V: Vaults, C: Clock>(
    State(s): St<D, V, C>,
    Path(p): Path<HashMap<String, String>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let run = async {
        let r = admit(&s, &p, &uri, &headers).await?;
        let kind = kind_of(&uri).ok_or(ScimError::NOT_FOUND)?;
        let etags = !r.client.profile.has(Rule::NoEtag);
        let a = if method == Method::POST {
            let v = body(&r, &headers, &bytes)?;
            s.scim.create(&r.client, kind, &v).await?
        } else {
            s.scim.list(&r.client, kind, &list_query(&r.query)).await?
        };
        Ok::<_, ScimError>(ok(a, etags))
    };
    run.await.unwrap_or_else(|e| answer(&e))
}

async fn one<D: Directory, V: Vaults, C: Clock>(
    State(s): St<D, V, C>,
    Path(p): Path<HashMap<String, String>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let run = async {
        let r = admit(&s, &p, &uri, &headers).await?;
        let kind = kind_of(&uri).ok_or(ScimError::NOT_FOUND)?;
        let id = p.get("id").map(String::as_str).unwrap_or_default();
        let etags = !r.client.profile.has(Rule::NoEtag);
        let if_match = headers
            .get(header::IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let client = &r.client;
        let out = match method {
            Method::GET => s.scim.get(client, kind, id, &list_query(&r.query)).await?,
            Method::PUT => {
                let v = body(&r, &headers, &bytes)?;
                s.scim
                    .replace(client, kind, id, &v, if_match.as_deref())
                    .await?
            }
            Method::PATCH => {
                let v = body(&r, &headers, &bytes)?;
                s.scim
                    .patch(client, kind, id, &v, if_match.as_deref())
                    .await?
            }
            Method::DELETE => s.scim.delete(client, kind, id, if_match.as_deref()).await?,
            _ => return Err(ScimError::NOT_IMPLEMENTED),
        };
        Ok::<_, ScimError>(ok(out, etags))
    };
    run.await.unwrap_or_else(|e| answer(&e))
}

async fn discover<D: Directory, V: Vaults, C: Clock>(
    State(s): St<D, V, C>,
    Path(p): Path<HashMap<String, String>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let run = async {
        let r = admit(&s, &p, &uri, &headers).await?;
        let base = &r.client.realm.base;
        let path = uri.path();
        let id = p.get("id").map(String::as_str);
        let body = if path.ends_with("/ServiceProviderConfig") {
            discovery::service_provider_config(base)
        } else if path.contains("/ResourceTypes") {
            match id {
                Some(i) => discovery::resource_type_named(base, i).ok_or(ScimError::NOT_FOUND)?,
                None => discovery::resource_types(base),
            }
        } else {
            match id {
                Some(i) => discovery::schema_named(base, i).ok_or(ScimError::NOT_FOUND)?,
                None => discovery::schemas(base),
            }
        };
        Ok::<_, ScimError>(ok(
            Answer {
                status: 200,
                body,
                etag: None,
                location: None,
                txn: None,
            },
            false,
        ))
    };
    run.await.unwrap_or_else(|e| answer(&e))
}
