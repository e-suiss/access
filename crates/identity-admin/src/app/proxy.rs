//! `idp.proxy.*` changes written under their committed ALLOW (OP-156 m.3 (a), (l)), and the
//! proxies as administrators read them. A proxy's client must be live with the application
//! host's callback as a redirect URI; a retired proxy keeps its name forever and its browser
//! sessions end with it (OP-73). The plain header setup check runs before the change is
//! proposed (access-server).

use access_identity_proxy::domain::registration::{ProxyChange, Registration, from_json, to_json};
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use access_store::proxy::{NewProxy, ProxyRow};
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::Invalid;

fn registration(row: &ProxyRow) -> Result<Registration, AdminError> {
    let v: Json = serde_json::from_str(&row.body)
        .map_err(|_| AdminError::Unavailable(String::from("proxy registration")))?;
    from_json(&v).map_err(|_| AdminError::Unavailable(String::from("proxy registration")))
}

async fn live(t: &mut TenantTx, name: &str) -> Result<(ProxyRow, Registration), AdminError> {
    match access_store::proxy::proxy(t, name).await? {
        Some(row) if row.live => {
            let r = registration(&row)?;
            Ok((row, r))
        }
        _ => Err(Invalid::NoProxy.into()),
    }
}

async fn client_ok(t: &mut TenantTx, r: &Registration) -> Result<(), AdminError> {
    let ok = access_store::idp::client(t, &r.client_id)
        .await?
        .is_some_and(|c| c.active && c.redirect_uris.contains(&r.redirect_uri()));
    ok.then_some(()).ok_or_else(|| Invalid::ProxyClient.into())
}

/// What must hold now for `change`: a new name was never used, any other names a live proxy;
/// a registration's client is live with the callback as a redirect URI; plain headers change
/// state.
///
/// # Errors
/// [`Invalid`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &ProxyChange) -> Result<(), AdminError> {
    match change {
        ProxyChange::Register(r) => {
            if access_store::proxy::proxy(t, &r.name).await?.is_some() {
                return Err(Invalid::ProxyExists.into());
            }
            client_ok(t, r).await
        }
        ProxyChange::Update(r) => {
            live(t, &r.name).await?;
            client_ok(t, r).await
        }
        ProxyChange::Retire(n) => live(t, n).await.map(drop),
        ProxyChange::PlainHeaders(n) => match live(t, n).await? {
            (row, _) if row.plain_headers => Err(AdminError::Conflict),
            _ => Ok(()),
        },
        ProxyChange::PlainHeadersClose(n) => match live(t, n).await? {
            (row, _) if !row.plain_headers => Err(AdminError::Conflict),
            _ => Ok(()),
        },
    }
}

/// The live registration of `name`, for the setup check.
///
/// # Errors
/// [`Invalid::NoProxy`]; [`AdminError`].
pub async fn registered(t: &mut TenantTx, name: &str) -> Result<Registration, AdminError> {
    live(t, name).await.map(|(_, r)| r)
}

/// Writes `change` under `bound`; a retirement ends the proxy's browser sessions.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &ProxyChange,
) -> Result<bool, AdminError> {
    let (r, live, plain) = match change {
        ProxyChange::Register(r) => (r.clone(), true, false),
        ProxyChange::Update(r) => {
            let (row, _) = self::live(t, &r.name).await?;
            (r.clone(), true, row.plain_headers)
        }
        ProxyChange::Retire(n) => {
            let (_, r) = self::live(t, n).await?;
            let now = t.server_time().await?;
            access_store::proxy::end_sessions(t, n, now).await?;
            (r, false, false)
        }
        ProxyChange::PlainHeaders(n) => (self::live(t, n).await?.1, true, true),
        ProxyChange::PlainHeadersClose(n) => (self::live(t, n).await?.1, true, false),
    };
    let body = to_json(&r).to_string();
    access_store::proxy::put_proxy(
        t,
        bound,
        &NewProxy {
            name: &r.name,
            live,
            engine: r.engine.word(),
            host: &r.host,
            pep: &r.pep,
            body: &body,
            plain_headers: plain,
        },
    )
    .await?;
    Ok(true)
}

/// The proxies as administrators read them, each with its decision position.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    let rows = access_store::proxy::proxies(t).await?;
    let mut out = Vec::new();
    for row in rows.iter().filter(|p| key.is_none_or(|k| k == p.name)) {
        let mut v = to_json(&registration(row)?);
        if let Json::Object(m) = &mut v {
            m.insert(
                String::from("status"),
                json!(if row.live { "live" } else { "retired" }),
            );
            m.insert(String::from("plain_headers"), json!(row.plain_headers));
            m.insert(
                String::from("decision_cache_s"),
                json!(access_identity_proxy::domain::cache::MAX_TTL_MS / 1000),
            );
            m.insert(String::from("version"), json!(row.version));
        }
        out.push((v, row.position));
    }
    Ok(out)
}
