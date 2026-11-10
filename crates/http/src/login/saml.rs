//! The SAML identity provider and WS-Federation on axum (OP-155 m.3 (c), (e), (f); §10.6.1;
//! IDI-7): `/saml/metadata`, `/saml/sso` (HTTP-Redirect and HTTP-POST), `/saml/sso/{sp}`
//! (IdP-initiated), `/saml/slo`, `/saml/ecp`, `/wsfed` and `/wsfed/metadata`, at the realm's host
//! and under `/realms/{slug}`. access-server keeps the cookies: each request opens a flow, which
//! the [`SamlFront`] forwards to the SAML gateway with the attested session and decides itself.
//! A posted message is first moved to a top-level navigation so the `SameSite=Lax` session cookie
//! comes with it. Only outcomes access-server wrote are rendered; an ACS that does not match is an
//! error page, never a message to the service provider.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use access_identity_oauth::app::Discovery;
use access_identity_oauth::ports::{Directory, Keys, RealmEntry};
use access_identity_saml::binding;
use access_identity_saml::wire::Binding;
use access_identity_session::app::sessions::SessionView;
use access_identity_ui::app::Hosted;
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};

use super::web::{Jar, realm};
use super::{Peer, Shared};

/// Largest form or SOAP body.
const MAX_BODY: usize = 128 * 1024;

/// The raw values of one browser request, as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// How it arrived.
    pub binding: Binding,
    /// A logout (`/saml/slo`, `wsignout1.0`) rather than a sign-in.
    pub slo: bool,
    /// The known parameters: still URL-encoded for HTTP-Redirect, decoded for a form; the SOAP
    /// body as `body`; the IdP-initiated registration as `sp`.
    pub values: Vec<(String, String)>,
}

/// What access-server decided for a flow; the only thing a browser is shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// An auto-submitting form to the validated endpoint.
    Post {
        /// The endpoint.
        action: String,
        /// The fields (`SAMLResponse`, `RelayState`; `wa`, `wresult`, `wctx`).
        fields: Vec<(String, String)>,
    },
    /// A redirect to a validated endpoint.
    Redirect(String),
    /// An ECP SOAP envelope.
    Soap(String),
    /// The user must authenticate first, then the flow continues.
    Login,
    /// Shown to the user, never sent to a service provider; a stable code.
    Error(String),
    /// Signed out, with nowhere registered to return to.
    SignedOut,
}

/// The SAML identity provider behind these routes (access-server).
pub trait SamlFront: Send + Sync + 'static {
    /// The realm's signed metadata.
    fn metadata(&self, entry: &RealmEntry) -> impl Future<Output = Option<String>> + Send;

    /// The realm's WS-Federation metadata.
    fn wsfed_metadata(&self, entry: &RealmEntry) -> impl Future<Output = Option<String>> + Send;

    /// Opens a flow; returns its key, or a refusal code.
    fn open(
        &self,
        entry: &RealmEntry,
        opening: Opening,
    ) -> impl Future<Output = Result<String, String>> + Send;

    /// Runs flow `key` with the browser's live session, if any.
    fn run(
        &self,
        entry: &RealmEntry,
        key: &str,
        session: Option<SessionView>,
        correlation: &str,
    ) -> impl Future<Output = Outcome> + Send;
}

struct Svc<D, K, KI, C, M, S> {
    login: Shared<D, K, KI, C, M>,
    front: Arc<S>,
}

type St<D, K, KI, C, M, S> = State<Arc<Svc<D, K, KI, C, M, S>>>;
type Params0 = Path<HashMap<String, String>>;

/// The SAML and WS-Federation routes, at the realm's host and under `/realms/{slug}`.
pub fn router<D, K, KI, C, M, S>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    front: impl Into<Arc<S>>,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
    S: SamlFront,
{
    let svc = Arc::new(Svc {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        front: front.into(),
    });
    let mut r = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        r = r
            .route(
                &format!("{prefix}/saml/metadata"),
                get(metadata::<D, K, KI, C, M, S>),
            )
            .route(
                &format!("{prefix}/saml/sso"),
                get(sso_get::<D, K, KI, C, M, S>).post(sso_post::<D, K, KI, C, M, S>),
            )
            .route(
                &format!("{prefix}/saml/sso/{{sp}}"),
                get(unsolicited::<D, K, KI, C, M, S>),
            )
            .route(
                &format!("{prefix}/saml/slo"),
                get(slo_get::<D, K, KI, C, M, S>).post(slo_post::<D, K, KI, C, M, S>),
            )
            .route(
                &format!("{prefix}/saml/ecp"),
                axum::routing::post(ecp::<D, K, KI, C, M, S>),
            )
            .route(
                &format!("{prefix}/wsfed"),
                get(wsfed_get::<D, K, KI, C, M, S>).post(wsfed_post::<D, K, KI, C, M, S>),
            )
            .route(
                &format!("{prefix}/wsfed/metadata"),
                get(wsfed_metadata::<D, K, KI, C, M, S>),
            );
    }
    r.with_state(svc)
}

const KNOWN: [&str; 9] = [
    "SAMLRequest",
    "RelayState",
    "SigAlg",
    "Signature",
    "rs_mac",
    "wa",
    "wtrealm",
    "wreply",
    "wctx",
];

/// The known parameters of a query, raw; a repeated parameter refuses the request.
fn raw_pairs(query: &str) -> Result<Vec<(String, String)>, Response> {
    let mut out: Vec<(String, String)> = Vec::new();
    for part in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        if !KNOWN.contains(&k) {
            continue;
        }
        if out.iter().any(|(n, _)| n == k) || v.len() > access_identity_saml::wire::MAX_VALUE {
            return Err(error_page("saml-request-malformed"));
        }
        out.push((String::from(k), String::from(v)));
    }
    Ok(out)
}

/// The known parameters of a query or form, decoded.
fn decoded(raw: &[(String, String)]) -> Result<Vec<(String, String)>, Response> {
    raw.iter()
        .map(|(k, v)| {
            binding::form_decode(v)
                .map(|d| (k.clone(), d))
                .ok_or_else(|| error_page("saml-request-malformed"))
        })
        .collect()
}

fn hardened(mut r: Response, csp: &str) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    r
}

fn html(status: StatusCode, page: String, csp: &str) -> Response {
    hardened(
        (
            status,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            page,
        )
            .into_response(),
        csp,
    )
}

/// An error page with a stable code; nothing is sent to a service provider (IDP-15).
fn error_page(code: &str) -> Response {
    let page = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in problem</title></head><body><h1>We could not sign you in to this application</h1><p>The application sent a request this sign-in service cannot accept. Contact the application's administrator and mention this code: <code>{}</code></p></body></html>",
        access_identity_saml::xml::html(code)
    );
    html(
        StatusCode::BAD_REQUEST,
        page,
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    )
}

fn nonce() -> String {
    binding::csp_nonce()
}

fn redirect(to: &str, status: StatusCode) -> Response {
    let mut r = status.into_response();
    if let Ok(v) = HeaderValue::from_str(to) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    hardened(r, "default-src 'none'; frame-ancestors 'none'")
}

fn flow_path(entry: &RealmEntry, endpoint: &str, key: &str) -> String {
    format!("{}{endpoint}?flow={key}", entry.issuer.path())
}

fn render(entry: &RealmEntry, endpoint: &str, key: &str, outcome: Outcome) -> Response {
    match outcome {
        Outcome::Post { action, fields } => {
            let n = nonce();
            let refs: Vec<(&str, &str)> = fields
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let page = binding::post_page(&action, &refs, &n);
            let csp = format!(
                "default-src 'none'; script-src 'nonce-{n}'; form-action {}; frame-ancestors 'none'; base-uri 'none'",
                origin(&action)
            );
            html(StatusCode::OK, page, &csp)
        }
        Outcome::Redirect(to) => redirect(&to, StatusCode::SEE_OTHER),
        Outcome::Soap(envelope) => hardened(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/vnd.paos+xml")],
                envelope,
            )
                .into_response(),
            "default-src 'none'",
        ),
        Outcome::Login => {
            let back = flow_path(entry, endpoint, key);
            let to = format!(
                "{}/login?return_to={}",
                entry.issuer.path(),
                binding::encode(&back)
            );
            redirect(&to, StatusCode::SEE_OTHER)
        }
        Outcome::Error(code) => error_page(&code),
        Outcome::SignedOut => html(
            StatusCode::OK,
            String::from(
                "<!doctype html><html><head><meta charset=\"utf-8\"><title>Signed out</title></head><body><h1>You are signed out</h1></body></html>",
            ),
            "default-src 'none'; frame-ancestors 'none'",
        ),
    }
}

/// The origin of an absolute `https` URL, for `form-action`.
fn origin(url: &str) -> String {
    let rest = url.strip_prefix("https://").unwrap_or_default();
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains(['\'', ';', ' ']) {
        String::from("'none'")
    } else {
        format!("https://{host}")
    }
}

macro_rules! handler {
    ($(#[$doc:meta])* $name:ident($s:ident, $entry:ident, $jar:ident, $p:ident, $uri:ident, $headers:ident, $body:ident) $block:block) => {
        $(#[$doc])*
        async fn $name<D, K, KI, C, M, S>(
            State($s): St<D, K, KI, C, M, S>,
            Path($p): Params0,
            peer: Option<Extension<Peer>>,
            $uri: Uri,
            $headers: HeaderMap,
            $body: Bytes,
        ) -> Response
        where
            D: Directory,
            K: Keys,
            KI: Kits,
            C: Clock + Sync,
            M: Messages,
            S: SamlFront,
        {
            let $entry = match realm(&$s.login, &$p, &$uri, &$headers).await {
                Ok(e) => e,
                Err(r) => return r,
            };
            if $body.len() > MAX_BODY {
                return error_page("saml-request-too-large");
            }
            let $jar = Jar::of(&$headers, peer);
            $block
        }
    };
}

async fn run_flow<D, K, KI, C, M, S>(
    s: &Svc<D, K, KI, C, M, S>,
    entry: &RealmEntry,
    jar: &Jar,
    endpoint: &str,
    key: &str,
) -> Response
where
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    S: SamlFront,
{
    let browser = jar.browser();
    let Ok(session) = s.login.hosted.saml_session(entry, &browser).await else {
        return error_page("saml-unavailable");
    };
    let outcome = s.front.run(entry, key, session, browser.correlation).await;
    render(entry, endpoint, key, outcome)
}

async fn open_and_run<D, K, KI, C, M, S>(
    s: &Svc<D, K, KI, C, M, S>,
    entry: &RealmEntry,
    jar: &Jar,
    endpoint: &str,
    opening: Opening,
) -> Response
where
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    S: SamlFront,
{
    match s.front.open(entry, opening).await {
        Ok(key) => run_flow(s, entry, jar, endpoint, &key).await,
        Err(code) => error_page(&code),
    }
}

fn flow_of(uri: &Uri) -> Option<String> {
    uri.query()?.split('&').find_map(|p| {
        p.strip_prefix("flow=")
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= 64
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .map(String::from)
    })
}

handler! {
    /// `GET /saml/metadata` (Ek B 4763, 4994): signed each time it is served.
    metadata(s, entry, jar, p, uri, headers, body) {
        let _ = (&jar, &body);
        match s.front.metadata(&entry).await {
            Some(doc) => hardened(
                (StatusCode::OK, [(header::CONTENT_TYPE, "application/samlmetadata+xml")], doc)
                    .into_response(),
                "default-src 'none'",
            ),
            None => error_page("saml-not-enabled"),
        }
    }
}

handler! {
    /// `GET /wsfed/metadata`.
    wsfed_metadata(s, entry, jar, p, uri, headers, body) {
        let _ = (&jar, &body);
        match s.front.wsfed_metadata(&entry).await {
            Some(doc) => hardened(
                (StatusCode::OK, [(header::CONTENT_TYPE, "application/xml")], doc).into_response(),
                "default-src 'none'",
            ),
            None => error_page("saml-not-enabled"),
        }
    }
}

handler! {
    /// `GET /saml/sso`: HTTP-Redirect binding, or the continuation of a flow.
    sso_get(s, entry, jar, p, uri, headers, body) {
        let _ = &body;
        if let Some(key) = flow_of(&uri) {
            return run_flow(&s, &entry, &jar, "/saml/sso", &key).await;
        }
        let values = match raw_pairs(uri.query().unwrap_or_default()) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let opening = Opening { binding: Binding::Redirect, slo: false, values };
        open_and_run(&s, &entry, &jar, "/saml/sso", opening).await
    }
}

handler! {
    /// `POST /saml/sso`: HTTP-POST binding; the flow continues as a top-level navigation so the
    /// session cookie comes with it.
    sso_post(s, entry, jar, p, uri, headers, body) {
        let _ = &jar;
        let raw = match raw_pairs(core::str::from_utf8(&body).unwrap_or_default()) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let values = match decoded(&raw) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let opening = Opening { binding: Binding::Post, slo: false, values };
        match s.front.open(&entry, opening).await {
            Ok(key) => redirect(&flow_path(&entry, "/saml/sso", &key), StatusCode::SEE_OTHER),
            Err(code) => error_page(&code),
        }
    }
}

handler! {
    /// `GET /saml/sso/{sp}`: IdP-initiated SSO, only for a registration that opted in (IDP-15).
    unsolicited(s, entry, jar, p, uri, headers, body) {
        let _ = &body;
        let Some(sp) = p.get("sp").filter(|n| access_internal_api::edge::valid_name(n)) else {
            return error_page("saml-unknown-sp");
        };
        let mut values = match raw_pairs(uri.query().unwrap_or_default()).and_then(|r| decoded(&r)) {
            Ok(v) => v,
            Err(r) => return r,
        };
        values.retain(|(k, _)| k == "RelayState" || k == "rs_mac");
        values.push((String::from("sp"), sp.clone()));
        let opening = Opening { binding: Binding::Unsolicited, slo: false, values };
        open_and_run(&s, &entry, &jar, "/saml/sso", opening).await
    }
}

async fn slo<D, K, KI, C, M, S>(
    s: &Svc<D, K, KI, C, M, S>,
    entry: &RealmEntry,
    jar: &Jar,
    opening: Opening,
) -> Response
where
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    S: SamlFront,
{
    let browser = jar.browser();
    let clear = s.login.hosted.saml_sign_out(entry, &browser).await;
    let outcome = match s.front.open(entry, opening).await {
        Ok(key) => s.front.run(entry, &key, None, browser.correlation).await,
        Err(code) => Outcome::Error(code),
    };
    let outcome = match outcome {
        Outcome::Error(_) | Outcome::Login => Outcome::SignedOut,
        other => other,
    };
    let mut r = render(entry, "/saml/slo", "", outcome);
    if let Ok(v) = HeaderValue::from_str(&clear) {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    r
}

handler! {
    /// `GET /saml/slo`: single logout, HTTP-Redirect; local sign-out always succeeds.
    slo_get(s, entry, jar, p, uri, headers, body) {
        let _ = &body;
        let values = match raw_pairs(uri.query().unwrap_or_default()) {
            Ok(v) => v,
            Err(r) => return r,
        };
        slo(&s, &entry, &jar, Opening { binding: Binding::Redirect, slo: true, values }).await
    }
}

handler! {
    /// `POST /saml/slo`: single logout, HTTP-POST.
    slo_post(s, entry, jar, p, uri, headers, body) {
        let values = match raw_pairs(core::str::from_utf8(&body).unwrap_or_default()).and_then(|r| decoded(&r)) {
            Ok(v) => v,
            Err(r) => return r,
        };
        slo(&s, &entry, &jar, Opening { binding: Binding::Post, slo: true, values }).await
    }
}

handler! {
    /// `POST /saml/ecp`: ECP for rich clients (PAOS). Basic authentication with the account's
    /// password is refused (OP-155 m.3 (e)).
    ecp(s, entry, jar, p, uri, headers, body) {
        let basic = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.len() >= 6 && v[..6].eq_ignore_ascii_case("basic "));
        if basic {
            return hardened(
                (StatusCode::UNAUTHORIZED, [(header::CONTENT_TYPE, "text/plain")], "ecp-basic-refused")
                    .into_response(),
                "default-src 'none'",
            );
        }
        let Ok(envelope) = core::str::from_utf8(&body) else {
            return error_page("saml-request-malformed");
        };
        let opening = Opening {
            binding: Binding::Soap,
            slo: false,
            values: vec![(String::from("body"), String::from(envelope))],
        };
        match s.front.open(&entry, opening).await {
            Ok(key) => {
                let browser = jar.browser();
                let session = s.login.hosted.saml_session(&entry, &browser).await.ok().flatten();
                match s.front.run(&entry, &key, session, browser.correlation).await {
                    Outcome::Login => hardened(StatusCode::UNAUTHORIZED.into_response(), "default-src 'none'"),
                    other => render(&entry, "/saml/ecp", &key, other),
                }
            }
            Err(code) => error_page(&code),
        }
    }
}

async fn wsfed<D, K, KI, C, M, S>(
    s: &Svc<D, K, KI, C, M, S>,
    entry: &RealmEntry,
    jar: &Jar,
    values: Vec<(String, String)>,
) -> Response
where
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    S: SamlFront,
{
    let signout = values
        .iter()
        .any(|(k, v)| k == "wa" && (v == "wsignout1.0" || v == "wsignoutcleanup1.0"));
    let opening = Opening {
        binding: Binding::Wsfed,
        slo: signout,
        values,
    };
    if signout {
        return slo(s, entry, jar, opening).await;
    }
    open_and_run(s, entry, jar, "/wsfed", opening).await
}

handler! {
    /// `GET /wsfed`: passive requestor (OP-155 m.3 (f)), or the continuation of a flow.
    wsfed_get(s, entry, jar, p, uri, headers, body) {
        let _ = &body;
        if let Some(key) = flow_of(&uri) {
            return run_flow(&s, &entry, &jar, "/wsfed", &key).await;
        }
        let values = match raw_pairs(uri.query().unwrap_or_default()).and_then(|r| decoded(&r)) {
            Ok(v) => v,
            Err(r) => return r,
        };
        wsfed(&s, &entry, &jar, values).await
    }
}

handler! {
    /// `POST /wsfed`: passive requestor, form; moved to a top-level navigation.
    wsfed_post(s, entry, jar, p, uri, headers, body) {
        let values = match raw_pairs(core::str::from_utf8(&body).unwrap_or_default()).and_then(|r| decoded(&r)) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if values.iter().any(|(k, v)| k == "wa" && v.starts_with("wsignout")) {
            return wsfed(&s, &entry, &jar, values).await;
        }
        let opening = Opening { binding: Binding::Wsfed, slo: false, values };
        match s.front.open(&entry, opening).await {
            Ok(key) => redirect(&flow_path(&entry, "/wsfed", &key), StatusCode::SEE_OTHER),
            Err(code) => error_page(&code),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // §3.4.4.1
    #[test]
    fn query_values_stay_raw_and_unknown_ones_are_dropped() {
        let v = raw_pairs("SAMLRequest=fZ%2B&x=1&RelayState=a%20b").unwrap();
        assert_eq!(
            v,
            [
                (String::from("SAMLRequest"), String::from("fZ%2B")),
                (String::from("RelayState"), String::from("a%20b"))
            ]
        );
        assert!(raw_pairs("SAMLRequest=a&SAMLRequest=b").is_err());
        assert_eq!(
            decoded(&v).unwrap()[1],
            (String::from("RelayState"), String::from("a b"))
        );
        assert_eq!(origin("https://sp.test:8443/acs?x"), "https://sp.test:8443");
        assert_eq!(origin("javascript:x"), "'none'");
    }
}
