//! The front-channel sign-out page (IDP-24, TN-150): in the person's language and the
//! environment's colours, it goes on once every frame has loaded or after five seconds, and
//! always offers the link on. It names no app.

use std::sync::LazyLock;

use access_identity_oauth::app::oauth::SignOut;
use access_identity_oauth::domain::fapi::html_attr;
use access_identity_ui::domain::branding::Theme;
use access_identity_ui::domain::locale::{
    Catalogs, DEFAULT_LANGUAGE, Overrides, overrides_of, tag,
};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::Problem;

/// Seconds before the page goes on by itself when a frame never loads.
pub(super) const WAIT_S: u8 = 5;

static CATALOGS: LazyLock<Option<Catalogs>> = LazyLock::new(|| Catalogs::embedded().ok());

pub(crate) const RTL: [&str; 4] = ["ar", "fa", "he", "ur"];

const SCRIPT: &str = "(()=>{const go=()=>{const a=document.getElementById(\"continue\");if(a)location.replace(a.href);};let n=0;setTimeout(go,5000);document.addEventListener(\"load\",e=>{const m=document.querySelector(\"main\");if(!(e.target instanceof HTMLIFrameElement)||!m)return;n+=1;if(n>=Number(m.dataset.frames))go();},true);})();";

pub(crate) const STYLE: &str = ":root{color-scheme:light dark;--bg:var(--brand-background,#ffffff);--fg:#111111;--muted:#555555;--accent:var(--brand-primary,#111111);--on-accent:#ffffff}@media (prefers-color-scheme:dark){:root{--bg:#111111;--fg:#f5f5f5;--muted:#a3a3a3;--accent:var(--brand-primary,#f5f5f5);--on-accent:#111111}}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif}main{width:100%;max-width:400px;display:flex;flex-direction:column;gap:24px}h1{margin:0 0 8px;font-size:28px;line-height:1.15;font-weight:600}p{margin:0;color:var(--muted)}a{display:flex;align-items:center;justify-content:center;height:48px;border-radius:999px;background:var(--accent);color:var(--on-accent);font-weight:600;text-decoration:none}a:focus-visible{outline:3px solid var(--accent);outline-offset:3px}";

/// The person's language: the first well-formed `ui_locales` tag, else the first
/// `Accept-Language` tag, else English.
#[must_use]
pub(crate) fn locale(ui_locales: Option<&str>, accept_language: Option<&str>) -> String {
    let asked = ui_locales.into_iter().flat_map(str::split_whitespace);
    let accepted = accept_language
        .into_iter()
        .flat_map(|a| a.split(','))
        .filter_map(|t| t.split(';').next())
        .map(str::trim);
    asked
        .chain(accepted)
        .find(|t| *t != "*" && tag(t).is_ok())
        .map_or_else(|| String::from(DEFAULT_LANGUAGE), str::to_ascii_lowercase)
}

pub(crate) fn text(key: &str, locale: &str, overrides: &Overrides) -> String {
    CATALOGS
        .as_ref()
        .and_then(|c| c.format(key, locale, Some(overrides), &[]))
        .unwrap_or_default()
}

/// The page's HTML with `nonce` on its style and script.
#[must_use]
pub(super) fn html(page: &SignOut, locale: &str, nonce: &str) -> String {
    let overrides = overrides_of(page.overrides.as_deref());
    let theme = Theme::decode(page.branding.as_deref());
    let language = tag(locale).map_or_else(|_| String::from(DEFAULT_LANGUAGE), |(_, l)| l);
    let dir = if RTL.contains(&language.as_str()) {
        "rtl"
    } else {
        "ltr"
    };
    let title = html_attr(&text("signout-title", locale, &overrides));
    let body = html_attr(&text("signout-body", locale, &overrides));
    let go_on = html_attr(&text("action-continue", locale, &overrides));
    let then = html_attr(&page.then);
    let mut out = format!(
        "<!doctype html><html lang=\"{lang}\" dir=\"{dir}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <meta http-equiv=\"refresh\" content=\"{WAIT_S};url={then}\"><title>{title}</title>\
         <style nonce=\"{nonce}\">{theme}{STYLE}</style><script nonce=\"{nonce}\">{SCRIPT}</script>\
         </head><body><main data-frames=\"{frames}\"><div role=\"status\"><h1>{title}</h1>\
         <p>{body}</p></div><a id=\"continue\" href=\"{then}\">{go_on}</a></main>",
        lang = html_attr(&language),
        theme = theme.css(),
        frames = page.frames.len(),
    );
    for f in &page.frames {
        out.push_str("<iframe hidden title=\"\" src=\"");
        out.push_str(&html_attr(f));
        out.push_str("\"></iframe>");
    }
    out.push_str("</body></html>");
    out
}

/// The page, which may frame only the clients' origins and run only its own style and script.
#[must_use]
pub(super) fn response(page: &SignOut, locale: &str) -> Response {
    let nonce = access_identity_saml::binding::csp_nonce();
    let csp = format!(
        "default-src 'none'; frame-src {}; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; \
         frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        page.origins.join(" ")
    );
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        return Problem::new(StatusCode::BAD_REQUEST, "invalid-frame", "Bad Request")
            .into_response();
    };
    let mut r = (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        html(page, locale, &nonce),
    )
        .into_response();
    r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, csp);
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

#[cfg(test)]
mod tests;
