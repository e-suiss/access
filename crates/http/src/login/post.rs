//! The page that carries a SAML or WS-Federation message on through the browser (§10.6.1,
//! TN-175): in the person's language and the environment's colours, like the front-channel
//! sign-out page (TN-150). It posts itself at once; its button is always there for a browser that
//! blocks the script. It names no app.

use access_identity_oauth::domain::fapi::html_attr;
use access_identity_ui::domain::branding::Theme;
use access_identity_ui::domain::locale::{DEFAULT_LANGUAGE, overrides_of, tag};
use axum::http::HeaderMap;
use axum::http::header::ACCEPT_LANGUAGE;

use crate::oauth::sign_out::{RTL, STYLE, locale, text};

const BUTTON: &str = "form{margin:0}button{width:100%;height:48px;border:0;border-radius:999px;background:var(--accent);color:var(--on-accent);font:inherit;font-weight:600;cursor:pointer}button:focus-visible{outline:3px solid var(--accent);outline-offset:3px}";

/// The environment's look and the person's language for the page.
#[derive(Debug, Default)]
pub(crate) struct Look {
    /// `idp.environment.branding`.
    pub(crate) branding: Option<Vec<u8>>,
    /// `idp.environment.locale_overrides`.
    pub(crate) overrides: Option<Vec<u8>>,
    /// The first well-formed `Accept-Language` tag, else English.
    pub(crate) locale: String,
}

impl Look {
    /// The person's language from `headers` with the environment's stored look.
    pub(crate) fn of(
        headers: &HeaderMap,
        (branding, overrides): (Option<Vec<u8>>, Option<Vec<u8>>),
    ) -> Self {
        Self {
            branding,
            overrides,
            locale: locale(
                None,
                headers.get(ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()),
            ),
        }
    }
}

/// The page that posts `fields` to `action` at once; its style and script run only under `nonce`.
pub(crate) fn post_page(action: &str, fields: &[(&str, &str)], nonce: &str, look: &Look) -> String {
    let overrides = overrides_of(look.overrides.as_deref());
    let theme = Theme::decode(look.branding.as_deref());
    let language = tag(&look.locale).map_or_else(|_| String::from(DEFAULT_LANGUAGE), |(_, l)| l);
    let dir = if RTL.contains(&language.as_str()) {
        "rtl"
    } else {
        "ltr"
    };
    let title = html_attr(&text("redirect-title", &look.locale, &overrides));
    let body = html_attr(&text("redirect-body", &look.locale, &overrides));
    let go_on = html_attr(&text("action-continue", &look.locale, &overrides));
    let mut inputs = String::new();
    for (name, value) in fields {
        inputs.push_str("<input type=\"hidden\" name=\"");
        inputs.push_str(&html_attr(name));
        inputs.push_str("\" value=\"");
        inputs.push_str(&html_attr(value));
        inputs.push_str("\">");
    }
    format!(
        "<!doctype html><html lang=\"{lang}\" dir=\"{dir}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\"><title>{title}</title>\
         <style nonce=\"{nonce}\">{theme}{STYLE}{BUTTON}</style></head><body><main>\
         <div role=\"status\"><h1>{title}</h1><p>{body}</p></div>\
         <form method=\"post\" action=\"{action}\">{inputs}<button type=\"submit\">{go_on}</button></form>\
         </main><script nonce=\"{nonce}\">document.forms[0].submit()</script></body></html>",
        lang = html_attr(&language),
        theme = theme.css(),
        action = html_attr(action),
        nonce = html_attr(nonce),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // §10.6.1, TN-175
    #[test]
    fn the_post_page_speaks_the_persons_language_escapes_and_carries_the_nonce() {
        let nonce: String = (0..5_u8).map(|i| char::from(b'a' + i)).collect();
        let look = Look {
            locale: String::from("tr"),
            ..Look::default()
        };
        let p = post_page(
            "https://sp.test/acs?a=1&b=\"",
            &[("SAMLResponse", "PD94<>"), ("RelayState", "r\"")],
            &nonce,
            &look,
        );
        assert!(p.contains("<html lang=\"tr\" dir=\"ltr\">"), "{p}");
        assert!(p.contains("<h1>Yönlendiriliyorsunuz</h1>"), "{p}");
        assert!(p.contains("<div role=\"status\">"));
        assert!(p.contains("<button type=\"submit\">Devam</button>"), "{p}");
        assert!(!p.contains("<noscript>"));
        assert!(p.contains("action=\"https://sp.test/acs?a=1&amp;b=&quot;\""));
        assert!(p.contains("value=\"PD94&lt;&gt;\""));
        assert!(p.contains("value=\"r&quot;\""));
        assert!(p.contains(&format!("<script nonce=\"{nonce}\">")));
        assert!(p.contains(&format!("<style nonce=\"{nonce}\">")));
        let english = post_page("https://sp.test/acs", &[], &nonce, &Look::default());
        assert!(
            english.contains("<h1>You&#39;re being redirected</h1>"),
            "{english}"
        );
    }
}
