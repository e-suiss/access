//! JWT Secured Authorization Response Mode (OAuth JARM; §10.4.3, CR-4, OP-155 m.3 (k)): the
//! authorization response as a JWT the realm signs with the client's chosen identity
//! algorithm, optionally encrypted to the client, returned in the query (`jwt`, `query.jwt`)
//! or in a posted form (`form_post.jwt`).

use serde_json::{Map, Value};

use crate::domain::issuer::{Issuer, form_encode};

/// Lifetime of a response JWT (JARM §2.1: short; PD).
pub const JARM_TTL_MS: u64 = 60_000;

/// `typ` of a response JWT.
pub const JARM_TYP: &str = "JWT";

/// The claims of a response JWT: `iss`, `aud` (the client), `exp`, and the response members,
/// `code` and `state`, or `error`, `error_description` and `state` (JARM §2.1, RFC 9207).
#[must_use]
pub fn claims(issuer: &Issuer, client_id: &str, now_ms: u64, members: &[(&str, &str)]) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("iss".into(), issuer.as_str().into());
    m.insert("aud".into(), client_id.into());
    m.insert(
        "exp".into(),
        (now_ms.saturating_add(JARM_TTL_MS) / 1000).into(),
    );
    for (k, v) in members {
        m.insert((*k).into(), (*v).into());
    }
    Value::Object(m).to_string().into_bytes()
}

/// `redirect_uri` with the response JWT as `response` (JARM §2.3.1).
#[must_use]
pub fn query(redirect_uri: &str, response: &str) -> String {
    let mut q = String::from("response=");
    form_encode(response, &mut q);
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{sep}{q}")
}

fn html_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The page that posts the response JWT to `redirect_uri` (JARM §2.3.4, OAuth Form Post
/// Response Mode §2): one hidden field, submitted by the browser without script.
#[must_use]
pub fn form_post(redirect_uri: &str, response: &str) -> String {
    format!(
        concat!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Continue</title></head>",
            "<body><form method=\"post\" action=\"{}\">",
            "<input type=\"hidden\" name=\"response\" value=\"{}\">",
            "<noscript><button type=\"submit\">Continue</button></noscript>",
            "<button type=\"submit\" autofocus>Continue</button></form></body></html>"
        ),
        html_attr(redirect_uri),
        html_attr(response)
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // JARM §2.1, RFC 9207
    #[test]
    fn response_claims_name_issuer_audience_and_expiry() {
        let iss = Issuer::parse("https://acme.id.test").unwrap();
        let c: Value = serde_json::from_slice(&claims(
            &iss,
            "cli_x",
            1_000_000,
            &[("code", "c"), ("state", "s")],
        ))
        .unwrap();
        assert_eq!(c["iss"], "https://acme.id.test");
        assert_eq!(c["aud"], "cli_x");
        assert_eq!(c["exp"], 1060);
        assert_eq!(c["code"], "c");
        assert_eq!(
            query("https://c.example/cb?x=1", "a.b.c"),
            "https://c.example/cb?x=1&response=a.b.c"
        );
    }

    #[test]
    fn the_form_escapes_what_it_posts() {
        let page = form_post("https://c.example/cb?a=1&b=\"2\"", "a.b.c");
        assert!(page.contains("action=\"https://c.example/cb?a=1&amp;b=&quot;2&quot;\""));
        assert!(page.contains("value=\"a.b.c\""));
        assert!(!page.contains("<script"));
    }
}
