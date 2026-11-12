//! `/.well-known/security.txt` (RFC 9116; §14.4 rule 1, SA-14).

use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Contents of `security.txt`. `Contact` and `Expires` are required by RFC 9116.
#[derive(Clone, Debug)]
pub struct SecurityTxt {
    /// `Contact:` URIs, in order of preference.
    pub contacts: Vec<String>,
    /// `Expires:` — RFC 9116 recommends less than one year ahead.
    pub expires: OffsetDateTime,
    /// `Policy:` URI.
    pub policy: Option<String>,
    /// `Canonical:` URI, where this file is published (RFC 9116 §2.5.2).
    pub canonical: Option<String>,
    /// `Preferred-Languages:` value, e.g. `en, tr`.
    pub preferred_languages: Option<String>,
}

impl SecurityTxt {
    /// Renders the file body.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for contact in &self.contacts {
            out.push_str("Contact: ");
            out.push_str(contact);
            out.push('\n');
        }
        out.push_str("Expires: ");
        out.push_str(&self.expires.format(&Rfc3339).unwrap_or_default());
        out.push('\n');
        if let Some(policy) = &self.policy {
            out.push_str("Policy: ");
            out.push_str(policy);
            out.push('\n');
        }
        if let Some(canonical) = &self.canonical {
            out.push_str("Canonical: ");
            out.push_str(canonical);
            out.push('\n');
        }
        if let Some(languages) = &self.preferred_languages {
            out.push_str("Preferred-Languages: ");
            out.push_str(languages);
            out.push('\n');
        }
        out
    }

    /// The `Canonical:` URI of the file served at the origin of `issuer`, an `https` URL.
    #[must_use]
    pub fn canonical_for(issuer: &str) -> Option<String> {
        let rest = issuer.strip_prefix("https://")?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return None;
        }
        Some(format!("https://{authority}/.well-known/security.txt"))
    }

    pub(crate) fn response(&self) -> Response {
        let mut response = self.render().into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response
    }
}
