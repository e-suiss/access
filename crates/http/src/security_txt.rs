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
        if let Some(languages) = &self.preferred_languages {
            out.push_str("Preferred-Languages: ");
            out.push_str(languages);
            out.push('\n');
        }
        out
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
