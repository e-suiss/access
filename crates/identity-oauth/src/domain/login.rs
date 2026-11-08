//! The contract between `/authorize` and the hosted login (OP-146 I7, I9): a request that needs
//! the user is stored, the browser goes to the login page with a `return_to` that names only
//! that stored request, and comes back to `/authorize` once signed in. `return_to` is a
//! path under the realm issuer, never a URL the login page could be steered elsewhere with.

use crate::domain::issuer::{Issuer, form_encode};
use crate::domain::metadata::Endpoint;

/// The `return_to` of a stored request: `<issuer path>/authorize?client_id=…&request_uri=…`.
#[must_use]
pub fn return_to(issuer: &Issuer, client_id: &str, request_uri: &str) -> String {
    let mut out = format!("{}{}?client_id=", issuer.path(), Endpoint::Authorize.path());
    form_encode(client_id, &mut out);
    out.push_str("&request_uri=");
    form_encode(request_uri, &mut out);
    out
}

/// Whether `value` is a `return_to` the login page may send the browser to: a path-absolute
/// reference to this issuer's `/authorize` with a query of unreserved and percent-encoded
/// characters only. The login surface checks this before following it.
#[must_use]
pub fn return_to_ok(issuer: &Issuer, value: &str) -> bool {
    let prefix = format!("{}{}?", issuer.path(), Endpoint::Authorize.path());
    value.strip_prefix(&prefix).is_some_and(|q| {
        !q.is_empty()
            && q.bytes().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, b'-' | b'.' | b'_' | b'*' | b'%' | b'&' | b'=' | b'+')
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-104, X41
    #[test]
    fn return_to_names_only_the_stored_request() {
        let sub = Issuer::parse("https://acme.id.test").unwrap();
        let path = Issuer::parse("https://id.test/realms/beta").unwrap();
        let r = return_to(&sub, "cli_x", "urn:ietf:params:oauth:request_uri:abc");
        assert_eq!(
            r,
            "/authorize?client_id=cli_x&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc"
        );
        assert!(return_to_ok(&sub, &r));
        assert!(!return_to_ok(&path, &r));
        assert!(return_to_ok(&path, &return_to(&path, "cli_x", "u")));
        for bad in [
            "https://evil.test/authorize?x=1",
            "//evil.test/authorize?x=1",
            "/authorize?x=1/../../evil",
            "/authorize?",
            "/authorizex?a=b",
            "/authorize?a=b#frag",
        ] {
            assert!(!return_to_ok(&sub, bad), "{bad}");
        }
    }
}
