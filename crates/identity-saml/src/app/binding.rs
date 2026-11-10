//! SAML bindings (SAML Bindings §3.4, §3.5; §10.6.1): HTTP-Redirect with raw DEFLATE and a
//! signature over the original URL-encoded values, HTTP-POST as an auto-submitting page whose
//! script carries the response's CSP nonce, and the HMAC that binds an IdP-initiated
//! `RelayState` to its service provider.

use crate::alg::SigAlg;
use crate::dsig::{SignError, XmlSigner};
use crate::sp::b64;
use crate::xml::html;

/// Percent-encodes `s` for a query value (RFC 3986 unreserved characters kept).
#[must_use]
pub fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{b:02X}"));
        }
    }
    out
}

/// Decodes a URL-encoded query or form value (`+` is a space); `None` for a malformed escape or
/// a value that is not UTF-8.
#[must_use]
pub fn form_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'+' => out.push(b' '),
            b'%' => {
                let hex =
                    core::str::from_utf8(b.get(i.checked_add(1)?..i.checked_add(3)?)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i = i.checked_add(2)?;
            }
            c => out.push(c),
        }
        i = i.checked_add(1)?;
    }
    String::from_utf8(out).ok()
}

/// The signed HTTP-Redirect URL of `message` (`SAMLRequest` or `SAMLResponse`) to `location`:
/// raw DEFLATE, base64, then `param=…&RelayState=…&SigAlg=…` signed as these encoded octets.
///
/// # Errors
/// [`SignError`].
pub async fn redirect<S: XmlSigner>(
    signer: &S,
    location: &str,
    param: &str,
    message: &str,
    relay_state: Option<&str>,
    alg: SigAlg,
) -> Result<String, SignError> {
    let deflated = miniz_oxide::deflate::compress_to_vec(message.as_bytes(), 6);
    let mut query = format!("{param}={}", encode(&b64::encode(&deflated)));
    if let Some(r) = relay_state {
        query.push_str("&RelayState=");
        query.push_str(&encode(r));
    }
    query.push_str("&SigAlg=");
    query.push_str(&encode(alg.uri()));
    let s = signer.sign(query.clone().into_bytes(), alg).await?;
    let sep = if location.contains('?') { '&' } else { '?' };
    Ok(format!(
        "{location}{sep}{query}&Signature={}",
        encode(&b64::encode(&s.value))
    ))
}

/// The octets an HTTP-Redirect signature covers, rebuilt from the raw (still URL-encoded) query
/// values as received, in the order the binding fixes; `RelayState` only when present.
#[must_use]
pub fn signed_octets(
    param: &str,
    raw_message: &str,
    raw_relay: Option<&str>,
    raw_sig_alg: &str,
) -> Vec<u8> {
    let mut s = format!("{param}={raw_message}");
    if let Some(r) = raw_relay {
        s.push_str("&RelayState=");
        s.push_str(r);
    }
    s.push_str("&SigAlg=");
    s.push_str(raw_sig_alg);
    s.into_bytes()
}

/// A fresh nonce for a page's `Content-Security-Policy` script source.
#[must_use]
pub fn csp_nonce() -> String {
    access_crypto::random::bytes::<16>()
        .map(|b| {
            crate::sp::b64::encode(&b)
                .trim_end_matches('=')
                .replace('+', "-")
                .replace('/', "_")
        })
        .unwrap_or_default()
}

/// An HTML page that posts `fields` to `action` at once; the script runs only under `nonce`.
#[must_use]
pub fn post_page(action: &str, fields: &[(&str, &str)], nonce: &str) -> String {
    let mut inputs = String::new();
    for (name, value) in fields {
        let _ = std::fmt::Write::write_fmt(
            &mut inputs,
            format_args!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                html(name),
                html(value)
            ),
        );
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Signing in</title></head><body><form method=\"post\" action=\"{}\">{inputs}<noscript><button type=\"submit\">Continue</button></noscript></form><script nonce=\"{}\">document.forms[0].submit()</script></body></html>",
        html(action),
        html(nonce)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // §3.4.4.1
    #[test]
    fn redirect_signed_octets_use_the_received_encoding() {
        assert_eq!(
            signed_octets("SAMLRequest", "fZ%2B", Some("a%20b"), "http%3A%2F%2Fx"),
            b"SAMLRequest=fZ%2B&RelayState=a%20b&SigAlg=http%3A%2F%2Fx"
        );
        assert_eq!(
            signed_octets("SAMLResponse", "x", None, "y"),
            b"SAMLResponse=x&SigAlg=y"
        );
        assert_eq!(encode("a b/+="), "a%20b%2F%2B%3D");
    }

    // §10.6.1
    #[test]
    fn the_post_page_escapes_and_carries_the_nonce() {
        let nonce: String = (0..5_u8).map(|i| char::from(b'a' + i)).collect();
        let p = post_page(
            "https://sp.test/acs?a=1&b=\"",
            &[("SAMLResponse", "PD94<>"), ("RelayState", "r\"")],
            &nonce,
        );
        assert!(p.contains("action=\"https://sp.test/acs?a=1&amp;b=&quot;\""));
        assert!(p.contains("value=\"PD94&lt;&gt;\""));
        assert!(p.contains("value=\"r&quot;\""));
        assert!(p.contains(&format!("<script nonce=\"{nonce}\">")));
    }
}
