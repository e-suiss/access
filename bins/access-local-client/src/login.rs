//! The authorization code flow of a public client (RFC 6749 §4.1, RFC 7636, RFC 9449, RFC 9207,
//! OP-149 m.26 (b)) without a browser: `/authorize` stores the request and sends the browser to
//! the hosted login; this client runs the login's JSON steps instead (start the flow, identify,
//! password), returns to `/authorize` with the session cookie, and exchanges the code at
//! `/token` with the PKCE verifier and a DPoP proof. Optionally the request names a platform
//! product as the token's RFC 8707 resource (OP-149 m.26 (a)).

use serde_json::{Value, json};

use crate::ClientError;
use crate::dpop::{Es256Key, pkce, random_text};
use crate::http::{Http, Response, Url};

/// What a sign-in needs.
pub struct Login<'a> {
    /// The realm issuer, e.g. `https://access-server:8443/realms/acme`.
    pub issuer: &'a str,
    /// The public client's `client_id`.
    pub client_id: &'a str,
    /// Its registered redirect URI; nothing listens there, the code is read from the redirect.
    pub redirect_uri: &'a str,
    /// The login identifier.
    pub identifier: &'a str,
    /// The password.
    pub password: &'a str,
    /// The `client_id` of the platform product the token is for, when it is for one.
    pub resource: Option<&'a str>,
    /// The scope; `openid` by default.
    pub scope: &'a str,
}

/// A browser's cookies, name by name.
#[derive(Default)]
struct Jar(Vec<(String, String)>);

impl Jar {
    fn take(&mut self, r: &Response) {
        for c in r.all("set-cookie") {
            let Some((name, value)) = c.split(';').next().and_then(|nv| nv.split_once('=')) else {
                continue;
            };
            self.0.retain(|(n, _)| n != name);
            if !c.to_ascii_lowercase().contains("max-age=0") {
                self.0.push((String::from(name), String::from(value)));
            }
        }
    }

    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn form_encode(s: &str, out: &mut String) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (k, v) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        form_encode(k, &mut out);
        out.push('=');
        form_encode(v, &mut out);
    }
    out
}

fn form_decode(s: &str) -> Option<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i)? {
            b'%' => {
                let hex = s.get(i.checked_add(1)?..i.checked_add(3)?)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i = i.checked_add(3)?;
            }
            b'+' => {
                out.push(b' ');
                i = i.checked_add(1)?;
            }
            b => {
                out.push(*b);
                i = i.checked_add(1)?;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// The value of `name` in the query of `url`, decoded.
#[must_use]
pub fn query(url: &str, name: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == name)
        .and_then(|(_, v)| form_decode(v))
}

fn unexpected(step: &'static str, r: &Response) -> ClientError {
    ClientError::Unexpected {
        step,
        status: r.status,
        body: r.text(),
    }
}

/// Runs the flow and returns the token response with the DPoP key's thumbprint under
/// `dpop_jkt`.
///
/// # Errors
/// [`ClientError`]; an answer that is not the flow's next step is
/// [`ClientError::Unexpected`] with what Access said.
pub async fn login(http: &Http, l: &Login<'_>) -> Result<Value, ClientError> {
    let issuer = Url::parse(l.issuer)?;
    let origin = issuer.origin();
    let key = Es256Key::generate()?;
    let (verifier, challenge) = pkce()?;
    let state = random_text::<16>()?;
    let nonce = random_text::<16>()?;
    let jkt = key.jkt();
    let mut pairs = vec![
        ("client_id", l.client_id),
        ("redirect_uri", l.redirect_uri),
        ("response_type", "code"),
        ("scope", l.scope),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", state.as_str()),
        ("nonce", nonce.as_str()),
        ("dpop_jkt", jkt.as_str()),
    ];
    if let Some(r) = l.resource {
        pairs.push(("resource", r));
    }
    let authorize = format!("{}/authorize?{}", l.issuer, form(&pairs));
    let mut jar = Jar::default();

    // RFC 6749 §4.1.1: without a session the browser is sent to the hosted login
    let first = http.request("GET", &authorize, &[], None).await?;
    let to_login = first.header("location").map(String::from);
    let Some(to_login) = to_login.filter(|_| first.status == 303) else {
        return Err(unexpected("authorize", &first));
    };
    if let Some(error) = query(&to_login, "error") {
        return Err(ClientError::Unexpected {
            step: "authorize",
            status: first.status,
            body: format!(
                "{error}: {}",
                query(&to_login, "error_description").unwrap_or_default()
            ),
        });
    }
    let return_to = query(&to_login, "return_to")
        .filter(|r| r.starts_with(&format!("{}/authorize?", issuer.path.split('?').next().unwrap_or(""))))
        .ok_or_else(|| unexpected("authorize", &first))?;

    // the hosted login's JSON steps (TN-96, TN-132): start, identify, password
    let flows = format!("{}/v1/login/flows", l.issuer);
    let started = post_json(http, &flows, &mut jar, None).await?;
    if started.status != 201 {
        return Err(unexpected("login flow", &started));
    }
    let action = started.json()["action"]
        .as_str()
        .map(|a| format!("{origin}{a}"))
        .ok_or_else(|| unexpected("login flow", &started))?;
    let identified = post_json(
        http,
        &action,
        &mut jar,
        Some(json!({ "method": "identifier", "fields": { "identifier": l.identifier } })),
    )
    .await?;
    if identified.status != 200 || identified.json()["step"] != "authenticate" {
        return Err(unexpected("identifier", &identified));
    }
    let signed_in = post_json(
        http,
        &action,
        &mut jar,
        Some(json!({ "method": "password", "fields": { "password": l.password } })),
    )
    .await?;
    if signed_in.status != 200 || signed_in.json()["step"] != "complete" {
        return Err(ClientError::Unexpected {
            step: "password",
            status: signed_in.status,
            body: signed_in.json()["messages"].to_string(),
        });
    }

    // back to /authorize with the session: the code comes with state and iss (RFC 9207)
    let cookies = jar.header();
    let back = http
        .request(
            "GET",
            &format!("{origin}{return_to}"),
            &[("Cookie", cookies.as_str())],
            None,
        )
        .await?;
    let redirected = back.header("location").map(String::from);
    let Some(redirected) = redirected.filter(|_| back.status == 303) else {
        return Err(unexpected("authorize (signed in)", &back));
    };
    if let Some(error) = query(&redirected, "error") {
        return Err(ClientError::Unexpected {
            step: "authorize (signed in)",
            status: back.status,
            body: error,
        });
    }
    if !redirected.starts_with(l.redirect_uri)
        || query(&redirected, "state").as_deref() != Some(state.as_str())
        || query(&redirected, "iss").as_deref() != Some(l.issuer)
    {
        return Err(unexpected("redirect", &back));
    }
    let code = query(&redirected, "code").ok_or_else(|| unexpected("redirect", &back))?;

    // RFC 6749 §4.1.3, RFC 9449 §5: the exchange, once with the server's DPoP nonce
    let token_url = format!("{}/token", l.issuer);
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("client_id", l.client_id),
        ("code", code.as_str()),
        ("redirect_uri", l.redirect_uri),
        ("code_verifier", verifier.as_str()),
    ];
    if let Some(r) = l.resource {
        pairs.push(("resource", r));
    }
    let body = form(&pairs);
    let mut nonce = None;
    for _ in 0..2 {
        let proof = key.proof("POST", &token_url, nonce.as_deref(), None)?;
        let r = http
            .request(
                "POST",
                &token_url,
                &[("DPoP", proof.as_str())],
                Some(("application/x-www-form-urlencoded", body.as_bytes())),
            )
            .await?;
        if r.status == 200 {
            let mut tokens = r.json();
            if let Some(m) = tokens.as_object_mut() {
                m.insert("dpop_jkt".into(), jkt.into());
            }
            return Ok(tokens);
        }
        let fresh = r.header("dpop-nonce").map(String::from);
        if r.json()["error"] == "use_dpop_nonce" && fresh.is_some() && nonce.is_none() {
            nonce = fresh;
            continue;
        }
        return Err(unexpected("token", &r));
    }
    Err(ClientError::Http(String::from(
        "the token endpoint kept asking for a nonce",
    )))
}

/// `POST url` with `body` as JSON, a fresh `Idempotency-Key` and the jar's cookies; the
/// answer's cookies go into the jar.
async fn post_json(
    http: &Http,
    url: &str,
    jar: &mut Jar,
    body: Option<Value>,
) -> Result<Response, ClientError> {
    let key = random_text::<16>()?;
    let cookies = jar.header();
    let mut headers = vec![("Idempotency-Key", key.as_str())];
    if !cookies.is_empty() {
        headers.push(("Cookie", cookies.as_str()));
    }
    let bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let r = http
        .request(
            "POST",
            url,
            &headers,
            Some(("application/json", bytes.as_bytes())),
        )
        .await?;
    jar.take(&r);
    Ok(r)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // the form coding round-trips and the redirect's query is read decoded
    #[test]
    fn forms_and_queries_round_trip() {
        let f = form(&[("a b", "x&y=z"), ("c", "~")]);
        assert_eq!(f, "a%20b=x%26y%3Dz&c=~");
        assert_eq!(
            query("https://cb/x?code=a%2Fb&state=s+t", "code").as_deref(),
            Some("a/b")
        );
        assert_eq!(
            query("https://cb/x?code=a&state=s+t", "state").as_deref(),
            Some("s t")
        );
        assert!(query("https://cb/x", "code").is_none());
        let mut jar = Jar::default();
        jar.take(&Response {
            status: 200,
            headers: vec![
                ("set-cookie".into(), "__Host-a=1; Path=/; Secure".into()),
                ("set-cookie".into(), "b=2; Path=/".into()),
            ],
            body: Vec::new(),
        });
        jar.take(&Response {
            status: 200,
            headers: vec![("set-cookie".into(), "b=; Max-Age=0; Path=/".into())],
            body: Vec::new(),
        });
        assert_eq!(jar.header(), "__Host-a=1");
    }
}
