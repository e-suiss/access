//! The authorization code flow of a public client (RFC 6749 §4.1, RFC 7636, RFC 9449, RFC 9207,
//! OP-149 m.26 (b)) without a browser: `/authorize` stores the request and sends the browser to
//! the hosted login; this client runs the login's JSON steps instead (start the flow, identify,
//! then the password or a passkey assertion, OP-149 m.26 (e)), returns to `/authorize` with the
//! session cookie, and exchanges the code at `/token` with the PKCE verifier and a DPoP proof.
//! Optionally the request names a platform product as the token's RFC 8707 resource (OP-149
//! m.26 (a)).

use std::fmt::Write as _;

use serde_json::{Value, json};

use access_kernel::json::b64url_decode;

use crate::ClientError;
use crate::dpop::{Es256Key, pkce, random_text};
use crate::http::{Http, Response, Url};
use crate::passkey::Passkey;

/// What the test user signs in with after the identifier.
#[derive(Clone, Copy)]
pub enum Credential<'a> {
    /// The password (AAL1); with a passkey, it answers the second factor the realm asks for
    /// once the account holds one (IDP-8).
    Password(&'a str, Option<&'a Passkey<'a>>),
    /// The software passkey (AAL2, phishing-resistant).
    Passkey(&'a Passkey<'a>),
}

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
    /// The first factor.
    pub credential: Credential<'a>,
    /// The `client_id` of the platform product the token is for, when it is for one.
    pub resource: Option<&'a str>,
    /// The scope; `openid` by default.
    pub scope: &'a str,
}

/// A browser's cookies, name by name.
#[derive(Default)]
pub struct Jar(Vec<(String, String)>);

impl Jar {
    /// Takes the answer's `Set-Cookie` headers.
    pub fn take(&mut self, r: &Response) {
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

    /// The `Cookie` header.
    #[must_use]
    pub fn header(&self) -> String {
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
            let _ = write!(out, "%{b:02X}");
        }
    }
}

pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
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

/// The text member `key` of a JSON answer.
fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(String::from)
}

/// The `Location` of a `303`, with an OAuth `error` in its query reported as such.
fn redirect(step: &'static str, r: &Response) -> Result<String, ClientError> {
    let location = r.header("location").map(String::from);
    let Some(location) = location.filter(|_| r.status == 303) else {
        return Err(unexpected(step, r));
    };
    if let Some(error) = query(&location, "error") {
        return Err(ClientError::Unexpected {
            step,
            status: r.status,
            body: format!(
                "{error}: {}",
                query(&location, "error_description").unwrap_or_default()
            ),
        });
    }
    Ok(location)
}

/// One run's request state: the DPoP key, the PKCE pair and the request's `state`.
struct Run {
    key: Es256Key,
    verifier: String,
    challenge: String,
    state: String,
    nonce: String,
}

impl Run {
    fn new() -> Result<Self, ClientError> {
        let (verifier, challenge) = pkce()?;
        Ok(Self {
            key: Es256Key::generate()?,
            verifier,
            challenge,
            state: random_text::<16>()?,
            nonce: random_text::<16>()?,
        })
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
    let run = Run::new()?;
    let return_to = authorize(http, l, &issuer, &run).await?;
    let jar = sign_in(http, l.issuer, l.identifier, l.credential).await?;
    let code = code(http, l, &issuer, &run, &return_to, &jar).await?;
    exchange(http, l, &run, &code).await
}

/// RFC 6749 §4.1.1: without a session the browser is sent to the hosted login; the `return_to`
/// it carries names only this realm's stored request (X41).
async fn authorize(
    http: &Http,
    l: &Login<'_>,
    issuer: &Url,
    run: &Run,
) -> Result<String, ClientError> {
    let jkt = run.key.jkt();
    let mut pairs = vec![
        ("client_id", l.client_id),
        ("redirect_uri", l.redirect_uri),
        ("response_type", "code"),
        ("scope", l.scope),
        ("code_challenge", run.challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", run.state.as_str()),
        ("nonce", run.nonce.as_str()),
        ("dpop_jkt", jkt.as_str()),
    ];
    if let Some(r) = l.resource {
        pairs.push(("resource", r));
    }
    let url = format!("{}/authorize?{}", l.issuer, form(&pairs));
    let first = http.request("GET", &url, &[], None).await?;
    let to_login = redirect("authorize", &first)?;
    let prefix = format!("{}/authorize?", issuer.path.trim_end_matches('/'));
    query(&to_login, "return_to")
        .filter(|r| r.starts_with(&prefix))
        .ok_or_else(|| unexpected("authorize", &first))
}

/// The passkey challenge the authenticate step offers (TN-96): the `passkey_get` node's
/// request options.
fn passkey_challenge(step: &Value) -> Option<Vec<u8>> {
    step.get("nodes")?
        .as_array()?
        .iter()
        .find(|n| n.get("type").and_then(Value::as_str) == Some("passkey_get"))?
        .get("options")?
        .get("challenge")?
        .as_str()
        .and_then(|c| b64url_decode(c).ok())
}

/// The hosted login's JSON steps (TN-96, TN-132): start, identify, then the password or a
/// passkey assertion over the step's challenge; each step's `action` is a path under the
/// realm, as the login page uses it. The jar comes back with the session cookie.
///
/// # Errors
/// [`ClientError`]; a refused factor is [`ClientError::Unexpected`] with what Access said.
pub async fn sign_in(
    http: &Http,
    issuer: &str,
    identifier: &str,
    credential: Credential<'_>,
) -> Result<Jar, ClientError> {
    let mut jar = Jar::default();
    let action = |r: &Response, step: &'static str| -> Result<String, ClientError> {
        text(&r.json(), "action")
            .map(|a| format!("{issuer}{a}"))
            .ok_or_else(|| unexpected(step, r))
    };
    let flows = format!("{issuer}/v1/login/flows");
    let started = post_json(http, &flows, &mut jar, None).await?;
    if started.status != 201 {
        return Err(unexpected("login flow", &started));
    }
    let second = post_json(
        http,
        &action(&started, "login flow")?,
        &mut jar,
        Some(json!({ "method": "identifier", "fields": { "identifier": identifier } })),
    )
    .await?;
    if second.status != 200 || text(&second.json(), "step").as_deref() != Some("authenticate") {
        return Err(unexpected("identifier", &second));
    }
    let passkey_step = |step: &Response, passkey: &Passkey<'_>| -> Result<Value, ClientError> {
        let challenge =
            passkey_challenge(&step.json()).ok_or_else(|| unexpected("passkey options", step))?;
        let assertion = passkey.assert(&challenge)?;
        Ok(
            json!({ "method": "passkey", "fields": { "passkey_credential": assertion.to_string() } }),
        )
    };
    let (step, submission, second_factor) = match credential {
        Credential::Password(password, passkey) => (
            "password",
            json!({ "method": "password", "fields": { "password": password } }),
            passkey,
        ),
        Credential::Passkey(passkey) => ("passkey", passkey_step(&second, passkey)?, None),
    };
    let mut answer = post_json(
        http,
        &action(&second, "identifier")?,
        &mut jar,
        Some(submission),
    )
    .await?;
    if answer.status == 200
        && text(&answer.json(), "step").as_deref() == Some("second_factor")
        && let Some(passkey) = second_factor
    {
        let submission = passkey_step(&answer, passkey)?;
        answer = post_json(
            http,
            &action(&answer, "second factor")?,
            &mut jar,
            Some(submission),
        )
        .await?;
    }
    if answer.status != 200 || text(&answer.json(), "step").as_deref() != Some("complete") {
        return Err(unexpected(step, &answer));
    }
    Ok(jar)
}

/// Back to `/authorize` with the session: the code comes with `state` and `iss` (RFC 9207).
async fn code(
    http: &Http,
    l: &Login<'_>,
    issuer: &Url,
    run: &Run,
    return_to: &str,
    jar: &Jar,
) -> Result<String, ClientError> {
    let cookies = jar.header();
    let back = http
        .request(
            "GET",
            &format!("{}{return_to}", issuer.origin()),
            &[("Cookie", cookies.as_str())],
            None,
        )
        .await?;
    let redirected = redirect("authorize (signed in)", &back)?;
    if !redirected.starts_with(l.redirect_uri)
        || query(&redirected, "state").as_deref() != Some(run.state.as_str())
        || query(&redirected, "iss").as_deref() != Some(l.issuer)
    {
        return Err(unexpected("redirect", &back));
    }
    query(&redirected, "code").ok_or_else(|| unexpected("redirect", &back))
}

/// RFC 6749 §4.1.3, RFC 9449 §5: the exchange, once more with the server's DPoP nonce when it
/// asks for one.
async fn exchange(http: &Http, l: &Login<'_>, run: &Run, code: &str) -> Result<Value, ClientError> {
    let token_url = format!("{}/token", l.issuer);
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("client_id", l.client_id),
        ("code", code),
        ("redirect_uri", l.redirect_uri),
        ("code_verifier", run.verifier.as_str()),
    ];
    if let Some(r) = l.resource {
        pairs.push(("resource", r));
    }
    let body = form(&pairs);
    let mut nonce = None;
    for _ in 0..2 {
        let proof = run.key.proof("POST", &token_url, nonce.as_deref(), None)?;
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
                m.insert("dpop_jkt".into(), run.key.jkt().into());
            }
            return Ok(tokens);
        }
        let fresh = r.header("dpop-nonce").map(String::from);
        if text(&r.json(), "error").as_deref() == Some("use_dpop_nonce")
            && fresh.is_some()
            && nonce.is_none()
        {
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
///
/// # Errors
/// [`ClientError`].
pub async fn post_json(
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
        // RFC 6749 §4.1.2.1: an error in the redirect is reported, not followed
        let r = Response {
            status: 303,
            headers: vec![(
                "location".into(),
                "https://cb/x?error=invalid_target&error_description=unknown%20resource".into(),
            )],
            body: Vec::new(),
        };
        let e = redirect("authorize", &r).unwrap_err().to_string();
        assert!(e.contains("invalid_target: unknown resource"), "{e}");
    }
}
