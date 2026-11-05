//! Reference adapters for the harness's self-test (OP-150 m.1 (a)): a sans-I/O PEP that
//! fails closed ([`Reference`]), and a negative control that leaks effects on faults
//! ([`Leaky`]) which the harness must flag. Both speak the adapter protocol through
//! [`drive`] over a blocking transport, or through any transport a test supplies.

use std::io::{BufRead, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_decode;
use access_kernel::receipt::{Expected, verify};
use access_kernel::verify::key_scope::DomainMetadata;
use access_kernel::verify::{PureBackend, ed25519};
use serde_json::{Value, json};

use crate::case::Mode;
use crate::fixture::unhex;
use crate::protocol::{CaseMessage, CaseResult, FromSut, Outcome, PROTOCOL, ToSut};

/// An HTTP request a machine wants made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetch {
    /// `GET` or `POST`.
    pub method: &'static str,
    /// Absolute `http://` URL.
    pub url: String,
    /// Content type and body.
    pub body: Option<(&'static str, String)>,
}

/// What came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// A response.
    Response {
        /// Status code.
        status: u16,
        /// Body.
        body: Vec<u8>,
    },
    /// No response: refused, reset or past the deadline.
    Failed(String),
}

/// The next thing a machine does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Make this request and call [`Machine::step`] with the result.
    Fetch(Fetch),
    /// Perform the effect; the case outcome is `allow`.
    Effect,
    /// Final: `deny` with a reason.
    Deny(String),
    /// Final: `error` with a reason; no effect.
    Error(String),
}

/// A sans-I/O PEP for one case.
pub trait Machine {
    /// The next step, given the result of the previous fetch (`None` at the start).
    fn step(&mut self, fetched: Option<Fetched>) -> Step;
}

/// `v[k]`, or `null`.
fn at<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&Value::Null)
}

fn json_body(fetched: Option<Fetched>) -> Result<Value, String> {
    match fetched {
        Some(Fetched::Response { status: 200, body }) => {
            serde_json::from_slice(&body).map_err(|e| format!("malformed body: {e}"))
        }
        Some(Fetched::Response { status, .. }) => Err(format!("upstream answered {status}")),
        Some(Fetched::Failed(why)) => Err(why),
        None => Err(String::from("no response")),
    }
}

fn text_body(fetched: Option<Fetched>) -> Result<String, String> {
    match fetched {
        Some(Fetched::Response { status: 200, body }) => {
            String::from_utf8(body).map_err(|_| String::from("malformed body"))
        }
        Some(Fetched::Response { status, .. }) => Err(format!("upstream answered {status}")),
        Some(Fetched::Failed(why)) => Err(why),
        None => Err(String::from("no response")),
    }
}

fn post_json(url: &str, body: &Value) -> Step {
    Step::Fetch(Fetch {
        method: "POST",
        url: url.to_owned(),
        body: Some(("application/json", body.to_string())),
    })
}

fn get(url: &str) -> Step {
    Step::Fetch(Fetch {
        method: "GET",
        url: url.to_owned(),
        body: None,
    })
}

fn introspect(msg: &CaseMessage) -> Step {
    let token = msg.request.token.clone().unwrap_or_default();
    Step::Fetch(Fetch {
        method: "POST",
        url: msg.upstream.introspection.clone(),
        body: Some((
            "application/x-www-form-urlencoded",
            format!("token={token}&token_type_hint=access_token"),
        )),
    })
}

/// Inflates a zlib stream made only of stored blocks; `None` otherwise.
#[must_use]
pub fn inflate_stored(z: &[u8]) -> Option<Vec<u8>> {
    let (header, mut rest) = z.split_at_checked(2)?;
    if header.first().is_none_or(|b| b & 0x0f != 8) {
        return None;
    }
    let mut out = Vec::new();
    loop {
        let (&flags, after) = rest.split_first()?;
        if flags & 0b110 != 0 {
            return None;
        }
        let (len, after) = after.split_at_checked(4)?;
        let n = u16::from_le_bytes([*len.first()?, *len.get(1)?]);
        let (data, after) = after.split_at_checked(usize::from(n))?;
        out.extend_from_slice(data);
        rest = after;
        if flags & 1 == 1 {
            return Some(out);
        }
    }
}

fn jws_parts(token: &str) -> Option<(&str, Value, Value, Vec<u8>)> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header = serde_json::from_slice(&b64url_decode(h).ok()?).ok()?;
    let payload = serde_json::from_slice(&b64url_decode(p).ok()?).ok()?;
    let signature = b64url_decode(s).ok()?;
    let signed_len = h.len().checked_add(1)?.checked_add(p.len())?;
    Some((token.get(..signed_len)?, header, payload, signature))
}

/// Verifies a compact JWS of type `typ` against a JWKS document; returns its claims.
fn verify_jws(token: &str, typ: &str, jwks: &Value) -> Result<Value, String> {
    let (signed, header, claims, signature) =
        jws_parts(token).ok_or_else(|| String::from("malformed token"))?;
    if at(&header, "alg") != "Ed25519" || at(&header, "typ") != typ {
        return Err(String::from("unexpected alg or typ"));
    }
    let key = at(jwks, "keys")
        .as_array()
        .and_then(|keys| {
            keys.iter().find(|k| {
                at(k, "kid") == at(&header, "kid")
                    && at(k, "kty") == "OKP"
                    && at(k, "crv") == "Ed25519"
            })
        })
        .and_then(|k| at(k, "x").as_str())
        .and_then(|x| b64url_decode(x).ok())
        .ok_or_else(|| String::from("no key for kid"))?;
    ed25519(&PureBackend, &key, signed.as_bytes(), &signature)
        .map_err(|e| format!("signature: {e}"))?;
    Ok(claims)
}

fn status_bit(list: &Value, idx: u64) -> Option<bool> {
    if at(list, "bits") != 1 {
        return None;
    }
    let bytes = inflate_stored(&b64url_decode(at(list, "lst").as_str()?).ok()?)?;
    let byte = bytes.get(usize::try_from(idx / 8).ok()?)?;
    Some(byte >> (idx % 8) & 1 == 1)
}

/// The fail-closed reference PEP: every fault, missing or mismatched receipt, inactive or
/// unverifiable token and stale or unreachable status list ends without an effect.
#[derive(Debug)]
pub struct Reference {
    msg: CaseMessage,
    at: u8,
    jwks: Value,
    status_index: u64,
}

impl Reference {
    /// A machine for one case.
    #[must_use]
    pub const fn new(msg: CaseMessage) -> Self {
        Self {
            msg,
            at: 0,
            jwks: Value::Null,
            status_index: 0,
        }
    }

    fn now_s(&self) -> u64 {
        self.msg.now / 1000
    }

    fn receipt(&self, answer: &Value) -> Step {
        if at(answer, "decision") != true {
            return Step::Deny(String::from("ADP denied"));
        }
        let receipt = &at(at(answer, "context"), "receipt");
        let (Some(sign1), Some(excerpt)) = (
            at(receipt, "sign1")
                .as_str()
                .and_then(|s| b64url_decode(s).ok()),
            at(receipt, "excerpt")
                .as_str()
                .and_then(|s| b64url_decode(s).ok()),
        ) else {
            return Step::Deny(String::from("allow without a receipt"));
        };
        let pinned = (
            unhex(&self.msg.pep.metadata).and_then(|m| DomainMetadata::from_bytes(&m).ok()),
            unhex(&self.msg.pep.domain).and_then(|d| Digest::from_bytes(&d).ok()),
            unhex(&self.msg.request.intent).and_then(|i| Digest::from_bytes(&i).ok()),
        );
        let (Some(metadata), Some(domain), Some(intent)) = pinned else {
            return Step::Error(String::from("bad PEP configuration"));
        };
        let expected = Expected {
            domain: &domain,
            audience: &self.msg.pep.audience,
            intent: &intent,
            now: self.msg.now,
        };
        match verify(&PureBackend, &metadata, &sign1, &excerpt, &expected) {
            Ok(_) => Step::Effect,
            Err(e) => Step::Deny(e.to_string()),
        }
    }

    fn introspected(&self, answer: &Value) -> Step {
        if at(answer, "active") != true {
            return Step::Deny(String::from("token inactive"));
        }
        let aud = at(answer, "aud");
        let ours = *aud == self.msg.pep.audience.as_str()
            || aud
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == self.msg.pep.audience.as_str()));
        if !ours {
            return Step::Deny(String::from("token for another audience"));
        }
        if at(answer, "exp")
            .as_u64()
            .is_none_or(|exp| exp <= self.now_s())
        {
            return Step::Deny(String::from("token expired"));
        }
        Step::Effect
    }

    fn token_claims(&mut self) -> Step {
        let token = self.msg.request.token.clone().unwrap_or_default();
        let claims = match verify_jws(&token, "at+jwt", &self.jwks) {
            Ok(c) => c,
            Err(e) => return Step::Deny(e),
        };
        let now = self.now_s();
        if at(&claims, "iss") != self.msg.pep.issuer.as_str()
            || at(&claims, "aud") != self.msg.pep.audience.as_str()
        {
            return Step::Deny(String::from("issuer or audience mismatch"));
        }
        if at(&claims, "exp").as_u64().is_none_or(|exp| exp <= now)
            || at(&claims, "iat")
                .as_u64()
                .is_none_or(|iat| iat > now.saturating_add(60))
        {
            return Step::Deny(String::from("token outside its validity"));
        }
        let reference = &at(at(&claims, "status"), "status_list");
        let (Some(idx), Some(uri)) = (at(reference, "idx").as_u64(), at(reference, "uri").as_str())
        else {
            return Step::Deny(String::from("token without a status reference"));
        };
        self.status_index = idx;
        get(uri)
    }

    fn status(&self, body: &str) -> Step {
        let claims = match verify_jws(body.trim(), "statuslist+jwt", &self.jwks) {
            Ok(c) => c,
            Err(e) => return Step::Error(format!("status list: {e}")),
        };
        if at(&claims, "exp")
            .as_u64()
            .is_none_or(|exp| exp <= self.now_s())
        {
            return Step::Error(String::from("status list is stale"));
        }
        match status_bit(at(&claims, "status_list"), self.status_index) {
            Some(false) => Step::Effect,
            Some(true) => Step::Deny(String::from("token revoked")),
            None => Step::Error(String::from("status list unreadable")),
        }
    }
}

impl Machine for Reference {
    fn step(&mut self, fetched: Option<Fetched>) -> Step {
        let phase = self.at;
        self.at = self.at.saturating_add(1);
        match (self.msg.request.mode, phase) {
            (Mode::Decision, 0) => post_json(&self.msg.upstream.adp, &self.msg.request.evaluation),
            (Mode::Decision, 1) => match json_body(fetched) {
                Ok(answer) => self.receipt(&answer),
                Err(e) => Step::Error(e),
            },
            (Mode::Introspection, 0) => introspect(&self.msg),
            (Mode::Introspection, 1) => match json_body(fetched) {
                Ok(answer) => self.introspected(&answer),
                Err(e) => Step::Error(e),
            },
            (Mode::Jwt, 0) => get(&self.msg.upstream.jwks),
            (Mode::Jwt, 1) => match json_body(fetched) {
                Ok(jwks) => {
                    self.jwks = jwks;
                    self.token_claims()
                }
                Err(e) => Step::Error(format!("jwks: {e}")),
            },
            (Mode::Jwt, 2) => match text_body(fetched) {
                Ok(body) => self.status(&body),
                Err(e) => Step::Error(format!("status list: {e}")),
            },
            _ => Step::Error(String::from("protocol state")),
        }
    }
}

/// The negative control: it treats every upstream fault as permission, ignores receipts and
/// ignores status list freshness. The harness must flag it.
#[derive(Debug)]
pub struct Leaky {
    msg: CaseMessage,
    at: u8,
}

impl Leaky {
    /// A machine for one case.
    #[must_use]
    pub const fn new(msg: CaseMessage) -> Self {
        Self { msg, at: 0 }
    }
}

impl Machine for Leaky {
    fn step(&mut self, fetched: Option<Fetched>) -> Step {
        let phase = self.at;
        self.at = self.at.saturating_add(1);
        match (self.msg.request.mode, phase) {
            (Mode::Decision, 0) => post_json(&self.msg.upstream.adp, &self.msg.request.evaluation),
            (Mode::Decision, 1) => match json_body(fetched) {
                Ok(answer) if at(&answer, "decision") == false => {
                    Step::Deny(String::from("denied"))
                }
                _ => Step::Effect,
            },
            (Mode::Introspection, 0) => introspect(&self.msg),
            (Mode::Introspection, 1) => match json_body(fetched) {
                Ok(answer) if at(&answer, "active") == false => {
                    Step::Deny(String::from("inactive"))
                }
                _ => Step::Effect,
            },
            (Mode::Jwt, 0) => get(&self.msg.upstream.jwks),
            (Mode::Jwt, 1) => {
                let token = self.msg.request.token.clone().unwrap_or_default();
                let uri = jws_parts(&token).and_then(|(_, _, c, _)| {
                    at(at(at(&c, "status"), "status_list"), "uri")
                        .as_str()
                        .map(str::to_owned)
                });
                match (json_body(fetched), uri) {
                    (Ok(_), Some(uri)) => get(&uri),
                    _ => Step::Effect,
                }
            }
            (Mode::Jwt, 2) => {
                let revoked = text_body(fetched).ok().and_then(|body| {
                    let (_, _, claims, _) = jws_parts(body.trim())?;
                    status_bit(at(&claims, "status_list"), 0)
                });
                if revoked == Some(true) {
                    Step::Deny(String::from("revoked"))
                } else {
                    Step::Effect
                }
            }
            _ => Step::Effect,
        }
    }
}

/// Blocking HTTP/1.1 over TCP for `http://` URLs, bounded by `until`.
///
/// # Errors
/// [`Fetched::Failed`] is returned, never an error.
#[must_use]
pub fn fetch_blocking(request: &Fetch, until: Instant) -> Fetched {
    match try_fetch(request, until) {
        Ok(f) => f,
        Err(e) => Fetched::Failed(e),
    }
}

fn try_fetch(request: &Fetch, until: Instant) -> Result<Fetched, String> {
    let rest = request
        .url
        .strip_prefix("http://")
        .ok_or_else(|| String::from("only http:// URLs"))?;
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let path = if path.is_empty() { "/" } else { path };
    let left = || {
        until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| String::from("deadline passed"))
    };
    let addr = authority
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| String::from("no address"))?;
    let mut stream = TcpStream::connect_timeout(&addr, left()?).map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(left()?))
        .map_err(|e| e.to_string())?;
    let mut head = format!(
        "{} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: */*\r\n",
        request.method
    );
    let body = match &request.body {
        Some((content_type, body)) => {
            head.push_str("Content-Type: ");
            head.push_str(content_type);
            head.push_str("\r\nContent-Length: ");
            head.push_str(&body.len().to_string());
            head.push_str("\r\n");
            body.as_str()
        }
        None => "",
    };
    head.push_str("\r\n");
    head.push_str(body);
    stream
        .write_all(head.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        stream
            .set_read_timeout(Some(left()?))
            .map_err(|e| e.to_string())?;
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(buf.get(..n).unwrap_or_default()),
            Err(e) => return Err(e.to_string()),
        }
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| String::from("malformed response"))?;
    let (head, body) = raw.split_at(split);
    let head = String::from_utf8_lossy(head).to_ascii_lowercase();
    if head.contains("transfer-encoding: chunked") {
        return Err(String::from("chunked responses are not supported"));
    }
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| String::from("malformed status line"))?;
    Ok(Fetched::Response {
        status,
        body: body.get(4..).unwrap_or_default().to_vec(),
    })
}

/// Runs a machine to its end with `fetch`, performing the effect at the resource when the
/// machine allows.
pub fn drive(
    msg: &CaseMessage,
    machine: &mut impl Machine,
    mut fetch: impl FnMut(&Fetch) -> Fetched,
) -> CaseResult {
    let result = |outcome, detail: String| CaseResult {
        case: msg.case.clone(),
        outcome,
        detail: Some(detail),
    };
    let mut fetched = None;
    loop {
        match machine.step(fetched.take()) {
            Step::Fetch(request) => fetched = Some(fetch(&request)),
            Step::Effect => {
                let effect = Fetch {
                    method: "POST",
                    url: msg.upstream.effect.clone(),
                    body: Some(("application/json", json!({ "case": msg.case }).to_string())),
                };
                return match fetch(&effect) {
                    Fetched::Response {
                        status: 200..=299, ..
                    } => result(Outcome::Allow, String::from("effect performed")),
                    other => result(Outcome::Error, format!("effect failed: {other:?}")),
                };
            }
            Step::Deny(why) => return result(Outcome::Deny, why),
            Step::Error(why) => return result(Outcome::Error, why),
        }
    }
}

/// Serves the adapter protocol on stdin and stdout with blocking HTTP.
///
/// # Errors
/// I/O errors on stdin or stdout.
pub fn serve<M: Machine>(name: &str, new: fn(CaseMessage) -> M) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        let reply = match serde_json::from_str::<ToSut>(&line) {
            Ok(ToSut::Hello { .. }) => FromSut::Ready {
                protocol: PROTOCOL.to_owned(),
                name: name.to_owned(),
            },
            Ok(ToSut::Case(msg)) => {
                let msg = *msg;
                let budget = Duration::from_millis(msg.deadline_ms);
                let after = |start: Instant| start.checked_add(budget).unwrap_or(start);
                let until = after(Instant::now());
                let mut machine = new(msg.clone());
                FromSut::Result(drive(&msg, &mut machine, |f| {
                    let until = if f.url == msg.upstream.effect {
                        after(Instant::now())
                    } else {
                        until
                    };
                    fetch_blocking(f, until)
                }))
            }
            Ok(ToSut::Bye) | Err(_) => return Ok(()),
        };
        let text = serde_json::to_string(&reply).map_err(std::io::Error::other)?;
        writeln!(stdout, "{text}")?;
        stdout.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::zlib_stored;

    // OP-150 m.1 (a)
    #[test]
    fn stored_zlib_round_trips_and_other_streams_are_refused() {
        for data in [&[][..], &[0], &[1, 0, 0xff], &[7; 300]] {
            assert_eq!(inflate_stored(&zlib_stored(data)).as_deref(), Some(data));
        }
        assert_eq!(inflate_stored(&[0x78, 0x9c, 0x03, 0x00]), None);
        let list =
            json!({ "bits": 1, "lst": access_kernel::json::b64url_encode(&zlib_stored(&[0b10])) });
        assert_eq!(status_bit(&list, 0), Some(false));
        assert_eq!(status_bit(&list, 1), Some(true));
        assert_eq!(status_bit(&list, 8), None);
    }
}
