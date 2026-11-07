//! Requests Access makes to URLs a client registered: its `jwks_uri` (RFC 7523, §11.3.6) and
//! its back-channel logout endpoint (§10.4.6). The URL is the client's, so every request is
//! guarded against server-side request forgery (§14.3):
//!
//! - `https` on port 443 only, no user info, no fragment;
//! - the host is resolved once and every address it resolves to must be public: no loopback,
//!   private, link-local (cloud metadata), shared, documentation, multicast or reserved range,
//!   also when wrapped in IPv6; the connection goes to the checked address, so a second
//!   resolution cannot point it elsewhere;
//! - redirects are not followed; a `3xx` is an answer like any other;
//! - one deadline for the whole exchange, a bounded response head and a bounded body.
//!
//! The one exception is an event delivery endpoint the operator declared (OP-149 m.23): a push
//! or webhook `POST` to a URL byte-for-byte equal to a declared target may reach a private
//! address and a port other than 443. Its certificate is still verified, against the target's
//! own trust anchors when it names them. Every other request keeps the rules above.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Largest response head read.
pub const MAX_HEAD: usize = 16 * 1024;

/// Why an outbound request did not get an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OutboundError {
    /// Not an `https` URL Access requests.
    #[error("not an https URL Access requests")]
    Url,
    /// The host resolves to an address Access does not connect to.
    #[error("address refused")]
    Blocked,
    /// No answer: resolution, connection, TLS or I/O failed, or the deadline passed.
    #[error("no answer")]
    Unreachable,
    /// The answer is not HTTP/1.1 or is larger than allowed.
    #[error("malformed or oversized answer")]
    Malformed,
}

impl OutboundError {
    /// Whether trying again later may help.
    #[must_use]
    pub const fn transient(self) -> bool {
        matches!(self, Self::Unreachable)
    }
}

/// An answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// Status.
    pub status: u16,
    /// `Cache-Control: max-age`, seconds; `None` without one, `Some(0)` for `no-store` and
    /// `no-cache`.
    pub max_age_s: Option<u64>,
    /// `Retry-After` in seconds.
    pub retry_after_s: Option<u64>,
    /// The body, when it was read.
    pub body: Vec<u8>,
}

/// An `https` URL split for the request line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    host: String,
    port: u16,
    path: String,
}

fn path_char(c: u8) -> bool {
    c.is_ascii_graphic() && c != b'#'
}

impl Target {
    /// Parses `https://host[:port][/path][?query]`.
    ///
    /// # Errors
    /// [`OutboundError::Url`].
    pub fn parse(url: &str) -> Result<Self, OutboundError> {
        if url.len() > 2048 {
            return Err(OutboundError::Url);
        }
        let rest = url.strip_prefix("https://").ok_or(OutboundError::Url)?;
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.contains('@') || !path.bytes().all(path_char) {
            return Err(OutboundError::Url);
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or(OutboundError::Url)?;
            h.parse::<Ipv6Addr>().map_err(|_| OutboundError::Url)?;
            (h, after.strip_prefix(':'))
        } else {
            match authority.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        let port = match port {
            Some(p) => p.parse::<u16>().map_err(|_| OutboundError::Url)?,
            None => 443,
        };
        let host_ok = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b':');
        if !host_ok || port == 0 {
            return Err(OutboundError::Url);
        }
        let path = if path.starts_with('?') {
            format!("/{path}")
        } else if path.is_empty() {
            String::from("/")
        } else {
            String::from(path)
        };
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    /// The port connected to.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The URL as Access writes it: lowercase host, the port only when not 443, and a path.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!("https://{}{}", self.host_header(), self.path)
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Whether Access may connect to `ip` on a client's behalf (§14.3).
#[must_use]
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19)))
}

fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = Ipv4Addr::new(
        s[6].to_be_bytes()[0],
        s[6].to_be_bytes()[1],
        s[7].to_be_bytes()[0],
        s[7].to_be_bytes()[1],
    );
    match s {
        [0, 0, 0, 0, 0, 0xffff | 0, _, _] | [0x64, 0xff9b, 0, 0, 0, 0, _, _] => Some(tail),
        [0x2002, hi, lo, ..] => Some(Ipv4Addr::new(
            hi.to_be_bytes()[0],
            hi.to_be_bytes()[1],
            lo.to_be_bytes()[0],
            lo.to_be_bytes()[1],
        )),
        _ => None,
    }
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return public_v4(v4);
    }
    let s = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x2001 && s[1] == 0)
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
        || s[0] == 0x3fff)
}

/// The one address of `target` Access connects to: every address it resolves to must be
/// public.
async fn resolve(target: &Target) -> Result<SocketAddr, OutboundError> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return if public(ip) {
            Ok(SocketAddr::new(ip, target.port))
        } else {
            Err(OutboundError::Blocked)
        };
    }
    let found: Vec<SocketAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|_| OutboundError::Unreachable)?
        .collect();
    if found.iter().any(|a| !public(a.ip())) {
        return Err(OutboundError::Blocked);
    }
    found.into_iter().next().ok_or(OutboundError::Unreachable)
}

/// A connection to a declared target: its host may resolve to any address; the first that
/// answers is used.
async fn connect_declared(target: &Target) -> Result<TcpStream, OutboundError> {
    let found: Vec<SocketAddr> = match target.host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, target.port)],
        Err(_) => tokio::net::lookup_host((target.host.as_str(), target.port))
            .await
            .map_err(|_| OutboundError::Unreachable)?
            .collect(),
    };
    for addr in found {
        if let Ok(tcp) = TcpStream::connect(addr).await {
            return Ok(tcp);
        }
    }
    Err(OutboundError::Unreachable)
}

/// The exact URLs of the event delivery targets the operator declared (OP-149 m.23): what
/// stream creation and the `suiss_event_receiver` check consult.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclaredTargets(Arc<[String]>);

impl DeclaredTargets {
    /// The declarations of `urls`.
    #[must_use]
    pub fn new(urls: impl IntoIterator<Item = String>) -> Self {
        Self(urls.into_iter().collect())
    }

    /// The declared URLs.
    #[must_use]
    pub fn urls(&self) -> &[String] {
        &self.0
    }

    /// Whether `url` is byte-for-byte a declared target.
    #[must_use]
    pub fn declares(&self, url: &str) -> bool {
        self.0.iter().any(|d| d == url)
    }

    /// Whether `url` may be an event delivery endpoint: an `https` URL Access requests that is
    /// declared, or that is on port 443 without a non-public address literal for a host. A
    /// host name that resolves to a private address is refused at delivery (§14.3).
    #[must_use]
    pub fn accepts(&self, url: &str) -> bool {
        let Ok(t) = Target::parse(url) else {
            return false;
        };
        self.declares(url) || (t.port == PORT && t.host.parse::<IpAddr>().ok().is_none_or(public))
    }
}

/// One delivery target the operator declared (OP-149 m.23): its exact URL and, when given, the
/// only trust anchors its certificate may chain to.
#[derive(Clone)]
pub struct DeclaredTarget {
    url: String,
    target: Target,
    connector: Option<TlsConnector>,
}

impl core::fmt::Debug for DeclaredTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeclaredTarget")
            .field("url", &self.url)
            .field("own_anchors", &self.connector.is_some())
            .finish_non_exhaustive()
    }
}

impl DeclaredTarget {
    /// `url`, which must be written as [`Target::canonical`] writes it, verified against `tls`
    /// when given and against the operator's trust anchors otherwise.
    ///
    /// # Errors
    /// [`OutboundError::Url`].
    pub fn new(url: &str, tls: Option<Arc<rustls::ClientConfig>>) -> Result<Self, OutboundError> {
        let target = Target::parse(url)?;
        if target.canonical() != url {
            return Err(OutboundError::Url);
        }
        Ok(Self {
            url: String::from(url),
            target,
            connector: tls.map(TlsConnector::from),
        })
    }

    /// The declared URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The port it is reached on.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.target.port
    }
}

fn header<'a>(headers: &'a [httparse::Header<'_>], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| core::str::from_utf8(h.value).ok())
        .map(str::trim)
}

fn max_age(value: &str) -> Option<u64> {
    let mut out = None;
    for d in value.split(',').map(str::trim) {
        let lower = d.to_ascii_lowercase();
        if lower == "no-store" || lower == "no-cache" {
            return Some(0);
        }
        if let Some(v) = lower.strip_prefix("max-age=") {
            out = v.trim_matches('"').parse::<u64>().ok();
        }
    }
    out
}

/// Decodes a `chunked` body (RFC 9112 §7.1), trailers ignored.
fn dechunk(mut raw: &[u8], max_body: usize) -> Result<Vec<u8>, OutboundError> {
    let mut out = Vec::new();
    loop {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(OutboundError::Malformed)?;
        let line = core::str::from_utf8(raw.get(..line_end).ok_or(OutboundError::Malformed)?)
            .map_err(|_| OutboundError::Malformed)?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| OutboundError::Malformed)?;
        let start = line_end.checked_add(2).ok_or(OutboundError::Malformed)?;
        if size == 0 {
            return Ok(out);
        }
        let end = start.checked_add(size).ok_or(OutboundError::Malformed)?;
        out.extend_from_slice(raw.get(start..end).ok_or(OutboundError::Malformed)?);
        if out.len() > max_body {
            return Err(OutboundError::Malformed);
        }
        if raw.get(end..end.checked_add(2).ok_or(OutboundError::Malformed)?) != Some(b"\r\n") {
            return Err(OutboundError::Malformed);
        }
        raw = raw
            .get(end.checked_add(2).ok_or(OutboundError::Malformed)?..)
            .ok_or(OutboundError::Malformed)?;
    }
}

/// Reads one answer from `stream`; the body only when `max_body` is not zero.
///
/// # Errors
/// [`OutboundError`].
pub async fn read_answer<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_body: usize,
) -> Result<Answer, OutboundError> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 4096];
    let limit = MAX_HEAD
        .checked_add(max_body.checked_mul(2).ok_or(OutboundError::Malformed)?)
        .and_then(|n| n.checked_add(4096))
        .ok_or(OutboundError::Malformed)?;
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| OutboundError::Unreachable)?;
        let complete = {
            buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&buf) {
                Ok(httparse::Status::Complete(head)) => Some((
                    head,
                    resp.code.ok_or(OutboundError::Malformed)?,
                    header(resp.headers, "content-length")
                        .map(|v| v.parse::<usize>().map_err(|_| OutboundError::Malformed))
                        .transpose()?,
                    header(resp.headers, "transfer-encoding")
                        .is_some_and(|v| v.eq_ignore_ascii_case("chunked")),
                    header(resp.headers, "cache-control").and_then(max_age),
                    header(resp.headers, "retry-after").and_then(|v| v.parse::<u64>().ok()),
                )),
                Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD && n > 0 => None,
                Ok(httparse::Status::Partial) if n == 0 => return Err(OutboundError::Unreachable),
                _ => return Err(OutboundError::Malformed),
            }
        };
        let Some((head, status, length, chunked, max_age_s, retry_after_s)) = complete else {
            continue;
        };
        let mut answer = Answer {
            status,
            max_age_s,
            retry_after_s,
            body: Vec::new(),
        };
        if max_body == 0 {
            return Ok(answer);
        }
        if length.is_some_and(|l| l > max_body) {
            return Err(OutboundError::Malformed);
        }
        let mut raw = buf.split_off(head);
        let complete = |raw: &[u8]| length.is_some_and(|l| raw.len() >= l) && !chunked;
        while !complete(&raw) {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|_| OutboundError::Unreachable)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            if raw.len() > limit {
                return Err(OutboundError::Malformed);
            }
        }
        answer.body = if chunked {
            dechunk(&raw, max_body)?
        } else {
            if let Some(l) = length {
                if raw.len() < l {
                    return Err(OutboundError::Unreachable);
                }
                raw.truncate(l);
            }
            raw
        };
        if answer.body.len() > max_body {
            return Err(OutboundError::Malformed);
        }
        return Ok(answer);
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
    max_body: usize,
) -> Result<Answer, OutboundError> {
    stream
        .write_all(request)
        .await
        .map_err(|_| OutboundError::Unreachable)?;
    stream
        .flush()
        .await
        .map_err(|_| OutboundError::Unreachable)?;
    read_answer(stream, max_body).await
}

fn header_ok(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        && value.bytes().all(|c| c == b' ' || c.is_ascii_graphic())
}

/// The `traceparent` header line of the current trace, or nothing outside one (OP-67 m.1).
fn traceparent() -> String {
    access_telemetry::trace::current_header()
        .map(|t| format!("traceparent: {t}\r\n"))
        .unwrap_or_default()
}

/// The bytes of `POST target` with `body`: the request [`Outbound::post`] sends, also for a
/// test receiver.
///
/// # Errors
/// [`OutboundError::Url`] for a header that cannot be carried.
pub fn post_request(
    target: &Target,
    content_type: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if !header_ok("content-type", content_type) || !headers.iter().all(|(n, v)| header_ok(n, v)) {
        return Err(OutboundError::Url);
    }
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         User-Agent: access\r\nCache-Control: no-store\r\nConnection: close\r\n{}",
        target.path,
        target.host_header(),
        body.len(),
        traceparent(),
    );
    for (n, v) in headers {
        head.push_str(n);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    Ok(out)
}

/// Sends `request` over `stream` and reads the answer's head: the exchange of
/// [`Outbound::post`], also for a test receiver.
///
/// # Errors
/// [`OutboundError`].
pub async fn post_over<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
) -> Result<Answer, OutboundError> {
    exchange(stream, request, 0).await
}

/// HTTPS to client-registered URLs behind the SSRF guard. Only port 443 is reached, and the
/// ports of declared targets: the server's runtime lockdown opens no other outbound port for it
/// (OP-92, OP-149 m.23).
#[derive(Clone)]
pub struct Outbound {
    connector: Option<TlsConnector>,
    timeout: Duration,
    declared: Arc<[DeclaredTarget]>,
}

/// The one port of clients' endpoints Access connects to.
pub const PORT: u16 = 443;

impl Outbound {
    /// A client over `tls` (the operator's trust anchors) with one deadline per exchange.
    #[must_use]
    pub fn new(tls: Arc<rustls::ClientConfig>, timeout: Duration) -> Self {
        Self {
            connector: Some(TlsConnector::from(tls)),
            timeout,
            declared: Arc::new([]),
        }
    }

    /// A client without trust anchors: every request is [`OutboundError::Unreachable`].
    #[must_use]
    pub fn disabled(timeout: Duration) -> Self {
        Self {
            connector: None,
            timeout,
            declared: Arc::new([]),
        }
    }

    /// This client with the operator's declared delivery targets (OP-149 m.23).
    #[must_use]
    pub fn declaring(mut self, targets: Vec<DeclaredTarget>) -> Self {
        self.declared = targets.into();
        self
    }

    /// The URLs of the declared delivery targets.
    #[must_use]
    pub fn declared(&self) -> DeclaredTargets {
        DeclaredTargets::new(self.declared.iter().map(|d| d.url.clone()))
    }

    async fn send(
        &self,
        target: &Target,
        request: Vec<u8>,
        max_body: usize,
        declared: Option<&DeclaredTarget>,
    ) -> Result<Answer, OutboundError> {
        let (connector, tcp) = if let Some(d) = declared {
            // OP-149 m.23
            let connector = d
                .connector
                .as_ref()
                .or(self.connector.as_ref())
                .ok_or(OutboundError::Unreachable)?;
            (connector, connect_declared(target).await?)
        } else {
            if target.port != PORT {
                return Err(OutboundError::Blocked);
            }
            let addr = resolve(target).await?;
            let connector = self.connector.as_ref().ok_or(OutboundError::Unreachable)?;
            let tcp = TcpStream::connect(addr)
                .await
                .map_err(|_| OutboundError::Unreachable)?;
            (connector, tcp)
        };
        let name = match target.host.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(target.host.clone()).map_err(|_| OutboundError::Url)?,
        };
        let mut tls = connector
            .connect(name, tcp)
            .await
            .map_err(|_| OutboundError::Unreachable)?;
        exchange(&mut tls, &request, max_body).await
    }

    async fn bounded(
        &self,
        target: &Target,
        request: Vec<u8>,
        max_body: usize,
        declared: Option<&DeclaredTarget>,
    ) -> Result<Answer, OutboundError> {
        tokio::time::timeout(self.timeout, self.send(target, request, max_body, declared))
            .await
            .map_err(|_| OutboundError::Unreachable)?
    }

    /// `GET url` accepting `accept`, the body read up to `max_body` bytes.
    ///
    /// # Errors
    /// [`OutboundError`].
    pub async fn get(
        &self,
        url: &str,
        accept: &str,
        max_body: usize,
    ) -> Result<Answer, OutboundError> {
        let target = Target::parse(url)?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: {accept}\r\nUser-Agent: access\r\n\
             Accept-Encoding: identity\r\nConnection: close\r\n{}\r\n",
            target.path,
            target.host_header(),
            traceparent(),
        );
        self.bounded(&target, request.into_bytes(), max_body, None)
            .await
    }

    /// `POST url` with `body` of `content_type` and extra `headers`: an event delivery
    /// (OP-149 m.4, m.7), one of the two requests a declared target is reached by (m.23), with
    /// [`Outbound::poll`]. Only the status and headers are read. A header name or value that is not a visible ASCII token,
    /// or contains a line break, is [`OutboundError::Url`].
    ///
    /// # Errors
    /// [`OutboundError`].
    pub async fn post(
        &self,
        url: &str,
        content_type: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<Answer, OutboundError> {
        let target = Target::parse(url)?;
        let request = post_request(&target, content_type, headers, body)?;
        let declared = self.declared.iter().find(|d| d.url == url);
        self.bounded(&target, request, 0, declared).await
    }

    /// `POST url` with the JSON `body` and extra `headers`, the answer body read up to
    /// `max_body` bytes: an RFC 8936 poll of an inbound SSF transmitter (OP-151 m.3 (l)). Like
    /// a delivery, it reaches a declared target by its exact URL (OP-149 m.23); every other rule
    /// above holds.
    ///
    /// # Errors
    /// [`OutboundError`].
    pub async fn poll(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: &[u8],
        max_body: usize,
    ) -> Result<Answer, OutboundError> {
        let target = Target::parse(url)?;
        let request = post_request(&target, "application/json", headers, body)?;
        let declared = self.declared.iter().find(|d| d.url == url);
        self.bounded(&target, request, max_body, declared).await
    }

    /// `POST url` with `body` of `content_type` and extra `headers`, the answer body read up to
    /// `max_body` bytes: an inline hook call (TN-135). A declared delivery target is not reached
    /// this way; every rule above holds.
    ///
    /// # Errors
    /// [`OutboundError`].
    pub async fn post_reading(
        &self,
        url: &str,
        content_type: &str,
        headers: &[(&str, String)],
        body: &[u8],
        max_body: usize,
    ) -> Result<Answer, OutboundError> {
        let target = Target::parse(url)?;
        let request = post_request(&target, content_type, headers, body)?;
        self.bounded(&target, request, max_body, None).await
    }

    /// `POST url` with a form body; only the status and headers are read.
    ///
    /// # Errors
    /// [`OutboundError`].
    pub async fn post_form(&self, url: &str, form: &str) -> Result<Answer, OutboundError> {
        let target = Target::parse(url)?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\nUser-Agent: access\r\nCache-Control: no-store\r\n\
             Connection: close\r\n{}\r\n{form}",
            target.path,
            target.host_header(),
            form.len(),
            traceparent(),
        );
        self.bounded(&target, request.into_bytes(), 0, None).await
    }
}

#[cfg(test)]
mod tests;
