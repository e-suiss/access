//! The export sinks' twins (OP-156 m.1 (c)): a real HTTPS listener that plays S3 (it checks each
//! `PUT`'s Signature Version 4 from the request as it arrived and keeps the object), an HTTP
//! event collector of each preset, and a Sentinel token endpoint; and a real TLS syslog receiver
//! (RFC 5425). Both can be taken down, and the S3 twin's copies can be altered, to show that the
//! record, not the copy, answers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    reason = "test kit; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// One request the HTTPS twin took.
#[derive(Clone, Debug)]
pub struct Seen {
    /// The method.
    pub method: String,
    /// The request target.
    pub path: String,
    /// Every header, lower-cased names.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
    /// The status the twin answered.
    pub status: u16,
}

impl Seen {
    /// The header `name`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct State {
    seen: Vec<Seen>,
    objects: BTreeMap<String, Vec<u8>>,
    s3: Option<(String, Vec<u8>)>,
}

fn tls_pair() -> (tokio_rustls::TlsAcceptor, Arc<rustls::ClientConfig>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let der: CertificateDer<'static> = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        tokio_rustls::TlsAcceptor::from(Arc::new(server)),
        Arc::new(client),
    )
}

struct Raw {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Option<Raw> {
    let mut buf = Vec::new();
    let mut chunk = vec![0_u8; 16384];
    loop {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(at) = req.parse(&buf).ok()? {
            let headers: Vec<(String, String)> = req
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_ascii_lowercase(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect();
            let len: usize = headers
                .iter()
                .find(|(n, _)| n == "content-length")
                .and_then(|(_, v)| v.trim().parse().ok())
                .unwrap_or(0);
            let method = req.method?.to_owned();
            let path = req.path?.to_owned();
            while buf.len() < at + len {
                let n = s.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            return Some(Raw {
                method,
                path,
                headers,
                body: buf[at..at + len].to_vec(),
            });
        }
        if buf.len() > 64 << 20 {
            return None;
        }
    }
}

fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Checks an S3 `PUT`'s Signature Version 4 as it arrived: the canonical request is rebuilt
/// from the request line and the headers it names.
fn sigv4_ok(r: &Raw, access_key_id: &str, secret: &[u8]) -> bool {
    let h = |n: &str| {
        r.headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.trim().to_owned())
    };
    let Some(auth) = h("authorization") else {
        return false;
    };
    let Some(rest) = auth.strip_prefix("AWS4-HMAC-SHA256 ") else {
        return false;
    };
    let parts: BTreeMap<&str, &str> = rest.split(", ").filter_map(|p| p.split_once('=')).collect();
    let (Some(cred), Some(signed), Some(sig)) = (
        parts.get("Credential"),
        parts.get("SignedHeaders"),
        parts.get("Signature"),
    ) else {
        return false;
    };
    let mut c = cred.split('/');
    let (Some(akid), Some(date), Some(region), Some(service), Some("aws4_request")) =
        (c.next(), c.next(), c.next(), c.next(), c.next())
    else {
        return false;
    };
    if akid != access_key_id || service != "s3" {
        return false;
    }
    let payload = hex(&suiss_crypto::digest::sha256(&r.body));
    if h("x-amz-content-sha256").as_deref() != Some(payload.as_str()) {
        return false;
    }
    let (path, query) = r.path.split_once('?').unwrap_or((&r.path, ""));
    let mut canonical = format!("{}\n{path}\n{query}\n", r.method);
    for name in signed.split(';') {
        let Some(v) = h(name) else {
            return false;
        };
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(&v);
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(signed);
    canonical.push('\n');
    canonical.push_str(&payload);
    let Some(stamp) = h("x-amz-date") else {
        return false;
    };
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{date}/{region}/s3/aws4_request\n{}",
        hex(&suiss_crypto::digest::sha256(canonical.as_bytes()))
    );
    hex(&access_crypto::sigv4::signature(
        secret,
        (date, region, service),
        &to_sign,
    )) == *sig
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        403 => "Forbidden",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// A running HTTPS sink twin at `https://localhost:<port>`.
#[derive(Clone)]
pub struct SinkTwin {
    /// `https://localhost:<port>`.
    pub base: String,
    /// A client configuration that trusts the twin.
    pub tls: Arc<rustls::ClientConfig>,
    down: Arc<AtomicBool>,
    state: Arc<Mutex<State>>,
}

impl SinkTwin {
    /// Starts a twin on a local port.
    pub async fn start() -> Self {
        let (acceptor, tls) = tls_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let twin = Self {
            base: format!("https://localhost:{port}"),
            tls,
            down: Arc::default(),
            state: Arc::default(),
        };
        let serving = twin.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let twin = serving.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Some(req) = read_request(&mut s).await else {
                        return;
                    };
                    let (status, body) = twin.answer(req);
                    let mut out = format!(
                        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        reason(status),
                        body.len()
                    )
                    .into_bytes();
                    out.extend_from_slice(&body);
                    let _ = s.write_all(&out).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        twin
    }

    /// Makes the twin S3 for `access_key_id` and `secret`: a `PUT` whose signature does not
    /// verify is `403`.
    pub fn s3(&self, access_key_id: &str, secret: &[u8]) {
        self.state.lock().unwrap().s3 = Some((access_key_id.to_owned(), secret.to_vec()));
    }

    /// Takes the twin down (`503` for everything) or brings it back.
    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    /// Every request taken so far.
    #[must_use]
    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    /// The stored objects by path.
    #[must_use]
    pub fn objects(&self) -> BTreeMap<String, Vec<u8>> {
        self.state.lock().unwrap().objects.clone()
    }

    /// Replaces the stored object at `path`: the copy changes, the record does not.
    pub fn tamper(&self, path: &str, bytes: Vec<u8>) {
        self.state
            .lock()
            .unwrap()
            .objects
            .insert(path.to_owned(), bytes);
    }

    fn answer(&self, r: Raw) -> (u16, Vec<u8>) {
        let mut st = self.state.lock().unwrap();
        let (status, body) = if self.down.load(Ordering::SeqCst) {
            (503, b"{}".to_vec())
        } else if r.method == "PUT" {
            let ok = st
                .s3
                .as_ref()
                .is_some_and(|(akid, secret)| sigv4_ok(&r, akid, secret));
            if ok {
                st.objects.insert(r.path.clone(), r.body.clone());
                (200, Vec::new())
            } else {
                (403, b"{\"error\":\"SignatureDoesNotMatch\"}".to_vec())
            }
        } else if r.path.ends_with("/token") {
            let t = hex(&access_crypto::random::bytes::<16>().unwrap());
            (
                200,
                format!(
                    "{{\"access_token\":\"{t}\",\"token_type\":\"Bearer\",\"expires_in\":3600}}"
                )
                .into_bytes(),
            )
        } else if r.path.ends_with("/_bulk") {
            (200, b"{\"errors\":false,\"items\":[]}".to_vec())
        } else if r.path.contains("/dataCollectionRules/") {
            (204, Vec::new())
        } else if r.path.ends_with("/api/v2/logs") {
            (202, b"{}".to_vec())
        } else {
            (200, b"{\"text\":\"Success\",\"code\":0}".to_vec())
        };
        st.seen.push(Seen {
            method: r.method,
            path: r.path,
            headers: r.headers,
            body: r.body,
            status,
        });
        (status, body)
    }
}

/// A running TLS syslog receiver at `localhost:<port>` (RFC 5425).
#[derive(Clone)]
pub struct SyslogTwin {
    /// The port.
    pub port: u16,
    /// A client configuration that trusts the twin.
    pub tls: Arc<rustls::ClientConfig>,
    down: Arc<AtomicBool>,
    streams: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl SyslogTwin {
    /// Starts a receiver on a local port.
    pub async fn start() -> Self {
        let (acceptor, tls) = tls_pair();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let twin = Self {
            port,
            tls,
            down: Arc::default(),
            streams: Arc::default(),
        };
        let serving = twin.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                if serving.down.load(Ordering::SeqCst) {
                    drop(tcp);
                    continue;
                }
                let acceptor = acceptor.clone();
                let twin = serving.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut all = Vec::new();
                    if s.read_to_end(&mut all).await.is_ok() {
                        twin.streams.lock().unwrap().push(all);
                    }
                });
            }
        });
        twin
    }

    /// Takes the receiver down (connections are dropped) or brings it back.
    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    /// Every message received, in order.
    #[must_use]
    pub fn messages(&self) -> Vec<String> {
        self.streams
            .lock()
            .unwrap()
            .iter()
            .flat_map(|s| crate::domain::syslog::unframe(s).unwrap_or_default())
            .collect()
    }
}
