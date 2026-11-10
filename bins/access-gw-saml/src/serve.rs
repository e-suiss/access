//! The forward listener: one bounded HTTP/1.1 `POST` per connection from access-server, answered
//! with deterministic CBOR (OP-155 m.3 (c)). The edge core names the gateway's realm and carries
//! its calls; the parser client reaches the worker supervisor.

use std::sync::Arc;
use std::time::Duration;

use access_edge_core::EdgeCore;
use access_edge_core::channel::{Channel, ChannelError};
use access_edge_core::ipc::{Op, Reply};
use access_edge_core::parser::ParserClient;
use access_identity_saml::wire::{self, Done, Forward};
use access_internal_api::edge::Call;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::forward::{self, Ports};

/// Largest request head.
const MAX_HEAD: usize = 8 * 1024;

/// Largest request body.
const MAX_BODY: usize = 128 * 1024;

/// Longest one forward may take end to end.
const DEADLINE: Duration = Duration::from_secs(14);

struct Live {
    core: EdgeCore,
    parser: ParserClient,
    realm: String,
}

impl Ports for Live {
    async fn parse(&self, op: Op, input: Vec<u8>) -> Result<Reply, String> {
        self.parser
            .parse(op, input)
            .await
            .map_err(|e| e.to_string())
    }

    async fn attest(&self, body: Vec<u8>) -> Result<Vec<u8>, String> {
        match self.core.raw(Call::SessionAttest, &body).await {
            Ok(b) => Ok(b),
            Err(access_edge_core::EdgeError::Channel(ChannelError::Refused { code, .. })) => {
                Err(code)
            }
            Err(_) => Err(String::from("edge-unavailable")),
        }
    }

    fn realm(&self) -> &str {
        &self.realm
    }
}

fn reply(status: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        wire::CONTENT_TYPE,
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// Reads one request: its path and its body.
async fn request(s: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(chunk.get(..n)?);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut r = httparse::Request::new(&mut headers);
        match r.parse(&buf).ok()? {
            httparse::Status::Partial if buf.len() <= MAX_HEAD => {}
            httparse::Status::Partial => return None,
            httparse::Status::Complete(at) => {
                if r.method != Some("POST") {
                    return None;
                }
                let path = String::from(r.path?);
                let len = r
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| core::str::from_utf8(h.value).ok())
                    .and_then(|v| v.trim().parse::<usize>().ok())?;
                if len > MAX_BODY {
                    return None;
                }
                let mut body = buf.get(at..)?.to_vec();
                while body.len() < len {
                    let n = s.read(&mut chunk).await.ok()?;
                    if n == 0 {
                        return None;
                    }
                    body.extend_from_slice(chunk.get(..n)?);
                }
                body.truncate(len);
                return Some((path, body));
            }
        }
    }
}

async fn one(live: Arc<Live>, mut s: TcpStream) {
    let work = async {
        let Some((path, body)) = request(&mut s).await else {
            return reply("400 Bad Request", &[]);
        };
        if path != wire::FORWARD_PATH {
            return reply("404 Not Found", &[]);
        }
        let done = match Forward::decode(&body) {
            Ok(f) => forward::handle(&*live, &f).await,
            Err(_) => Done::Refused(String::from("saml-forward-malformed")),
        };
        reply("200 OK", &done.encode())
    };
    if let Ok(out) = tokio::time::timeout(DEADLINE, work).await {
        let _ = s.write_all(&out).await;
        let _ = s.flush().await;
    }
}

/// Connects to access-server (`hello`), then answers forwards until the listener fails.
///
/// # Errors
/// The listener or the first edge call failed.
pub(crate) async fn run(
    listener: std::net::TcpListener,
    channel: Channel,
    parser: ParserClient,
    locked: suiss_sandbox::Locked,
) -> Result<(), String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::from_std(listener).map_err(|e| e.to_string())?;
    let core = EdgeCore::connect(channel)
        .await
        .map_err(|e| format!("hello refused: {e}"))?;
    let realm = String::from(core.realm(None).map_err(|e| e.to_string())?);
    // SA-22
    locked
        .narrow()
        .map_err(|e| format!("lockdown narrowing failed: {e}"))?;
    let live = Arc::new(Live {
        core,
        parser,
        realm,
    });
    loop {
        let (s, _) = listener.accept().await.map_err(|e| e.to_string())?;
        tokio::spawn(one(Arc::clone(&live), s));
    }
}
