//! The doorbell's NATS client (OP-156 m.3 (j)): TCP, the server's `INFO`, then TLS 1.3 with a
//! client certificate (aws-lc-rs, CR-12), `CONNECT` and a `PING`/`PONG` round. There is no
//! plaintext mode and no token or nkey: the client certificate is the credential.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::BTreeMap;
use std::time::Duration;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::proto::{self, Message, Parser, ProtoError, ServerOp};
use super::{Ack, ApiError, Bell, Ring, Topic, pub_ack};
use crate::fence::Cursor;

/// How long one connection step or one acknowledgement may take.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// How long the stream keeps rings: an hour, in nanoseconds.
pub const MAX_AGE_NS: u64 = 3_600_000_000_000;

/// The stream's deduplication window: two minutes, in nanoseconds.
pub const DUPLICATE_WINDOW_NS: u64 = 120_000_000_000;

/// `JetStream`'s code for a stream that exists with another configuration.
pub const STREAM_NAME_IN_USE: u64 = 10058;

/// Why the doorbell is down; never a reason to fail a commit or a consumer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DoorbellError {
    /// The connection failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The TLS configuration or handshake failed.
    #[error("tls: {0}")]
    Tls(String),
    /// The server broke the protocol.
    #[error("{0}")]
    Proto(#[from] ProtoError),
    /// The server said `-ERR`.
    #[error("server: {0}")]
    Server(String),
    /// The server offers no TLS, headers or `JetStream`.
    #[error("server lacks {0}")]
    Lacks(&'static str),
    /// A step took longer than [`TIMEOUT`].
    #[error("timed out")]
    Timeout,
    /// `JetStream` refused.
    #[error("{0}")]
    Api(#[from] ApiError),
    /// No stream took the publish (`503` no responders).
    #[error("no stream for the subject")]
    NoStream,
    /// The connection closed.
    #[error("closed")]
    Closed,
}

/// Where and how to connect.
#[derive(Clone)]
pub struct Config {
    /// `host:port`.
    pub addr: String,
    /// The name the server certificate must carry.
    pub server_name: ServerName<'static>,
    /// TLS 1.3 with the client certificate; see [`tls`].
    pub tls: Arc<rustls::ClientConfig>,
    /// The stream and subjects.
    pub topic: Topic,
    /// A token unique to this process; the reply subjects are `_INBOX.<inbox>.<n>`.
    pub inbox: String,
    /// The client name the server shows.
    pub name: String,
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("addr", &self.addr)
            .field("topic", &self.topic)
            .finish_non_exhaustive()
    }
}

/// The client TLS configuration: the operator's CA bundle for the server, and the client
/// certificate chain and key, all PEM; TLS 1.3 only.
///
/// # Errors
/// [`DoorbellError::Tls`].
pub fn tls(
    ca_pem: &[u8],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::ClientConfig>, DoorbellError> {
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots
        .add_parsable_certificates(CertificateDer::pem_slice_iter(ca_pem).filter_map(Result::ok));
    if added == 0 {
        return Err(DoorbellError::Tls(String::from("no CA certificate")));
    }
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| DoorbellError::Tls(e.to_string()))?;
    if chain.is_empty() {
        return Err(DoorbellError::Tls(String::from("no client certificate")));
    }
    let key =
        PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| DoorbellError::Tls(e.to_string()))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| DoorbellError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|e| DoorbellError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

async fn within<T>(f: impl Future<Output = Result<T, DoorbellError>>) -> Result<T, DoorbellError> {
    tokio::time::timeout(TIMEOUT, f)
        .await
        .map_err(|_| DoorbellError::Timeout)?
}

/// One open connection.
struct Conn {
    io: TlsStream<TcpStream>,
    parser: Parser,
}

fn info_flag(info: &serde_json::Value, key: &str) -> bool {
    info.get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

impl Conn {
    async fn open(cfg: &Config, jetstream: bool) -> Result<Self, DoorbellError> {
        let mut tcp = within(async { Ok(TcpStream::connect(&cfg.addr).await?) }).await?;
        let mut parser = Parser::new();
        let info = within(async {
            loop {
                if let Some(op) = parser.server_op()? {
                    return match op {
                        ServerOp::Info(json) => Ok(json),
                        _ => Err(DoorbellError::Proto(ProtoError("info"))),
                    };
                }
                let mut buf = [0_u8; 4096];
                let n = tcp.read(&mut buf).await?;
                if n == 0 {
                    return Err(DoorbellError::Closed);
                }
                parser.feed(buf.get(..n).unwrap_or_default())?;
            }
        })
        .await?;
        let info: serde_json::Value =
            serde_json::from_str(&info).map_err(|_| ProtoError("info json"))?;
        if parser.pending() != 0 {
            return Err(DoorbellError::Proto(ProtoError("data before tls")));
        }
        if !info_flag(&info, "tls_required") && !info_flag(&info, "tls_available") {
            return Err(DoorbellError::Lacks("tls"));
        }
        if !info_flag(&info, "headers") {
            return Err(DoorbellError::Lacks("headers"));
        }
        if jetstream && !info_flag(&info, "jetstream") {
            return Err(DoorbellError::Lacks("jetstream"));
        }
        let io = within(async {
            TlsConnector::from(cfg.tls.clone())
                .connect(cfg.server_name.clone(), tcp)
                .await
                .map_err(|e| DoorbellError::Tls(e.to_string()))
        })
        .await?;
        let mut conn = Self { io, parser };
        let options = serde_json::json!({
            "verbose": false,
            "pedantic": false,
            "tls_required": true,
            "name": cfg.name,
            "lang": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": 1,
            "headers": true,
            "no_responders": true,
        });
        conn.write(&proto::connect(&options.to_string())).await?;
        within(async {
            loop {
                match conn.read_op().await? {
                    ServerOp::Pong => return Ok(()),
                    ServerOp::Err(e) => return Err(DoorbellError::Server(e)),
                    ServerOp::Ping => conn.write(proto::pong()).await?,
                    _ => {}
                }
            }
        })
        .await?;
        Ok(conn)
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), DoorbellError> {
        within(async {
            self.io.write_all(bytes).await?;
            self.io.flush().await?;
            Ok(())
        })
        .await
    }

    async fn read_op(&mut self) -> Result<ServerOp, DoorbellError> {
        loop {
            if let Some(op) = self.parser.server_op()? {
                return Ok(op);
            }
            let mut buf = [0_u8; 4096];
            let n = self.io.read(&mut buf).await?;
            if n == 0 {
                return Err(DoorbellError::Closed);
            }
            self.parser.feed(buf.get(..n).unwrap_or_default())?;
        }
    }

    /// The next message, answering the server's `PING`s on the way.
    async fn next_msg(&mut self) -> Result<Message, DoorbellError> {
        loop {
            match self.read_op().await? {
                ServerOp::Msg(m) => return Ok(m),
                ServerOp::Ping => self.write(proto::pong()).await?,
                ServerOp::Err(e) => return Err(DoorbellError::Server(e)),
                ServerOp::Info(_) | ServerOp::Pong | ServerOp::Ok => {}
            }
        }
    }
}

/// Publishes rings and waits for each `JetStream` acknowledgement.
pub struct Publisher {
    conn: Conn,
    topic: Topic,
    inbox: String,
    next: u64,
}

impl Publisher {
    /// Connects, subscribes to its reply subjects and makes sure the stream exists.
    ///
    /// # Errors
    /// [`DoorbellError`].
    pub async fn connect(cfg: &Config) -> Result<Self, DoorbellError> {
        let mut conn = Conn::open(cfg, true).await?;
        let inbox = alloc::format!("_INBOX.{}", cfg.inbox);
        conn.write(&proto::sub(&alloc::format!("{inbox}.*"), "1")?)
            .await?;
        let mut p = Self {
            conn,
            topic: cfg.topic,
            inbox,
            next: 0,
        };
        p.ensure_stream().await?;
        Ok(p)
    }

    async fn request(
        &mut self,
        subject: &str,
        headers: &[(&str, &str)],
        payload: &[u8],
    ) -> Result<Message, DoorbellError> {
        self.next = self.next.wrapping_add(1);
        let reply = alloc::format!("{}.{}", self.inbox, self.next);
        self.conn
            .write(&proto::publish(subject, Some(&reply), headers, payload)?)
            .await?;
        let conn = &mut self.conn;
        within(async {
            loop {
                let m = conn.next_msg().await?;
                if m.subject == reply {
                    return Ok(m);
                }
            }
        })
        .await
    }

    /// Creates the stream over the topic's subjects; an existing stream, however its operator
    /// configured it, is left as it is.
    async fn ensure_stream(&mut self) -> Result<(), DoorbellError> {
        let t = self.topic;
        let config = serde_json::json!({
            "name": t.stream,
            "subjects": [t.all()],
            "retention": "limits",
            "storage": "file",
            "discard": "old",
            "max_age": MAX_AGE_NS,
            "duplicate_window": DUPLICATE_WINDOW_NS,
            "num_replicas": 1,
        });
        let subject = alloc::format!("$JS.API.STREAM.CREATE.{}", t.stream);
        let m = self
            .request(&subject, &[], config.to_string().as_bytes())
            .await?;
        if m.status() == Some(503) {
            return Err(DoorbellError::Lacks("jetstream"));
        }
        match super::api_answer(&m.payload) {
            Ok(_) => Ok(()),
            Err(e) if e.code == STREAM_NAME_IN_USE => Ok(()),
            Err(e) => Err(DoorbellError::Api(e)),
        }
    }

    /// Publishes `ring` with its `Nats-Msg-Id` and waits for the stream to store it.
    ///
    /// # Errors
    /// [`DoorbellError`]; the caller reconnects.
    pub async fn ring(&mut self, ring: &Ring) -> Result<Ack, DoorbellError> {
        let subject = self.topic.subject(&ring.domain);
        let id = ring.msg_id();
        let m = self
            .request(&subject, &[("Nats-Msg-Id", &id)], &ring.payload())
            .await?;
        if m.status() == Some(503) {
            return Err(DoorbellError::NoStream);
        }
        Ok(pub_ack(&m.payload)?)
    }
}

/// Receives rings on every partition.
pub struct Listener {
    conn: Conn,
}

impl Listener {
    /// Connects and subscribes to the topic.
    ///
    /// # Errors
    /// [`DoorbellError`].
    pub async fn connect(cfg: &Config) -> Result<Self, DoorbellError> {
        let mut conn = Conn::open(cfg, false).await?;
        conn.write(&proto::sub(&cfg.topic.all(), "1")?).await?;
        conn.write(proto::ping()).await?;
        Ok(Self { conn })
    }

    /// The next ring; a message that is not one is passed.
    ///
    /// # Errors
    /// [`DoorbellError`] when the connection ends.
    pub async fn next(&mut self) -> Result<([u8; 32], Cursor), DoorbellError> {
        loop {
            let m = self.conn.next_msg().await?;
            if let Ok(r) = Ring::read(&m.payload) {
                return Ok(r);
            }
        }
    }
}

/// A bounded queue of rings, the [`Bell`] a writer holds. A full queue drops the ring: the
/// consumers' polling covers it.
#[derive(Clone, Debug)]
pub struct Queue(mpsc::Sender<Ring>);

impl Bell for Queue {
    fn ring(&self, ring: Ring) {
        let _ = self.0.try_send(ring);
    }
}

/// A queue of `capacity` rings and its receiving end, for [`publish`].
#[must_use]
pub fn queue(capacity: usize) -> (Queue, mpsc::Receiver<Ring>) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    (Queue(tx), rx)
}

/// What [`publish`] reports, for the caller's telemetry.
#[derive(Debug)]
#[non_exhaustive]
pub enum Report {
    /// The stream stored a ring.
    Rang(Ack),
    /// The doorbell is down; the rings in hand were dropped.
    Down(DoorbellError),
}

/// How long [`publish`] waits before connecting again.
pub const RECONNECT: Duration = Duration::from_secs(2);

/// Waits [`RECONNECT`] or until `stop` changes; `false` once its sender is gone.
async fn pause(stop: &mut watch::Receiver<bool>) -> bool {
    !matches!(
        tokio::time::timeout(RECONNECT, stop.changed()).await,
        Ok(Err(_))
    )
}

/// Publishes what `rx` receives until `stop` is set or every sender is gone. Rings that queued
/// up are coalesced to the latest per domain. While the server is down rings are dropped and
/// the connection is tried again every [`RECONNECT`].
pub async fn publish(
    cfg: Config,
    mut rx: mpsc::Receiver<Ring>,
    mut stop: watch::Receiver<bool>,
    mut report: impl FnMut(Report) + Send,
) {
    let mut conn: Option<Publisher> = None;
    while !*stop.borrow() {
        let first = tokio::select! {
            r = rx.recv() => r,
            c = stop.changed() => {
                if c.is_err() {
                    return;
                }
                continue;
            }
        };
        let Some(first) = first else {
            return;
        };
        let mut latest: BTreeMap<[u8; 32], Ring> = BTreeMap::new();
        latest.insert(first.domain, first);
        while let Ok(r) = rx.try_recv() {
            let keep = latest.get(&r.domain).is_none_or(|l| l.at < r.at);
            if keep {
                latest.insert(r.domain, r);
            }
        }
        if conn.is_none() {
            match Publisher::connect(&cfg).await {
                Ok(p) => conn = Some(p),
                Err(e) => {
                    report(Report::Down(e));
                    if !pause(&mut stop).await {
                        return;
                    }
                    continue;
                }
            }
        }
        for ring in latest.values() {
            let Some(p) = conn.as_mut() else {
                break;
            };
            match p.ring(ring).await {
                Ok(ack) => report(Report::Rang(ack)),
                Err(e) => {
                    report(Report::Down(e));
                    conn = None;
                }
            }
        }
    }
}

/// Calls `wake` for every ring until `stop` is set; while the server is down it connects again
/// every [`RECONNECT`] and reports why through `down`. Consumers keep polling meanwhile.
pub async fn listen(
    cfg: Config,
    mut stop: watch::Receiver<bool>,
    mut wake: impl FnMut([u8; 32], Cursor) + Send,
    mut down: impl FnMut(DoorbellError) + Send,
) {
    while !*stop.borrow() {
        let mut l = match Listener::connect(&cfg).await {
            Ok(l) => l,
            Err(e) => {
                down(e);
                if !pause(&mut stop).await {
                    return;
                }
                continue;
            }
        };
        loop {
            let next = tokio::select! {
                n = l.next() => n,
                c = stop.changed() => {
                    if c.is_err() {
                        return;
                    }
                    break;
                }
            };
            match next {
                Ok((domain, at)) => wake(domain, at),
                Err(e) => {
                    down(e);
                    if !pause(&mut stop).await {
                        return;
                    }
                    break;
                }
            }
        }
    }
}
