//! An in-process twin of `nats-server` 2.15 for tests (OP-156 m.1 (c)): plaintext `INFO`, then
//! TLS with the test's server configuration, core publish/subscribe with `*`/`>` filters, and
//! `JetStream` streams that store a publish once per `Nats-Msg-Id` and acknowledge it. The real
//! server runs in CI (`ci.yml` job `nats`).

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Mutex;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;

use super::proto::{self, ClientOp, Message, Parser};

/// One stored message of a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    /// Its subject.
    pub subject: String,
    /// Its `Nats-Msg-Id`, if it had one.
    pub msg_id: Option<String>,
    /// Its payload.
    pub payload: Vec<u8>,
    /// Its sequence.
    pub seq: u64,
}

#[derive(Default)]
struct Stream {
    subjects: Vec<String>,
    stored: Vec<Stored>,
    seen: BTreeSet<String>,
}

type Subs = BTreeMap<(u64, String), (String, mpsc::UnboundedSender<Vec<u8>>)>;

#[derive(Default)]
struct State {
    streams: BTreeMap<String, Stream>,
    subs: Subs,
    next_conn: u64,
}

/// A running twin. Dropping it, or [`Twin::stop`], closes the listener and every connection.
pub struct Twin {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: watch::Sender<bool>,
}

impl Twin {
    /// Listens on a free loopback port with `tls` as the server configuration.
    ///
    /// # Errors
    /// The bind error.
    pub async fn start(tls: Arc<rustls::ServerConfig>) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State::default()));
        let (stop, stopped) = watch::channel(false);
        let acceptor = TlsAcceptor::from(tls);
        let shared = state.clone();
        tokio::spawn(async move {
            let mut until = stopped.clone();
            loop {
                let accepted = tokio::select! {
                    a = listener.accept() => a,
                    _ = until.changed() => return,
                };
                let Ok((tcp, _)) = accepted else {
                    continue;
                };
                tokio::spawn(serve(
                    tcp,
                    acceptor.clone(),
                    shared.clone(),
                    stopped.clone(),
                ));
            }
        });
        Ok(Self { addr, state, stop })
    }

    /// `host:port`.
    #[must_use]
    pub fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// What stream `name` stored, in order.
    #[must_use]
    pub fn stored(&self, name: &str) -> Vec<Stored> {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.streams.get(name).map(|st| st.stored.clone()))
            .unwrap_or_default()
    }

    /// Closes the listener and every connection.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

impl Drop for Twin {
    fn drop(&mut self) {
        self.stop();
    }
}

const INFO: &str = r#"INFO {"server_id":"twin","server_name":"twin","version":"2.15.0","proto":1,"headers":true,"jetstream":true,"tls_required":true,"max_payload":1048576}"#;

async fn serve(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    state: Arc<Mutex<State>>,
    mut stopped: watch::Receiver<bool>,
) {
    let mut tcp = tcp;
    if tcp
        .write_all(alloc::format!("{INFO}\r\n").as_bytes())
        .await
        .is_err()
    {
        return;
    }
    let Ok(io) = acceptor.accept(tcp).await else {
        return;
    };
    let (mut rd, mut wr) = tokio::io::split(io);
    let (out, mut outq) = mpsc::unbounded_channel::<Vec<u8>>();
    let conn = {
        let Ok(mut s) = state.lock() else {
            return;
        };
        s.next_conn = s.next_conn.saturating_add(1);
        s.next_conn
    };
    let writer = tokio::spawn(async move {
        while let Some(b) = outq.recv().await {
            if wr.write_all(&b).await.is_err() {
                return;
            }
        }
    });
    let mut parser = Parser::new();
    let mut buf = [0_u8; 4096];
    'conn: loop {
        let n = tokio::select! {
            n = rd.read(&mut buf) => n,
            _ = stopped.changed() => break,
        };
        let Ok(n) = n else {
            break;
        };
        if n == 0 || parser.feed(buf.get(..n).unwrap_or_default()).is_err() {
            break;
        }
        loop {
            let op = match parser.client_op() {
                Ok(Some(op)) => op,
                Ok(None) => break,
                Err(e) => {
                    let _ = out.send(alloc::format!("-ERR '{e}'\r\n").into_bytes());
                    break 'conn;
                }
            };
            handle(&state, conn, &out, op);
        }
    }
    if let Ok(mut s) = state.lock() {
        s.subs.retain(|(c, _), _| *c != conn);
    }
    writer.abort();
}

fn handle(state: &Mutex<State>, conn: u64, out: &mpsc::UnboundedSender<Vec<u8>>, op: ClientOp) {
    match op {
        ClientOp::Connect(_) | ClientOp::Pong => {}
        ClientOp::Ping => {
            let _ = out.send(proto::pong().to_vec());
        }
        ClientOp::Sub { subject, sid } => {
            if let Ok(mut s) = state.lock() {
                s.subs.insert((conn, sid), (subject, out.clone()));
            }
        }
        ClientOp::Unsub(sid) => {
            if let Ok(mut s) = state.lock() {
                s.subs.remove(&(conn, sid));
            }
        }
        ClientOp::Pub(m) => publish(state, &m),
    }
}

fn reply(state: &State, to: &str, payload: &[u8]) {
    route(
        state,
        &Message {
            subject: to.to_string(),
            sid: String::new(),
            reply: None,
            headers: None,
            payload: payload.to_vec(),
        },
    );
}

fn route(state: &State, m: &Message) {
    for ((_, sid), (filter, tx)) in &state.subs {
        if proto::matches(filter, &m.subject) {
            let mut d = m.clone();
            d.sid.clone_from(sid);
            let _ = tx.send(proto::deliver(&d));
        }
    }
}

fn publish(state: &Mutex<State>, m: &Message) {
    let Ok(mut s) = state.lock() else {
        return;
    };
    if let Some(name) = m.subject.strip_prefix("$JS.API.STREAM.CREATE.") {
        let answer = create(&mut s, name, &m.payload);
        if let Some(r) = &m.reply {
            reply(&s, r, answer.as_bytes());
        }
        return;
    }
    let msg_id = m
        .headers
        .as_deref()
        .and_then(|h| proto::header(h, "Nats-Msg-Id"));
    let mut ack = None;
    for (name, st) in &mut s.streams {
        if !st.subjects.iter().any(|f| proto::matches(f, &m.subject)) {
            continue;
        }
        let duplicate = msg_id.as_ref().is_some_and(|id| st.seen.contains(id));
        if !duplicate {
            let seq = u64::try_from(st.stored.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            st.stored.push(Stored {
                subject: m.subject.clone(),
                msg_id: msg_id.clone(),
                payload: m.payload.clone(),
                seq,
            });
            if let Some(id) = &msg_id {
                st.seen.insert(id.clone());
            }
        }
        let seq = st
            .stored
            .iter()
            .rev()
            .find(|x| !duplicate || x.msg_id == msg_id)
            .map_or(0, |x| x.seq);
        ack = Some(
            serde_json::json!({"stream": name, "seq": seq, "duplicate": duplicate}).to_string(),
        );
        break;
    }
    route(&s, m);
    if let (Some(r), Some(a)) = (&m.reply, ack) {
        reply(&s, r, a.as_bytes());
    }
}

fn create(s: &mut State, name: &str, config: &[u8]) -> String {
    let subjects: Vec<String> = serde_json::from_slice::<serde_json::Value>(config)
        .ok()
        .and_then(|v| {
            v.get("subjects")?.as_array().map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(ToString::to_string))
                    .collect()
            })
        })
        .unwrap_or_default();
    if let Some(existing) = s.streams.get(name) {
        if existing.subjects != subjects {
            return serde_json::json!({"error": {"code": 400, "err_code": super::client::STREAM_NAME_IN_USE, "description": "stream name already in use with a different configuration"}}).to_string();
        }
    } else {
        s.streams.insert(
            String::from(name),
            Stream {
                subjects: subjects.clone(),
                ..Stream::default()
            },
        );
    }
    serde_json::json!({"type": "io.nats.jetstream.api.v1.stream_create_response", "config": {"name": name, "subjects": subjects}}).to_string()
}

/// A throwaway PKI for one test: a CA, a server certificate for `localhost` and a client
/// certificate, made at run time.
pub struct Pki {
    /// The twin's TLS configuration: TLS 1.3, client certificate required.
    pub server: Arc<rustls::ServerConfig>,
    /// The CA certificate, PEM.
    pub ca_pem: String,
    /// The client certificate, PEM.
    pub cert_pem: String,
    /// The client key, PEM.
    pub key_pem: String,
    /// The server certificate, PEM, for a real `nats-server`.
    pub server_cert_pem: String,
    /// The server key, PEM.
    pub server_key_pem: String,
}

/// Why a [`Pki`] could not be made.
#[derive(Debug, thiserror::Error)]
#[error("test pki: {0}")]
pub struct PkiError(String);

fn pki_err(e: impl core::fmt::Display) -> PkiError {
    PkiError(e.to_string())
}

impl Pki {
    /// A fresh CA with one server and one client certificate.
    ///
    /// # Errors
    /// [`PkiError`].
    pub fn new() -> Result<Self, PkiError> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
        let ca_key = KeyPair::generate().map_err(pki_err)?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(pki_err)?;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "doorbell test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).map_err(pki_err)?;
        let issuer = Issuer::new(ca_params, ca_key);
        let server_key = KeyPair::generate().map_err(pki_err)?;
        let server = CertificateParams::new(alloc::vec![String::from("localhost")])
            .map_err(pki_err)?
            .signed_by(&server_key, &issuer)
            .map_err(pki_err)?;
        let client_key = KeyPair::generate().map_err(pki_err)?;
        let mut client_params = CertificateParams::new(Vec::<String>::new()).map_err(pki_err)?;
        client_params
            .distinguished_name
            .push(DnType::CommonName, "doorbell test client");
        let client = client_params
            .signed_by(&client_key, &issuer)
            .map_err(pki_err)?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).map_err(pki_err)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .map_err(pki_err)?;
        let key = rustls_pki_types::PrivateKeyDer::try_from(server_key.serialize_der())
            .map_err(pki_err)?;
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(pki_err)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(alloc::vec![server.der().clone()], key)
            .map_err(pki_err)?;
        Ok(Self {
            server: Arc::new(config),
            ca_pem: ca.pem(),
            cert_pem: client.pem(),
            key_pem: client_key.serialize_pem(),
            server_cert_pem: server.pem(),
            server_key_pem: server_key.serialize_pem(),
        })
    }

    /// A client [`super::client::Config`] for `addr` with this PKI's client certificate.
    ///
    /// # Errors
    /// [`PkiError`].
    pub fn client(&self, addr: &str, inbox: &str) -> Result<super::client::Config, PkiError> {
        Ok(super::client::Config {
            addr: String::from(addr),
            server_name: rustls_pki_types::ServerName::try_from("localhost")
                .map_err(pki_err)?
                .to_owned(),
            tls: super::client::tls(
                self.ca_pem.as_bytes(),
                self.cert_pem.as_bytes(),
                self.key_pem.as_bytes(),
            )
            .map_err(pki_err)?,
            topic: super::Topic::ACCESS,
            inbox: String::from(inbox),
            name: String::from("doorbell-test"),
        })
    }
}
