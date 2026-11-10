//! Access's public routes over HTTPS with the host's client certificate (OP-62, B22): the NSS
//! snapshot, the device authorization of the host's client and the person's sign-in and step-up
//! with the DPoP-bound token the daemon polled for. One request per connection, every wait
//! bounded; anything outside the contract is [`Reached::Unreachable`].

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::verify::cose::PublicKey;
use access_sdk::auth::dpop::{ProofFor, ProofKey, proof};
use access_sdk::auth::{Random as SdkRandom, RandomUnavailable};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{Value, json};
use suiss_crypto::signer::{Signer as _, SoftSigner};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::domain::fido::Credential;
use crate::ports::{Access, DevicePoll, DeviceStart, Reached, SignIn};

/// Largest answer read.
pub const MAX_ANSWER: usize = 4 * 1024 * 1024;

/// How long one request may take.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// The device grant (RFC 8628 §3.4).
pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

struct Target {
    host: String,
    port: u16,
    path: String,
}

fn target(url: &str) -> Option<Target> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| {
        (rest.get(..i).unwrap_or(""), rest.get(i..).unwrap_or("/"))
    });
    if authority.is_empty() || authority.contains('@') || path.contains(['\r', '\n', ' ']) {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => (h, p.parse().ok()?),
        Some(_) => return None,
        None => (authority, 443),
    };
    Some(Target {
        host: host.to_owned(),
        port,
        path: path.to_owned(),
    })
}

/// One HTTP answer: status, the `DPoP-Nonce` header and the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// Status.
    pub status: u16,
    /// `DPoP-Nonce`.
    pub nonce: Option<String>,
    /// Body.
    pub body: Vec<u8>,
}

/// Parses one HTTP/1.1 response read to the end of the connection.
#[must_use]
pub fn parse(buf: &[u8]) -> Option<Answer> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(head) = parsed.parse(buf).ok()? else {
        return None;
    };
    let status = parsed.code?;
    let find = |name: &str| {
        parsed
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
    };
    let nonce = find("dpop-nonce").map(String::from);
    let chunked = find("transfer-encoding").is_some_and(|t| t.eq_ignore_ascii_case("chunked"));
    let rest = buf.get(head..)?;
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(len) = find("content-length") {
        rest.get(..len.trim().parse::<usize>().ok()?)?.to_vec()
    } else {
        rest.to_vec()
    };
    Some(Answer {
        status,
        nonce,
        body,
    })
}

fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(rest.get(..line)?).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        rest = rest.get(line.checked_add(2)?..)?;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size.checked_add(2)?..)?;
    }
}

struct DpopKey {
    signer: SoftSigner,
    public: PublicKey,
}

impl ProofKey for DpopKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, input: &[u8]) -> Option<Vec<u8>> {
        self.signer.sign(input).ok()
    }
}

struct OsRandom;

impl SdkRandom for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(out)
            .map_err(|_| RandomUnavailable)
    }
}

fn now_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

/// Access over HTTPS with the host's client certificate.
pub struct AccessHttps {
    connector: TlsConnector,
    issuer: String,
    client_id: String,
    key: DpopKey,
    address: Option<std::net::SocketAddr>,
    nonce: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
}

fn form_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Why the client could not be built.
#[derive(Debug, thiserror::Error)]
pub enum Setup {
    /// TLS configuration.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    /// The DPoP key.
    #[error("dpop key")]
    Key,
    /// The issuer is not an `https` URL.
    #[error("issuer")]
    Issuer,
}

impl AccessHttps {
    /// A client of the realm at `issuer` (its issuer URL) as `client_id`, presenting the host's
    /// `chain` and `key`, trusting `roots`. The DPoP key lives in memory only.
    ///
    /// # Errors
    /// [`Setup`].
    pub fn new(
        roots: rustls::RootCertStore,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        issuer: &str,
        client_id: &str,
    ) -> Result<Self, Setup> {
        if target(issuer).is_none() {
            return Err(Setup::Issuer);
        }
        let c = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
        let (signer, _) = SoftSigner::generate_p256().map_err(|_| Setup::Key)?;
        let public = signer.public_key();
        Ok(Self {
            connector: TlsConnector::from(Arc::new(c)),
            issuer: issuer.trim_end_matches('/').to_owned(),
            client_id: client_id.to_owned(),
            key: DpopKey { signer, public },
            address: None,
            nonce: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        })
    }

    /// The same client, connecting to `address` whatever the issuer's host resolves to; the
    /// server's certificate is still checked against the issuer's host name.
    #[must_use]
    pub const fn resolving(mut self, address: std::net::SocketAddr) -> Self {
        self.address = Some(address);
        self
    }

    async fn exchange(
        &self,
        url: &str,
        head: Vec<(String, String)>,
        body: &[u8],
        ct: &str,
    ) -> Option<Answer> {
        let at = target(url)?;
        if head
            .iter()
            .any(|(k, v)| k.contains(['\r', '\n']) || v.contains(['\r', '\n']))
        {
            return None;
        }
        let name = ServerName::try_from(at.host.clone()).ok()?;
        let tcp = match self.address {
            Some(a) => TcpStream::connect(a).await.ok()?,
            None => TcpStream::connect((at.host.as_str(), at.port)).await.ok()?,
        };
        let mut tls = self.connector.connect(name, tcp).await.ok()?;
        let mut h = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nContent-Type: {ct}\r\n",
            at.path, at.host, at.port
        );
        for (k, v) in &head {
            let _ = write!(h, "{k}: {v}\r\n");
        }
        let _ = write!(
            h,
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        tls.write_all(h.as_bytes()).await.ok()?;
        tls.write_all(body).await.ok()?;
        tls.flush().await.ok()?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = tls.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(chunk.get(..n)?);
            if buf.len() > MAX_ANSWER {
                return None;
            }
        }
        parse(&buf)
    }

    /// One `POST`, with a DPoP proof when `dpop` and the access token when `token`; retried
    /// once with the nonce the server asks for.
    async fn post(
        &self,
        path: &str,
        body: &[u8],
        ct: &str,
        dpop: bool,
        token: Option<&str>,
    ) -> Option<Answer> {
        let url = format!("{}{path}", self.issuer);
        for _ in 0..2 {
            let mut head = Vec::new();
            if dpop {
                let nonce = self.nonce.lock().ok()?.get(path).cloned();
                let p = proof(
                    &self.key,
                    &ProofFor {
                        method: "POST",
                        uri: &url,
                        access_token: token,
                        nonce: nonce.as_deref(),
                    },
                    now_ms()?,
                    &OsRandom,
                )
                .ok()?;
                head.push((String::from("DPoP"), p));
            }
            if let Some(t) = token {
                head.push((String::from("Authorization"), format!("DPoP {t}")));
            }
            let answer = tokio::time::timeout(TIMEOUT, self.exchange(&url, head, body, ct))
                .await
                .ok()??;
            let asked = answer.nonce.clone();
            let retry = dpop
                && asked.is_some()
                && (answer.status == 401
                    || serde_json::from_slice::<Value>(&answer.body)
                        .is_ok_and(|v| at(&v, "error") == "use_dpop_nonce"));
            if let Some(n) = asked {
                self.nonce.lock().ok()?.insert(String::from(path), n);
            }
            if !retry {
                return Some(answer);
            }
        }
        None
    }

    async fn json(&self, path: &str, body: &Value, token: Option<&str>) -> Option<Answer> {
        self.post(
            path,
            body.to_string().as_bytes(),
            "application/json",
            token.is_some(),
            token,
        )
        .await
    }
}

static NULL: Value = Value::Null;

fn at<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&NULL)
}

fn credential(v: &Value) -> Option<Credential> {
    Some(Credential {
        id: b64url_decode(at(v, "id").as_str()?).ok()?,
        alg: at(v, "alg").as_i64()?,
        public_key: b64url_decode(at(v, "public_key").as_str()?).ok()?,
        rp_id: String::from(at(v, "rp_id").as_str()?),
        sign_count: u32::try_from(at(v, "sign_count").as_u64().unwrap_or(0)).ok()?,
    })
}

fn outcome(a: &Answer) -> Reached<bool> {
    match a.status {
        200 => match serde_json::from_slice::<Value>(&a.body) {
            Ok(v) if at(&v, "outcome") == "allow" => Reached::Answer(true),
            Ok(v) if at(&v, "outcome") == "deny" => Reached::Answer(false),
            _ => Reached::Unreachable,
        },
        400..=499 => Reached::Answer(false),
        _ => Reached::Unreachable,
    }
}

impl Access for AccessHttps {
    async fn snapshot(&self) -> Reached<Vec<u8>> {
        match self.json("/linux/v1/nss", &json!({}), None).await {
            Some(a) if a.status == 200 => Reached::Answer(a.body),
            _ => Reached::Unreachable,
        }
    }

    async fn device_start(&self) -> Reached<DeviceStart> {
        let body = format!("client_id={}&scope=openid", form_escape(&self.client_id));
        let Some(a) = self
            .post(
                "/device_authorization",
                body.as_bytes(),
                "application/x-www-form-urlencoded",
                false,
                None,
            )
            .await
            .filter(|a| a.status == 200)
        else {
            return Reached::Unreachable;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&a.body) else {
            return Reached::Unreachable;
        };
        let d = (|| {
            Some(DeviceStart {
                device_code: String::from(at(&v, "device_code").as_str()?),
                user_code: String::from(at(&v, "user_code").as_str()?),
                verification_uri: String::from(at(&v, "verification_uri").as_str()?),
                expires_in: at(&v, "expires_in").as_u64()?,
                interval: at(&v, "interval").as_u64().unwrap_or(5),
            })
        })();
        d.map_or(Reached::Unreachable, Reached::Answer)
    }

    async fn device_poll(&self, device_code: &str) -> Reached<DevicePoll> {
        let body = format!(
            "grant_type={}&client_id={}&device_code={}",
            form_escape(DEVICE_GRANT),
            form_escape(&self.client_id),
            form_escape(device_code)
        );
        let Some(a) = self
            .post(
                "/token",
                body.as_bytes(),
                "application/x-www-form-urlencoded",
                true,
                None,
            )
            .await
        else {
            return Reached::Unreachable;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&a.body) else {
            return Reached::Unreachable;
        };
        if a.status == 200 {
            return match (
                at(&v, "access_token").as_str(),
                at(&v, "token_type").as_str(),
            ) {
                (Some(t), Some(ty)) if ty.eq_ignore_ascii_case("dpop") => {
                    Reached::Answer(DevicePoll::Token(String::from(t)))
                }
                _ => Reached::Answer(DevicePoll::Ended),
            };
        }
        match at(&v, "error").as_str() {
            Some("authorization_pending" | "slow_down") => Reached::Answer(DevicePoll::Pending),
            Some(_) => Reached::Answer(DevicePoll::Ended),
            None => Reached::Unreachable,
        }
    }

    async fn sign_in(&self, token: &str, user: &str) -> Reached<SignIn> {
        let Some(a) = self
            .json("/linux/v1/auth", &json!({ "user": user }), Some(token))
            .await
        else {
            return Reached::Unreachable;
        };
        let allow = match outcome(&a) {
            Reached::Answer(b) => b,
            Reached::Unreachable => return Reached::Unreachable,
        };
        let credentials = serde_json::from_slice::<Value>(&a.body)
            .ok()
            .and_then(|v| at(&v, "credentials").as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(credential)
            .collect();
        Reached::Answer(SignIn { allow, credentials })
    }

    async fn sudo(&self, token: &str, user: &str, command: &[u8; 32]) -> Reached<bool> {
        match self
            .json(
                "/linux/v1/sudo",
                &json!({ "user": user, "command": b64url_encode(command) }),
                Some(token),
            )
            .await
        {
            Some(a) => outcome(&a),
            None => Reached::Unreachable,
        }
    }
}
