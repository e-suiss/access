//! The HTTP Negotiate endpoint (RFC 4559; §10.6.4, IDP-17, OP-155 m.3 (o)). HTTP/1.1 only, over
//! TLS 1.3 (CR-12), because Negotiate is bound to one connection. `GET /negotiate` without a
//! token answers 401 with `WWW-Authenticate: Negotiate` and a page that sends the browser on to
//! normal sign-in, for browsers whose allowlist does not name this host. With a token, every
//! failure (NTLM, another SPN, RC4, a bad ticket, an unknown principal) falls back to normal
//! sign-in with a 303, never a second 401. A success has the realm issuer's `authentication`
//! Claim queued and also ends at the sign-in page.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use access_edge_core::EdgeCore;
use access_edge_core::governor::Governor;
use access_edge_core::ipc::{Op, Reply};
use access_edge_core::parser::ParserClient;
use access_edge_core::spnego::{self, Refusal, Token};
use access_internal_api::edge::Call;
use access_internal_api::edge::kerberos::{Authenticate, Authenticated};
use libgssapi::credential::Cred;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::accept::Acceptor;
use crate::proxy::Proxy;

/// Largest request head.
pub const MAX_HEAD: usize = 16 * 1024;

/// Longest a connection may stay silent.
pub const IDLE: Duration = Duration::from_secs(60);

/// Longest a TLS handshake may take.
pub const HANDSHAKE: Duration = Duration::from_secs(10);

/// Why the TLS configuration was refused; the gateway does not start.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The PEM input holds no usable certificate or key.
    #[error("{0}")]
    Pem(&'static str),
    /// rustls refused the configuration.
    #[error("tls: {0}")]
    Rustls(#[from] rustls::Error),
}

/// The TLS acceptor over the gateway's certificate chain and key, PEM: TLS 1.3, ALPN
/// `http/1.1` only.
///
/// # Errors
/// [`TlsError`].
pub fn acceptor(chain_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor, TlsError> {
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::Pem("certificate chain"))?;
    if chain.is_empty() {
        return Err(TlsError::Pem("no server certificate"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| TlsError::Pem("private key"))?;
    // CR-12
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// What the endpoint serves.
#[derive(Clone)]
pub struct Endpoint {
    /// The edge core.
    pub core: Arc<EdgeCore>,
    /// The parser worker supervisor.
    pub parser: ParserClient,
    /// The acceptor of the configured SPN.
    pub acceptor: Acceptor,
    /// The configured SPN, compared exactly.
    pub spn: String,
    /// The realm's normal sign-in page.
    pub login: String,
    /// The `S4U2Proxy` backend, when configured.
    pub proxy: Option<Proxy>,
    /// The TLS acceptor.
    pub tls: TlsAcceptor,
    /// Connections per second and burst per client address.
    pub governor: Arc<Governor>,
}

/// The outcome of one `Authorization` header.
pub enum Outcome {
    /// No token: ask for one.
    Challenge,
    /// Anything that is not an accepted ticket of an active account: normal sign-in.
    Fallback,
    /// An accepted ticket; the Claim is queued.
    Accepted {
        /// The `NegTokenResp`, base64.
        response: String,
        /// The proxy credential for `S4U2Proxy`, when the ticket allows it.
        delegated: Option<Cred>,
    },
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn fallback_page(login: &str) -> String {
    format!(
        "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0; url={login}\"><title>Sign in</title><p><a href=\"{login}\">Continue to sign in</a></p>"
    )
}

impl Endpoint {
    /// Writes the audit event `name` as the realm's log names it (`edge.<event>.<outcome>`).
    async fn audit(&self, name: &str) {
        let Some((event, outcome)) = name
            .strip_prefix("edge.")
            .and_then(|rest| rest.rsplit_once('.'))
        else {
            return;
        };
        if self.core.audit(event, outcome, None).await.is_err() {
            crate::log("audit unavailable");
        }
    }

    async fn read_token(&self, token: Vec<u8>) -> Result<Token, ()> {
        match self.parser.parse(Op::SpnegoRead, token).await {
            Ok(Reply::Ok { output, .. }) => Token::decode(&output).map_err(|_| ()),
            _ => Err(()),
        }
    }

    /// The outcome of `authorization`, the request's `Authorization` header (§10.6.4).
    pub async fn negotiate(&self, authorization: Option<&str>) -> Outcome {
        let Some(value) = authorization else {
            return Outcome::Challenge;
        };
        let scheme = value.trim().split(' ').next().unwrap_or_default();
        if scheme.eq_ignore_ascii_case("ntlm") {
            self.audit("edge.kerberos.ntlm.refused").await;
            return Outcome::Fallback;
        }
        let Some(raw) = spnego::authorization(value) else {
            self.audit("edge.kerberos.token.refused").await;
            return Outcome::Fallback;
        };
        let Ok(token) = self.read_token(raw).await else {
            self.audit("edge.kerberos.token.refused").await;
            return Outcome::Fallback;
        };
        // IDP-17, OP-155 m.3 (o)
        let kvno = match spnego::check(&token, &self.spn) {
            Ok(k) => k,
            Err(Refusal::Ntlm) => {
                self.audit("edge.kerberos.ntlm.refused").await;
                return Outcome::Fallback;
            }
            Err(Refusal::Spn | Refusal::Enctype | Refusal::Kvno) => {
                self.audit("edge.kerberos.token.refused").await;
                return Outcome::Fallback;
            }
        };
        let acceptor = self.acceptor.clone();
        let krb5 = token.krb5.clone();
        let accepted = tokio::task::spawn_blocking(move || acceptor.accept(&krb5)).await;
        let Ok(Ok(accepted)) = accepted else {
            self.audit("edge.kerberos.accept.refused").await;
            return Outcome::Fallback;
        };
        let Ok(realm) = self.core.realm(None) else {
            return Outcome::Fallback;
        };
        let q = Authenticate {
            realm: String::from(realm),
            principal: accepted.principal.clone(),
            spn: token.spn(),
            kvno,
            etype: token.etype,
        };
        let subject = match self.core.raw(Call::Authenticate, &q.encode()).await {
            Ok(body) => Authenticated::decode(&body).ok().and_then(|a| a.subject),
            Err(_) => None,
        };
        let Some(subject) = subject else {
            return Outcome::Fallback;
        };
        let evidence = suiss_crypto::digest::sha256(&token.krb5);
        // IDP-17, P-ID-5
        if self
            .core
            .issue(None, subject, "kerberos", now_ms(), Some(evidence))
            .await
            .is_err()
        {
            return Outcome::Fallback;
        }
        Outcome::Accepted {
            response: spnego::base64(&spnego::accept_completed(accepted.ap_rep.as_deref())),
            delegated: accepted.delegated,
        }
    }

    /// Serves the endpoint on `listener` until it fails.
    pub async fn serve(self, listener: TcpListener) {
        loop {
            let Ok((tcp, peer)) = listener.accept().await else {
                continue;
            };
            let key = match peer.ip() {
                std::net::IpAddr::V4(v) => v.octets().to_vec(),
                std::net::IpAddr::V6(v) => v.octets().to_vec(),
            };
            if !self.governor.admit(&key, now_ms()) {
                continue;
            }
            let e = self.clone();
            tokio::spawn(async move {
                let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE, e.tls.accept(tcp)).await
                else {
                    return;
                };
                e.connection(&mut tls).await;
            });
        }
    }

    /// Serves one connection until it closes, fails or stays silent.
    pub async fn connection<S: AsyncRead + AsyncWrite + Unpin>(&self, s: &mut S) {
        let mut buf = Vec::new();
        loop {
            let Some(head) = read_head(s, &mut buf).await else {
                return;
            };
            let (keep, answer) = self.request(&head).await;
            if s.write_all(&answer).await.is_err() || s.flush().await.is_err() || !keep {
                return;
            }
        }
    }

    async fn request(&self, head: &[u8]) -> (bool, Vec<u8>) {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut r = httparse::Request::new(&mut headers);
        let Ok(httparse::Status::Complete(_)) = r.parse(head) else {
            return (false, answer(400, &[], ""));
        };
        let has_body = r.headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case("transfer-encoding")
                || (h.name.eq_ignore_ascii_case("content-length") && h.value != b"0")
        });
        if r.method != Some("GET") || r.version != Some(1) || has_body {
            return (false, answer(405, &[], ""));
        }
        let path = r.path.unwrap_or_default();
        let authorization = r
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .and_then(|h| core::str::from_utf8(h.value).ok());
        let route = path.split('?').next().unwrap_or_default();
        if route == "/negotiate" {
            return (true, self.respond(self.negotiate(authorization).await));
        }
        if let (Some(rest), Some(proxy)) = (route.strip_prefix("/proxy"), &self.proxy)
            && (rest.is_empty() || rest.starts_with('/'))
        {
            let forward = path.strip_prefix("/proxy").unwrap_or("/");
            let forward = if forward.is_empty() { "/" } else { forward };
            return (false, self.proxied(proxy, forward, authorization).await);
        }
        (true, answer(404, &[], ""))
    }

    fn respond(&self, o: Outcome) -> Vec<u8> {
        match o {
            Outcome::Challenge => answer(
                401,
                &[
                    ("WWW-Authenticate", "Negotiate"),
                    ("Content-Type", "text/html; charset=utf-8"),
                ],
                &fallback_page(&self.login),
            ),
            Outcome::Fallback => answer(303, &[("Location", &self.login)], ""),
            Outcome::Accepted { response, .. } => {
                let negotiate = format!("Negotiate {response}");
                answer(
                    303,
                    &[("Location", &self.login), ("WWW-Authenticate", &negotiate)],
                    "",
                )
            }
        }
    }

    async fn proxied(&self, proxy: &Proxy, path: &str, authorization: Option<&str>) -> Vec<u8> {
        let delegated = match self.negotiate(authorization).await {
            Outcome::Accepted { delegated, .. } => delegated,
            other => return self.respond(other),
        };
        let Some(delegated) = delegated else {
            self.audit("edge.kerberos.s4u2proxy.refused").await;
            return answer(303, &[("Location", &self.login)], "");
        };
        let p = proxy.clone();
        let token = tokio::task::spawn_blocking(move || p.token(delegated)).await;
        let Ok(Ok(token)) = token else {
            self.audit("edge.kerberos.s4u2proxy.refused").await;
            return answer(303, &[("Location", &self.login)], "");
        };
        if let Ok(raw) = proxy.get(path, &spnego::base64(&token)).await {
            self.audit("edge.kerberos.s4u2proxy.ok").await;
            raw
        } else {
            self.audit("edge.kerberos.s4u2proxy.refused").await;
            answer(502, &[], "")
        }
    }
}

/// Reads one request head (up to the blank line) into `buf`'s front; `None` at the end of the
/// stream, on silence, or past [`MAX_HEAD`].
async fn read_head<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let end = at.checked_add(4)?;
            let rest = buf.split_off(end);
            return Some(core::mem::replace(buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
        let n = match tokio::time::timeout(IDLE, s.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => return None,
            Ok(Ok(n)) => n,
        };
        buf.extend_from_slice(chunk.get(..n)?);
    }
}

/// One HTTP/1.1 answer with `headers` and an HTML or empty `body`.
#[must_use]
pub fn answer(status: u16, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let reason = match status {
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Bad Gateway",
    };
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in headers {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    out.push_str("Cache-Control: no-store\r\n");
    let _ = write!(out, "Content-Length: {}\r\n\r\n", body.len());
    out.push_str(body);
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // §10.6.4
    #[test]
    fn the_challenge_offers_negotiate_and_a_way_to_sign_in() {
        let page = fallback_page("https://corp.example/login");
        let a = String::from_utf8(answer(
            401,
            &[
                ("WWW-Authenticate", "Negotiate"),
                ("Content-Type", "text/html; charset=utf-8"),
            ],
            &page,
        ))
        .unwrap_or_default();
        assert!(a.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(a.contains("\r\nWWW-Authenticate: Negotiate\r\n"));
        assert!(a.contains("url=https://corp.example/login"));
        assert!(!a.contains("NTLM"));
        let f = String::from_utf8(answer(
            303,
            &[("Location", "https://corp.example/login")],
            "",
        ))
        .unwrap_or_default();
        assert!(f.contains("\r\nLocation: https://corp.example/login\r\n"));
    }
}
