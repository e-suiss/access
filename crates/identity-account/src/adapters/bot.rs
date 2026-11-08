//! Bot signal adapters (OP-153 m.1 (b), m.3 (h), TN-81): Privacy Pass redemption (positive
//! only), Friendly Captcha (the default score adapter) and Cloudflare Turnstile (optional), each
//! one HTTPS `POST` to the provider's verify endpoint. reCAPTCHA has no adapter. A provider that
//! does not answer in time, or answers outside its format, is `Unavailable`: never a refusal.

use std::sync::Arc;
use std::time::Duration;

use access_crypto::Secret;
use access_crypto::privacy_pass::{self, Issuer};
use access_kernel::json::b64url_decode;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::domain::bot::{BotProvider, BotSignal};
use crate::ports::BotSignals;

/// Largest provider answer read.
const MAX_ANSWER: usize = 16 * 1024;

/// The score a provider's "success" stands for, and its failure.
const PASSED: u8 = 90;
const FAILED: u8 = 10;

/// A score provider's verify endpoint and secret.
#[derive(Clone)]
pub struct ScoreProvider {
    /// Which one.
    pub provider: BotProvider,
    /// Verify host, e.g. `global.frcapi.com` or `challenges.cloudflare.com`.
    pub host: String,
    /// Verify path.
    pub path: String,
    /// The site key Friendly Captcha checks the answer against.
    pub site_key: String,
    /// The provider secret (Friendly Captcha API key, Turnstile secret).
    pub secret: Secret<String>,
}

impl core::fmt::Debug for ScoreProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScoreProvider")
            .field("provider", &self.provider)
            .field("host", &self.host)
            .field("secret", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Privacy Pass redemption settings.
#[derive(Clone, Debug)]
pub struct PrivacyPass {
    /// Issuers whose tokens are accepted.
    pub issuers: Vec<Issuer>,
    /// The `challenge_digest` of the challenge the hosted page presents.
    pub challenge: [u8; 32],
}

/// The configured bot signal sources; none configured answers `Unavailable` (OP-153 m.1 (b)).
#[derive(Clone, Default)]
pub struct BotProviders {
    /// Privacy Pass, if configured.
    pub privacy_pass: Option<PrivacyPass>,
    /// The score provider, if configured.
    pub score: Option<ScoreProvider>,
    /// The TLS connector for provider calls.
    pub tls: Option<TlsConnector>,
    /// How long a provider may take.
    pub timeout: Option<Duration>,
}

impl core::fmt::Debug for BotProviders {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BotProviders")
            .field("privacy_pass", &self.privacy_pass.is_some())
            .field("score", &self.score)
            .finish_non_exhaustive()
    }
}

/// The TLS connector over the platform roots.
#[must_use]
pub fn connector(config: Arc<rustls::ClientConfig>) -> TlsConnector {
    TlsConnector::from(config)
}

fn form_escape(v: &str) -> String {
    v.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// The request a score provider's verify endpoint takes.
#[must_use]
pub fn verify_request(p: &ScoreProvider, token: &str) -> Vec<u8> {
    let (content_type, body, auth) = match p.provider {
        BotProvider::Turnstile => (
            "application/x-www-form-urlencoded",
            format!(
                "secret={}&response={}",
                form_escape(p.secret.expose()),
                form_escape(token)
            ),
            String::new(),
        ),
        _ => (
            "application/json",
            serde_json::json!({ "response": token, "sitekey": p.site_key }).to_string(),
            format!("X-API-Key: {}\r\n", p.secret.expose()),
        ),
    };
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{auth}Connection: close\r\n\r\n{body}",
        p.path,
        p.host,
        body.len(),
    )
    .into_bytes()
}

/// The signal of a verify answer: `{"success": true}` passes, `false` fails, anything else is
/// `Unavailable`.
#[must_use]
pub fn read_answer(raw: &[u8]) -> BotSignal {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let Ok(httparse::Status::Complete(at)) = resp.parse(raw) else {
        return BotSignal::Unavailable;
    };
    if resp.code != Some(200) {
        return BotSignal::Unavailable;
    }
    let body = raw.get(at..).unwrap_or_default();
    match serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("success").and_then(serde_json::Value::as_bool))
    {
        Some(true) => BotSignal::Score(PASSED),
        Some(false) => BotSignal::Score(FAILED),
        None => BotSignal::Unavailable,
    }
}

impl BotProviders {
    async fn exchange(&self, p: &ScoreProvider, token: &str) -> Option<Vec<u8>> {
        let tls = self.tls.as_ref()?;
        let name = ServerName::try_from(p.host.clone()).ok()?;
        let tcp = TcpStream::connect((p.host.as_str(), 443)).await.ok()?;
        let mut s = tls.connect(name, tcp).await.ok()?;
        s.write_all(&verify_request(p, token)).await.ok()?;
        s.flush().await.ok()?;
        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0_u8; 2048];
        loop {
            let n = s.read(&mut chunk).await.ok()?;
            if n == 0 {
                return Some(buf);
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
            if buf.len() > MAX_ANSWER {
                return None;
            }
        }
    }
}

impl BotSignals for BotProviders {
    async fn assess(&self, token: Option<&str>, _context: &[u8]) -> BotSignal {
        let Some(token) = token.filter(|t| !t.is_empty() && t.len() <= 4096) else {
            return BotSignal::Unavailable;
        };
        if let (Some(pp), Some(raw)) = (&self.privacy_pass, token.strip_prefix("pp:"))
            && let Ok(bytes) = b64url_decode(raw)
        {
            return if privacy_pass::verify(&bytes, &pp.challenge, &pp.issuers) {
                BotSignal::Positive
            } else {
                BotSignal::Unavailable
            };
        }
        let Some(p) = &self.score else {
            return BotSignal::Unavailable;
        };
        let timeout = self.timeout.unwrap_or(Duration::from_secs(2));
        match tokio::time::timeout(timeout, self.exchange(p, token)).await {
            Ok(Some(raw)) => read_answer(&raw),
            _ => BotSignal::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(provider: BotProvider) -> ScoreProvider {
        ScoreProvider {
            provider,
            host: String::from("verify.example"),
            path: String::from("/siteverify"),
            site_key: String::from("site"),
            secret: Secret::new(String::from("s3cr&t")),
        }
    }

    // OP-153 m.1 (b), m.3 (h), TN-81
    #[tokio::test]
    async fn no_provider_and_a_failed_token_never_refuse() {
        let none = BotProviders::default();
        assert_eq!(none.assess(None, b"").await, BotSignal::Unavailable);
        assert_eq!(none.assess(Some("x"), b"").await, BotSignal::Unavailable);
        assert_eq!(
            read_answer(b"HTTP/1.1 200 OK\r\n\r\n{\"success\":false}"),
            BotSignal::Score(FAILED)
        );
        assert_eq!(
            read_answer(b"HTTP/1.1 200 OK\r\n\r\n{\"success\":true}"),
            BotSignal::Score(PASSED)
        );
        assert_eq!(
            read_answer(b"HTTP/1.1 500 X\r\n\r\n{}"),
            BotSignal::Unavailable
        );
        assert!(BotSignal::Score(FAILED).step_up());
    }

    // OP-153 m.1 (b)
    #[test]
    fn the_verify_requests_carry_the_secret_where_each_provider_wants_it() {
        let t = String::from_utf8(verify_request(&provider(BotProvider::Turnstile), "tok"))
            .unwrap_or_default();
        assert!(t.contains("secret=s3cr%26t&response=tok"));
        let f = String::from_utf8(verify_request(
            &provider(BotProvider::FriendlyCaptcha),
            "tok",
        ))
        .unwrap_or_default();
        assert!(f.contains("X-API-Key: s3cr&t\r\n"));
        assert!(f.contains("\"sitekey\":\"site\""));
    }
}
