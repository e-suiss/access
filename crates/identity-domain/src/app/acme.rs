//! One ACME issuance (RFC 8555 §7, RFC 8737, OP-156 m.3 (i)): the account, an order for one
//! `dns` identifier, its TLS-ALPN-01 challenge published on the TLS listeners, a P-256 key made
//! in this process and its CSR, and the issued chain checked against the order before Access
//! keeps it.

use core::time::Duration;

use suiss_crypto::cose::PublicKey;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer as _, SoftSigner};

use crate::acme::AcmeError;
use crate::acme::jws::{self, Signer};
use crate::acme::wire::{
    self, Authorization, BAD_NONCE, Directory, MAX_DOCUMENT, Order, State, on_origin,
};
use crate::ports::{AccountKey, AcmeHttp, Answer, Challenges, Pause};
use crate::x509::{self, Leaf};

/// Most polls of one authorization or order (PD).
pub const MAX_POLLS: u32 = 30;

/// Longest pause between polls a server's `Retry-After` may ask for (PD).
pub const MAX_PAUSE: Duration = Duration::from_secs(10);

/// Most certificates in an issued chain (PD).
pub const MAX_CHAIN: usize = 4;

/// Times a stale nonce is replaced before the request fails (RFC 8555 §6.5).
const NONCE_RETRIES: u32 = 3;

/// What an issuance hands back: the chain, its leaf's fields, and the key made for it, which
/// the caller seals under the realm KEK before it is stored.
pub struct Issued {
    /// The chain as PEM, leaf first.
    pub chain_pem: String,
    /// The leaf's validity and names.
    pub leaf: Leaf,
    /// The certificate key, PKCS#8.
    pub key_pkcs8: Secret<Vec<u8>>,
}

/// The client of one ACME directory.
pub struct Client<'a, H, K, P> {
    /// HTTPS to the directory's origin.
    pub http: &'a H,
    /// The account key.
    pub key: &'a K,
    /// The pause between polls.
    pub pause: &'a P,
    /// The directory URL.
    pub directory: &'a str,
    /// The account's contact, `mailto:` (optional, §7.3).
    pub contact: Option<&'a str>,
}

fn unreachable<E>(_: E) -> AcmeError {
    AcmeError::Unreachable
}

struct Session {
    dir: Directory,
    point: Vec<u8>,
    nonce: Option<String>,
    kid: Option<String>,
}

impl<H: AcmeHttp, K: AccountKey, P: Pause> Client<'_, H, K, P> {
    async fn fresh_nonce(&self, s: &mut Session) -> Result<String, AcmeError> {
        if let Some(n) = s.nonce.take() {
            return Ok(n);
        }
        let a = self
            .http
            .head(&s.dir.new_nonce)
            .await
            .map_err(unreachable)?;
        a.nonce.ok_or(AcmeError::Protocol("no nonce"))
    }

    /// A signed POST to `url` (`payload` `None` for POST-as-GET), with a stale nonce replaced.
    async fn post(
        &self,
        s: &mut Session,
        url: &str,
        payload: Option<&[u8]>,
        max_body: usize,
    ) -> Result<Answer, AcmeError> {
        let url = on_origin(&s.dir.url, url)?;
        let mut tries = 0_u32;
        loop {
            let nonce = self.fresh_nonce(s).await?;
            let who = match &s.kid {
                Some(kid) => Signer::Kid(kid),
                None => Signer::Jwk(&s.point),
            };
            let (input, _) = jws::signing_input(who, &nonce, &url, payload)?;
            let sig = self
                .key
                .sign(input.as_bytes())
                .await
                .map_err(|_| AcmeError::Key)?;
            let body = jws::body(&input, &sig)?;
            let a = self
                .http
                .post(&url, &body, max_body)
                .await
                .map_err(unreachable)?;
            s.nonce.clone_from(&a.nonce);
            if (200..300).contains(&a.status) {
                return Ok(a);
            }
            let kind = wire::problem_type(&a.body).unwrap_or_default();
            tries = tries.saturating_add(1);
            if kind == BAD_NONCE && tries < NONCE_RETRIES {
                continue;
            }
            return Err(AcmeError::Refused(if kind.is_empty() {
                format!("status {}", a.status)
            } else {
                kind
            }));
        }
    }

    async fn wait(&self, a: &Answer) {
        let s = a.retry_after_s.unwrap_or(1).clamp(1, MAX_PAUSE.as_secs());
        self.pause.pause(Duration::from_secs(s)).await;
    }

    async fn open(&self) -> Result<Session, AcmeError> {
        let a = self
            .http
            .get(self.directory, MAX_DOCUMENT)
            .await
            .map_err(unreachable)?;
        if a.status != 200 {
            return Err(AcmeError::Protocol("directory status"));
        }
        let dir = Directory::read(self.directory, &a.body)?;
        let point = self.key.public_point().await.map_err(|_| AcmeError::Key)?;
        jws::jwk(&point)?;
        let mut s = Session {
            dir,
            point,
            nonce: None,
            kid: None,
        };
        let contact = self
            .contact
            .map_or_else(|| serde_json::json!([]), |c| serde_json::json!([c]));
        let account = serde_json::json!({ "termsOfServiceAgreed": true, "contact": contact });
        let url = s.dir.new_account.clone();
        let a = self
            .post(
                &mut s,
                &url,
                Some(account.to_string().as_bytes()),
                MAX_DOCUMENT,
            )
            .await?;
        let kid = a.location.ok_or(AcmeError::Protocol("no account url"))?;
        s.kid = Some(on_origin(&s.dir.url, &kid)?);
        Ok(s)
    }

    async fn authorize<C: Challenges>(
        &self,
        s: &mut Session,
        url: &str,
        host: &str,
        challenges: &C,
    ) -> Result<(), AcmeError> {
        let a = self.post(s, url, None, MAX_DOCUMENT).await?;
        let authz = Authorization::read(&s.dir.url, &a.body)?;
        if authz.host != host {
            return Err(AcmeError::Protocol("authorization for another host"));
        }
        match authz.state {
            State::Valid => return Ok(()),
            State::Invalid => return Err(AcmeError::Invalid("authorization")),
            _ => {}
        }
        let challenge = authz.tls_alpn().ok_or(AcmeError::NoChallenge)?.clone();
        let ka = jws::key_authorization(&challenge.token, &s.point)?;
        challenges
            .publish(host, jws::alpn_digest(&ka))
            .await
            .map_err(|_| AcmeError::Publish)?;
        let out = self.respond(s, url, &challenge.url).await;
        challenges
            .withdraw(host)
            .await
            .map_err(|_| AcmeError::Publish)?;
        out
    }

    async fn respond(
        &self,
        s: &mut Session,
        authz: &str,
        challenge: &str,
    ) -> Result<(), AcmeError> {
        self.post(s, challenge, Some(b"{}"), MAX_DOCUMENT).await?;
        for _ in 0..MAX_POLLS {
            let a = self.post(s, authz, None, MAX_DOCUMENT).await?;
            match Authorization::read(&s.dir.url, &a.body)?.state {
                State::Valid => return Ok(()),
                State::Invalid => return Err(AcmeError::Invalid("challenge")),
                _ => self.wait(&a).await,
            }
        }
        Err(AcmeError::Timeout)
    }

    async fn settle(
        &self,
        s: &mut Session,
        url: &str,
        mut order: Order,
    ) -> Result<Order, AcmeError> {
        for _ in 0..MAX_POLLS {
            match order.state {
                State::Valid if order.certificate.is_some() => return Ok(order),
                State::Invalid => return Err(AcmeError::Invalid("order")),
                _ => {}
            }
            let a = self.post(s, url, None, MAX_DOCUMENT).await?;
            order = Order::read(&s.dir.url, &a.body)?;
            if !matches!(order.state, State::Valid) {
                self.wait(&a).await;
            }
        }
        Err(AcmeError::Timeout)
    }

    /// Issues a certificate for `host` at `now_s`, its TLS-ALPN-01 challenge answered through
    /// `challenges`.
    ///
    /// # Errors
    /// [`AcmeError`].
    pub async fn issue<C: Challenges>(
        &self,
        host: &str,
        now_s: i64,
        challenges: &C,
    ) -> Result<Issued, AcmeError> {
        let mut s = self.open().await?;
        let ask = serde_json::json!({ "identifiers": [{ "type": "dns", "value": host }] });
        let new_order = s.dir.new_order.clone();
        let a = self
            .post(
                &mut s,
                &new_order,
                Some(ask.to_string().as_bytes()),
                MAX_DOCUMENT,
            )
            .await?;
        let order_url = on_origin(
            &s.dir.url,
            &a.location.ok_or(AcmeError::Protocol("no order url"))?,
        )?;
        let order = Order::read(&s.dir.url, &a.body)?;
        for authz in &order.authorizations {
            self.authorize(&mut s, authz, host, challenges).await?;
        }
        let (cert_key, key_pkcs8) = SoftSigner::generate_p256().map_err(|_| AcmeError::Key)?;
        let PublicKey::P256(point) = cert_key.public_key() else {
            return Err(AcmeError::Key);
        };
        let csr = x509::csr(&cert_key, host).map_err(|_| AcmeError::Key)?;
        let finalize = serde_json::json!({ "csr": access_kernel::json::b64url_encode(&csr) });
        let a = self
            .post(
                &mut s,
                &order.finalize,
                Some(finalize.to_string().as_bytes()),
                MAX_DOCUMENT,
            )
            .await?;
        let finalized = Order::read(&s.dir.url, &a.body)?;
        let order = self.settle(&mut s, &order_url, finalized).await?;
        let cert_url = order
            .certificate
            .ok_or(AcmeError::Protocol("no certificate"))?;
        let a = self.post(&mut s, &cert_url, None, MAX_DOCUMENT).await?;
        let chain_pem = String::from_utf8(a.body).map_err(|_| AcmeError::Certificate)?;
        let chain = x509::pem_chain(&chain_pem, MAX_CHAIN).map_err(|_| AcmeError::Certificate)?;
        let leaf = x509::read_leaf(chain.first().ok_or(AcmeError::Certificate)?)
            .map_err(|_| AcmeError::Certificate)?;
        let matches = leaf.public_point == point
            && leaf.dns_names.iter().any(|n| n == host)
            && leaf.not_before <= now_s.saturating_add(300)
            && leaf.not_after > now_s;
        if !matches {
            return Err(AcmeError::Certificate);
        }
        Ok(Issued {
            chain_pem,
            leaf,
            key_pkcs8,
        })
    }
}
