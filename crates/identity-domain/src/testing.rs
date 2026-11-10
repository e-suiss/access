//! Test doubles for custom domains (OP-156 m.3 (i)): the in-process ACME twin, which checks
//! every JWS, nonce and CSR and validates TLS-ALPN-01 through the test's probe of a real TLS
//! listener; a DNS double; an in-memory challenge board; a software account key; and a pause
//! that does not wait. CI runs the same client against Pebble.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::unused_async_trait_impl,
    clippy::needless_pass_by_value,
    clippy::type_complexity,
    clippy::too_many_lines,
    clippy::single_match_else,
    reason = "test doubles"
)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_kernel::json::{b64url_decode, b64url_encode};
use access_parse::der::{Reader, SEQUENCE};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::{Signer as _, SoftSigner};

use crate::der;
use crate::ports::{AccountKey, AcmeHttp, Answer, Challenges, DnsProbe, Pause, Unavailable};
use crate::x509::{self, Profile, basic_constraints, key_usage, san, server_auth};

/// The base URL of the twin's directory.
pub const TWIN_ORIGIN: &str = "https://acme-twin.test";

/// The twin's directory URL.
pub const TWIN_DIRECTORY: &str = "https://acme-twin.test/dir";

/// A pause that does not wait.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPause;

impl Pause for NoPause {
    async fn pause(&self, _: Duration) {}
}

/// A software ACME account key.
pub struct SoftAccount(pub SoftSigner);

impl SoftAccount {
    /// A fresh P-256 account key.
    #[must_use]
    pub fn generate() -> Self {
        Self(SoftSigner::generate_p256().unwrap().0)
    }
}

impl AccountKey for SoftAccount {
    async fn public_point(&self) -> Result<Vec<u8>, Unavailable> {
        match self.0.public_key() {
            PublicKey::P256(p) => Ok(p),
            _ => Err(Unavailable(String::from("key"))),
        }
    }

    async fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Unavailable> {
        self.0
            .sign(input)
            .map_err(|_| Unavailable(String::from("sign")))
    }
}

/// The challenges published, by host.
#[derive(Default)]
pub struct MemChallenges(pub Mutex<HashMap<String, [u8; 32]>>);

impl Challenges for MemChallenges {
    async fn publish(&self, host: &str, digest: [u8; 32]) -> Result<(), Unavailable> {
        self.0.lock().unwrap().insert(host.to_owned(), digest);
        Ok(())
    }

    async fn withdraw(&self, host: &str) -> Result<(), Unavailable> {
        self.0.lock().unwrap().remove(host);
        Ok(())
    }
}

impl<T: Challenges> Challenges for Arc<T> {
    async fn publish(&self, host: &str, digest: [u8; 32]) -> Result<(), Unavailable> {
        (**self).publish(host, digest).await
    }

    async fn withdraw(&self, host: &str) -> Result<(), Unavailable> {
        (**self).withdraw(host).await
    }
}

/// DNS records set by the test.
#[derive(Default)]
pub struct FakeDns {
    /// TXT strings by name.
    pub txt: Mutex<HashMap<String, Vec<String>>>,
    /// CNAME targets by name.
    pub cname: Mutex<HashMap<String, Vec<String>>>,
    /// Whether the resolver answers.
    pub down: std::sync::atomic::AtomicBool,
}

impl FakeDns {
    /// Publishes both records of a registration.
    pub fn publish(&self, host: &str, challenge: &str, target: &str) {
        self.txt.lock().unwrap().insert(
            format!("{}.{host}", crate::domain::host::CHALLENGE_LABEL),
            vec![challenge.to_owned()],
        );
        self.cname
            .lock()
            .unwrap()
            .insert(host.to_owned(), vec![format!("{target}.")]);
    }

    /// Removes the TXT record of `host`.
    pub fn remove_challenge(&self, host: &str) {
        self.txt
            .lock()
            .unwrap()
            .remove(&format!("{}.{host}", crate::domain::host::CHALLENGE_LABEL));
    }

    fn answer(
        &self,
        map: &Mutex<HashMap<String, Vec<String>>>,
        name: &str,
    ) -> Result<Vec<String>, Unavailable> {
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Unavailable(String::from("dns down")));
        }
        Ok(map.lock().unwrap().get(name).cloned().unwrap_or_default())
    }
}

impl DnsProbe for FakeDns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, Unavailable> {
        self.answer(&self.txt, name)
    }

    async fn cname(&self, name: &str) -> Result<Vec<String>, Unavailable> {
        self.answer(&self.cname, name)
    }
}

impl<T: DnsProbe> DnsProbe for Arc<T> {
    async fn txt(&self, name: &str) -> Result<Vec<String>, Unavailable> {
        (**self).txt(name).await
    }

    async fn cname(&self, name: &str) -> Result<Vec<String>, Unavailable> {
        (**self).cname(name).await
    }
}

/// A TLS-ALPN-01 validation the test supplies: whether a listener answers `host` with the
/// challenge certificate of `digest`.
pub type Probe = Arc<
    dyn Fn(String, [u8; 32]) -> core::pin::Pin<Box<dyn core::future::Future<Output = bool> + Send>>
        + Send
        + Sync,
>;

/// How the twin validates a challenge.
#[derive(Clone)]
pub enum Validation {
    /// Over TLS-ALPN-01 to a real listener, through the test's probe.
    Alpn(Probe),
    /// Against what was published on this board, without a network.
    Board(Arc<MemChallenges>),
}

#[derive(Clone)]
struct OrderState {
    host: String,
    status: &'static str,
    authz: u64,
    cert: Option<u64>,
}

#[derive(Clone)]
struct AuthzState {
    host: String,
    status: &'static str,
    token: String,
    order: u64,
}

#[derive(Default)]
struct State {
    next: u64,
    nonces: HashSet<String>,
    accounts: Vec<Vec<u8>>,
    orders: HashMap<u64, OrderState>,
    authz: HashMap<u64, AuthzState>,
    certs: HashMap<u64, String>,
    issued: u32,
    refuse_finalize: bool,
}

/// An in-process ACME server (RFC 8555 subset) that validates TLS-ALPN-01 for real.
pub struct AcmeTwin {
    state: Mutex<State>,
    validation: Validation,
    ca_key: SoftSigner,
    ca_der: Vec<u8>,
    lifetime_s: i64,
}

fn now_s() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn json_answer(
    status: u16,
    nonce: String,
    location: Option<String>,
    body: serde_json::Value,
) -> Answer {
    Answer {
        status,
        nonce: Some(nonce),
        location,
        retry_after_s: None,
        content_type: Some(String::from("application/json")),
        body: body.to_string().into_bytes(),
    }
}

fn problem(nonce: String, status: u16, kind: &str) -> Answer {
    json_answer(
        status,
        nonce,
        None,
        serde_json::json!({ "type": format!("urn:ietf:params:acme:error:{kind}") }),
    )
}

fn point_of_jwk(jwk: &serde_json::Value) -> Option<Vec<u8>> {
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return None;
    }
    let x = b64url_decode(jwk["x"].as_str()?).ok()?;
    let y = b64url_decode(jwk["y"].as_str()?).ok()?;
    (x.len() == 32 && y.len() == 32).then(|| [vec![4], x, y].concat())
}

/// The public point and dNSNames of a CSR whose signature verifies.
fn read_csr(csr: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
    let mut outer = Reader::new(csr).ok()?;
    let mut parts = Reader::new(outer.tagged(SEQUENCE).ok()?).ok()?;
    let info = parts.tagged(SEQUENCE).ok()?;
    parts.tagged(SEQUENCE).ok()?;
    let sig = parts.tagged(der::BIT_STRING).ok()?;
    let mut cri = Reader::new(info).ok()?;
    cri.tagged(der::INTEGER).ok()?;
    cri.tagged(SEQUENCE).ok()?;
    let mut spki = Reader::new(cri.tagged(SEQUENCE).ok()?).ok()?;
    spki.tagged(SEQUENCE).ok()?;
    let point = spki.tagged(der::BIT_STRING).ok()?.get(1..)?.to_vec();
    let raw = der::ecdsa_raw(sig.get(1..)?).ok()?;
    suiss_crypto::sig::p256(&PureBackend, &point, &der::tlv(SEQUENCE, info), &raw, false).ok()?;
    let attrs = cri.tagged(0xa0).ok()?;
    let mut attr = Reader::new(Reader::new(attrs).ok()?.tagged(SEQUENCE).ok()?).ok()?;
    attr.tagged(der::OID).ok()?;
    let mut set = Reader::new(attr.tagged(der::SET).ok()?).ok()?;
    let mut exts = Reader::new(set.tagged(SEQUENCE).ok()?).ok()?;
    let mut names = Vec::new();
    while !exts.is_empty() {
        let mut ext = Reader::new(exts.tagged(SEQUENCE).ok()?).ok()?;
        let id = ext.tagged(der::OID).ok()?;
        let value = ext.tagged(der::OCTET_STRING).ok()?;
        if id == der::SUBJECT_ALT_NAME {
            let mut gn = Reader::new(Reader::new(value).ok()?.tagged(SEQUENCE).ok()?).ok()?;
            while !gn.is_empty() {
                let n = gn.next_tlv().ok()?;
                if n.tag == 0x82 {
                    names.push(String::from_utf8(n.value.to_vec()).ok()?);
                }
            }
        }
    }
    Some((point, names))
}

impl AcmeTwin {
    /// A twin validating through `validation`, issuing 90-day certificates.
    #[must_use]
    pub fn new(validation: Validation) -> Self {
        let (ca_key, _) = SoftSigner::generate_p256().unwrap();
        let PublicKey::P256(point) = ca_key.public_key() else {
            panic!("p256");
        };
        let now = now_s();
        let ca_der = x509::certificate(
            &Profile {
                serial: &[1],
                subject: Some("Access ACME twin"),
                issuer: Some("Access ACME twin"),
                not_before: now - 86_400,
                not_after: now + 400 * 86_400,
                extensions: vec![basic_constraints(true), key_usage(true)],
            },
            &point,
            &ca_key,
        )
        .unwrap();
        Self {
            state: Mutex::new(State::default()),
            validation,
            ca_key,
            ca_der,
            lifetime_s: crate::domain::schedule::LIFETIME_S,
        }
    }

    /// This twin issuing certificates of `lifetime_s`.
    #[must_use]
    pub const fn with_lifetime(mut self, lifetime_s: i64) -> Self {
        self.lifetime_s = lifetime_s;
        self
    }

    /// The twin's CA certificate, DER: the trust anchor of what it issues.
    #[must_use]
    pub fn ca(&self) -> &[u8] {
        &self.ca_der
    }

    /// Certificates issued so far.
    #[must_use]
    pub fn issued(&self) -> u32 {
        self.state.lock().unwrap().issued
    }

    /// Makes every finalize fail from now on (or not).
    pub fn refuse_finalize(&self, refuse: bool) {
        self.state.lock().unwrap().refuse_finalize = refuse;
    }

    fn nonce(s: &mut State) -> String {
        let n = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
        s.nonces.insert(n.clone());
        n
    }

    fn url(path: &str) -> String {
        format!("{TWIN_ORIGIN}{path}")
    }

    /// Checks a request's JWS; returns the account index (or `None` for a new account's key),
    /// the payload, and the key.
    fn verify(
        s: &mut State,
        url: &str,
        body: &[u8],
    ) -> Result<(Option<usize>, Vec<u8>, Vec<u8>), &'static str> {
        let jws: serde_json::Value = serde_json::from_slice(body).map_err(|_| "malformed")?;
        let protected = jws["protected"].as_str().ok_or("malformed")?;
        let payload = jws["payload"].as_str().ok_or("malformed")?;
        let sig = b64url_decode(jws["signature"].as_str().ok_or("malformed")?)
            .map_err(|_| "malformed")?;
        let header: serde_json::Value =
            serde_json::from_slice(&b64url_decode(protected).map_err(|_| "malformed")?)
                .map_err(|_| "malformed")?;
        if header["alg"] != "ES256" || header["url"] != url {
            return Err("malformed");
        }
        let nonce = header["nonce"].as_str().ok_or("badNonce")?;
        if !s.nonces.remove(nonce) {
            return Err("badNonce");
        }
        let (account, point) = match (header.get("jwk"), header.get("kid")) {
            (Some(jwk), None) => (None, point_of_jwk(jwk).ok_or("badPublicKey")?),
            (None, Some(kid)) => {
                let kid = kid.as_str().ok_or("malformed")?;
                let i: usize = kid
                    .strip_prefix(&Self::url("/acct/"))
                    .and_then(|n| n.parse().ok())
                    .ok_or("accountDoesNotExist")?;
                (
                    Some(i),
                    s.accounts.get(i).cloned().ok_or("accountDoesNotExist")?,
                )
            }
            _ => return Err("malformed"),
        };
        let input = format!("{protected}.{payload}");
        suiss_crypto::sig::p256(&PureBackend, &point, input.as_bytes(), &sig, false)
            .map_err(|_| "unauthorized")?;
        let payload = b64url_decode(payload).map_err(|_| "malformed")?;
        Ok((account, payload, point))
    }

    fn order_json(o: &OrderState, id: u64) -> serde_json::Value {
        let mut v = serde_json::json!({
            "status": o.status,
            "identifiers": [{ "type": "dns", "value": o.host }],
            "authorizations": [Self::url(&format!("/authz/{}", o.authz))],
            "finalize": Self::url(&format!("/finalize/{id}")),
        });
        if let Some(c) = o.cert {
            v["certificate"] = serde_json::json!(Self::url(&format!("/cert/{c}")));
        }
        v
    }

    fn authz_json(a: &AuthzState, id: u64) -> serde_json::Value {
        serde_json::json!({
            "status": a.status,
            "identifier": { "type": "dns", "value": a.host },
            "challenges": [
                { "type": "http-01", "url": Self::url(&format!("/chall-http/{id}")), "token": a.token, "status": "pending" },
                { "type": "tls-alpn-01", "url": Self::url(&format!("/chall/{id}")), "token": a.token,
                  "status": if a.status == "valid" { "valid" } else if a.status == "invalid" { "invalid" } else { "pending" } },
            ],
        })
    }

    async fn validate(&self, host: &str, digest: [u8; 32]) -> bool {
        match &self.validation {
            Validation::Alpn(probe) => probe(host.to_owned(), digest).await,
            Validation::Board(b) => b.0.lock().unwrap().get(host) == Some(&digest),
        }
    }

    fn issue(&self, s: &mut State, host: &str, point: &[u8]) -> u64 {
        let now = now_s();
        let serial = access_crypto::random::bytes::<16>().unwrap();
        let leaf = x509::certificate(
            &Profile {
                serial: &serial,
                subject: Some(host),
                issuer: Some("Access ACME twin"),
                not_before: now - 60,
                not_after: now - 60 + self.lifetime_s,
                extensions: vec![
                    san(&[host]),
                    server_auth(),
                    basic_constraints(false),
                    key_usage(false),
                ],
            },
            point,
            &self.ca_key,
        )
        .unwrap();
        s.next += 1;
        let id = s.next;
        s.certs.insert(
            id,
            format!("{}{}", x509::pem(&leaf), x509::pem(&self.ca_der)),
        );
        s.issued += 1;
        id
    }

    async fn handle_post(&self, url: &str, body: &[u8]) -> Answer {
        let path = url.strip_prefix(TWIN_ORIGIN).unwrap_or_default().to_owned();
        let verified = {
            let mut s = self.state.lock().unwrap();
            let v = Self::verify(&mut s, url, body);
            let n = Self::nonce(&mut s);
            (v, n)
        };
        let (checked, nonce) = verified;
        let (account, payload, point) = match checked {
            Ok(v) => v,
            Err(kind) => return problem(nonce, 400, kind),
        };
        if path == "/acct" {
            let mut s = self.state.lock().unwrap();
            let i = match s.accounts.iter().position(|p| *p == point) {
                Some(i) => i,
                None => {
                    s.accounts.push(point);
                    s.accounts.len() - 1
                }
            };
            return json_answer(
                201,
                nonce,
                Some(Self::url(&format!("/acct/{i}"))),
                serde_json::json!({ "status": "valid" }),
            );
        }
        if account.is_none() {
            return problem(nonce, 400, "malformed");
        }
        let (kind, id) = match path.trim_start_matches('/').split_once('/') {
            Some((k, i)) => (k.to_owned(), i.parse::<u64>().unwrap_or(0)),
            None => (path.trim_start_matches('/').to_owned(), 0),
        };
        match kind.as_str() {
            "order" if id == 0 => {
                let ask: serde_json::Value = serde_json::from_slice(&payload).unwrap_or_default();
                let Some(host) = ask["identifiers"][0]["value"].as_str().map(String::from) else {
                    return problem(nonce, 400, "malformed");
                };
                let mut s = self.state.lock().unwrap();
                s.next += 2;
                let (oid, aid) = (s.next - 1, s.next);
                let token = b64url_encode(&access_crypto::random::bytes::<32>().unwrap());
                s.authz.insert(
                    aid,
                    AuthzState {
                        host: host.clone(),
                        status: "pending",
                        token,
                        order: oid,
                    },
                );
                let o = OrderState {
                    host,
                    status: "pending",
                    authz: aid,
                    cert: None,
                };
                let body = Self::order_json(&o, oid);
                s.orders.insert(oid, o);
                json_answer(201, nonce, Some(Self::url(&format!("/order/{oid}"))), body)
            }
            "order" => {
                let s = self.state.lock().unwrap();
                match s.orders.get(&id) {
                    Some(o) => json_answer(200, nonce, None, Self::order_json(o, id)),
                    None => problem(nonce, 404, "malformed"),
                }
            }
            "authz" => {
                let s = self.state.lock().unwrap();
                match s.authz.get(&id) {
                    Some(a) => json_answer(200, nonce, None, Self::authz_json(a, id)),
                    None => problem(nonce, 404, "malformed"),
                }
            }
            "chall" => {
                let a = self.state.lock().unwrap().authz.get(&id).cloned();
                let Some(a) = a else {
                    return problem(nonce, 404, "malformed");
                };
                let ka = crate::acme::jws::key_authorization(&a.token, &point).unwrap();
                let ok = self
                    .validate(&a.host, crate::acme::jws::alpn_digest(&ka))
                    .await;
                let mut s = self.state.lock().unwrap();
                let status = if ok { "valid" } else { "invalid" };
                if let Some(x) = s.authz.get_mut(&id) {
                    x.status = status;
                }
                if let Some(o) = s.orders.get_mut(&a.order) {
                    o.status = if ok { "ready" } else { "invalid" };
                }
                json_answer(
                    200,
                    nonce,
                    None,
                    serde_json::json!({ "type": "tls-alpn-01", "status": if ok { "processing" } else { "invalid" }, "url": url, "token": a.token }),
                )
            }
            "finalize" => {
                let ask: serde_json::Value = serde_json::from_slice(&payload).unwrap_or_default();
                let csr = ask["csr"]
                    .as_str()
                    .and_then(|c| b64url_decode(c).ok())
                    .unwrap_or_default();
                let mut s = self.state.lock().unwrap();
                let Some(o) = s.orders.get(&id).cloned() else {
                    return problem(nonce, 404, "malformed");
                };
                if o.status != "ready" || s.refuse_finalize {
                    return problem(nonce, 403, "orderNotReady");
                }
                let Some((cert_point, names)) = read_csr(&csr) else {
                    return problem(nonce, 400, "badCSR");
                };
                if names != [o.host.clone()] {
                    return problem(nonce, 400, "badCSR");
                }
                let cert = self.issue(&mut s, &o.host, &cert_point);
                let o = s.orders.get_mut(&id).unwrap();
                o.status = "valid";
                o.cert = Some(cert);
                let body = Self::order_json(o, id);
                json_answer(200, nonce, None, body)
            }
            "cert" => {
                let s = self.state.lock().unwrap();
                match s.certs.get(&id) {
                    Some(pem) => Answer {
                        status: 200,
                        nonce: Some(nonce),
                        location: None,
                        retry_after_s: None,
                        content_type: Some(String::from(crate::acme::wire::PEM_CHAIN)),
                        body: pem.clone().into_bytes(),
                    },
                    None => problem(nonce, 404, "malformed"),
                }
            }
            _ => problem(nonce, 404, "malformed"),
        }
    }
}

impl AcmeHttp for AcmeTwin {
    async fn get(&self, url: &str, _: usize) -> Result<Answer, Unavailable> {
        if url != TWIN_DIRECTORY {
            return Ok(Answer {
                status: 404,
                ..Answer::default()
            });
        }
        Ok(Answer {
            status: 200,
            body: serde_json::json!({
                "newNonce": Self::url("/nonce"),
                "newAccount": Self::url("/acct"),
                "newOrder": Self::url("/order"),
            })
            .to_string()
            .into_bytes(),
            ..Answer::default()
        })
    }

    async fn head(&self, _: &str) -> Result<Answer, Unavailable> {
        let nonce = Self::nonce(&mut self.state.lock().unwrap());
        Ok(Answer {
            status: 200,
            nonce: Some(nonce),
            ..Answer::default()
        })
    }

    async fn post(&self, url: &str, body: &[u8], _: usize) -> Result<Answer, Unavailable> {
        Ok(self.handle_post(url, body).await)
    }
}

impl<T: AcmeHttp> AcmeHttp for Arc<T> {
    async fn get(&self, url: &str, max: usize) -> Result<Answer, Unavailable> {
        (**self).get(url, max).await
    }

    async fn head(&self, url: &str) -> Result<Answer, Unavailable> {
        (**self).head(url).await
    }

    async fn post(&self, url: &str, body: &[u8], max: usize) -> Result<Answer, Unavailable> {
        (**self).post(url, body, max).await
    }
}

/// The root store holding only the twin's CA.
#[must_use]
pub fn twin_roots(twin: &AcmeTwin) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(twin.ca().to_vec()))
        .unwrap();
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::acme::Client;

    // RFC 8555 §7, RFC 8737, OP-156 m.3 (i)
    #[tokio::test]
    async fn the_client_gets_a_certificate_for_its_own_key_from_the_twin() {
        let board = Arc::new(MemChallenges::default());
        let twin = AcmeTwin::new(Validation::Board(board.clone()));
        let key = SoftAccount::generate();
        let client = Client {
            http: &twin,
            key: &key,
            pause: &NoPause,
            directory: TWIN_DIRECTORY,
            contact: Some("mailto:ops@acme.example"),
        };
        let issued = client
            .issue("login.acme.example", now_s(), &board)
            .await
            .unwrap();
        assert_eq!(issued.leaf.dns_names, ["login.acme.example"]);
        assert!(
            issued.leaf.not_after - issued.leaf.not_before
                >= crate::domain::schedule::LIFETIME_S - 60
        );
        assert_eq!(board.0.lock().unwrap().len(), 0);
        assert_eq!(twin.issued(), 1);
        twin.refuse_finalize(true);
        let refused = client.issue("login.acme.example", now_s(), &board).await;
        assert!(matches!(refused, Err(crate::acme::AcmeError::Refused(_))));
    }

    // RFC 8737 §3
    #[tokio::test]
    async fn an_unanswered_challenge_fails_the_order() {
        let board = Arc::new(MemChallenges::default());
        let twin = AcmeTwin::new(Validation::Board(Arc::new(MemChallenges::default())));
        let key = SoftAccount::generate();
        let client = Client {
            http: &twin,
            key: &key,
            pause: &NoPause,
            directory: TWIN_DIRECTORY,
            contact: None,
        };
        let out = client.issue("login.acme.example", now_s(), &board).await;
        assert_eq!(out.err().map(|e| e.code()), Some("acme-invalid"));
    }
}
