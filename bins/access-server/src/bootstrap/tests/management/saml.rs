//! The SAML identity provider and WS-Federation through the real routers (OP-155 m.3 (c) to
//! (f), OP-153 m.3 (gg), §10.6.1, IDI-7, IDP-15, MD-10, Ek B 4760-4775, 4781, 4790, 4947, 4974,
//! 4994): service providers and the gateway are registered by REST as `idp.*` decisions; the
//! browser reaches `/realms/acme/saml/*` and `/realms/acme/wsfed` with a real session; the forward
//! reaches a gateway stand-in that redeems the handle over the mutual-TLS edge channel against
//! the real edge router; every signature comes from the real identity signer. The stand-in only
//! replaces the parser worker, which needs the Linux lockdown (its real-process run is
//! `bins/access-gw-saml/tests/real.rs` in the CI sandbox job): it returns the facts the worker
//! would read from the request the test sent.

#![allow(
    clippy::similar_names,
    clippy::format_collect,
    clippy::needless_pass_by_value,
    reason = "test code"
)]

use std::sync::Mutex;

use access_edge_core::EdgeCore;
use access_edge_core::channel::{Channel, ChannelConfig, ChannelError};
use access_edge_core::saml::{Facts, Kind, Signed};
use access_identity_saml::sp::b64;
use access_identity_saml::wire::{Attest, Done, Forward};
use access_identity_saml::{time as stime, uri};
use access_internal_api::edge::Call;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

const SESSION_COOKIE: &str = "__Host-access-session";

struct Ca {
    pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

fn ca() -> Ca {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let pem = params.self_signed(&key).unwrap().pem();
    Ca {
        pem,
        issuer: rcgen::Issuer::new(params, key),
    }
}

/// A gateway client certificate: PEM chain, PEM key, SHA-256 hex.
fn leaf(ca: &Ca, uri: &str) -> (String, String, String) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    let digest = suiss_crypto::digest::sha256(cert.der());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    (cert.pem(), key.serialize_pem(), hex)
}

/// What the stand-in answers for the next forward: the worker's facts, or a worker refusal.
type Script = Arc<Mutex<Option<Result<Facts, String>>>>;

struct Idp {
    c: Console,
    saml: axum::Router,
    script: Script,
    edge_addr: std::net::SocketAddr,
    server_roots: String,
    gateway: (String, String),
    issuer: String,
    cookie: String,
}

impl Idp {
    async fn new(label: &str) -> Self {
        let c = console(label, false).await;
        let ca = ca();
        let (chain, key, digest) = leaf(&ca, "urn:suiss:access:gw:saml:gw1");
        let w = c
            .rest_write(
                &Method::POST,
                "/admin/v1/realms/acme/gateways",
                ("registerGateway", None),
                serde_json::json!({ "kind": "saml", "name": "gw1", "cert_sha256": digest }),
                None,
            )
            .await;
        assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);

        let keks = crate::login::RealmKeks::new(Arc::clone(&c.w.keys));
        let forward = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forward_addr = forward.local_addr().unwrap();
        let saml = Arc::new(crate::saml::Saml::new(
            c.w.db.app.clone(),
            c.w.identity_signer.clone(),
            Some(crate::saml::GatewayAddr(forward_addr.to_string())),
            Arc::clone(&c.w.keys),
            keks.clone(),
        ));

        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let config = access_http::tls::server_config(
            server.cert.pem().as_bytes(),
            server.signing_key.serialize_pem().as_bytes(),
            Some(ca.pem.as_bytes()),
        )
        .unwrap();
        let edge = access_http::harden(
            crate::edge::routes(
                c.w.db.router.clone(),
                c.w.db.app.clone(),
                keks,
                saml.clone(),
            ),
            access_http::Limits::default(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_addr = listener.local_addr().unwrap();
        tokio::spawn(access_http::tls::serve(
            listener,
            config,
            edge,
            std::future::pending(),
        ));

        let script: Script = Arc::new(Mutex::new(None));
        let channel = channel(edge_addr, &server.cert.pem(), &chain, &key);
        tokio::spawn(stand_in(forward, channel, Arc::clone(&script)));

        let hosted = super::super::vault::Lab::hosted(&c.w);
        let discovery = access_identity_oauth::app::Discovery::new(
            PgDirectory::new(c.w.db.router.clone()),
            SignerKeys::new(c.w.identity_signer.clone()),
        );
        let saml_router = access_http::login::saml_router::<_, _, _, _, _, crate::saml::Saml>(
            discovery, hosted, saml,
        );

        let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
            .await
            .unwrap();
        let issuer = access_store::idp::governance(&mut t)
            .await
            .unwrap()
            .unwrap()
            .issuer
            .unwrap();
        let value: [u8; 32] = access_crypto::random::bytes().unwrap();
        let at = now();
        t.insert_session(&NewSession {
            cookie_hash: &cookie_digest(&value),
            subject: c.subject,
            session_epoch: 0,
            keep_signed_in: false,
            created_ms: i64::try_from(at).unwrap(),
            auth_time_ms: i64::try_from(at).unwrap(),
            idle_ms: 3_600_000,
            expires_ms: i64::try_from(at + 3_600_000).unwrap(),
            assurance: &serde_json::to_vec(&vector(&[Factor::password(at)])).unwrap(),
        })
        .await
        .unwrap();
        t.commit().await.unwrap();
        Self {
            c,
            saml: saml_router,
            script,
            edge_addr,
            server_roots: server.cert.pem(),
            gateway: (chain, key),
            issuer,
            cookie: format!("{SESSION_COOKIE}={}", b64url_encode(&value)),
        }
    }

    async fn register(&self, body: serde_json::Value) {
        let w = self
            .c
            .rest_write(
                &Method::POST,
                "/admin/v1/realms/acme/saml-sps",
                ("registerSamlSp", None),
                body,
                None,
            )
            .await;
        assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    }

    fn facts(&self, entity: &str, id: &str, acs: &str) -> Facts {
        Facts {
            kind: Kind::Authn,
            id: String::from(id),
            issue_instant: stime::format(now()),
            destination: Some(format!("{}/saml/sso", self.issuer.trim_end_matches('/'))),
            issuer: String::from(entity),
            acs_url: Some(String::from(acs)),
            acs_index: None,
            protocol_binding: Some(String::from(uri::BINDING_POST)),
            force_authn: false,
            is_passive: false,
            nameid_format: None,
            allow_create: None,
            sp_name_qualifier: None,
            requester_ids: vec![String::from("urn:requester:portal")],
            proxy_count: None,
            signed: Signed::Absent,
            name_id: None,
            session_indexes: vec![],
            soap: false,
        }
    }

    async fn get(&self, target: &str, signed_in: bool) -> (Response<Body>, String) {
        let mut req = Request::get(target).header(header::HOST, HOST);
        if signed_in {
            req = req.header(header::COOKIE, &self.cookie);
        }
        let (r, body) = send(&self.saml, req.body(Body::empty()).unwrap()).await;
        (r, String::from_utf8_lossy(&body).into_owned())
    }

    /// A redirect-binding sign-in whose worker reads `facts`.
    async fn sso(&self, facts: Facts, signed_in: bool) -> (Response<Body>, String) {
        *self.script.lock().unwrap() = Some(Ok(facts));
        let message = binding_value(b"<samlp:AuthnRequest/>");
        self.get(
            &format!("/realms/acme/saml/sso?SAMLRequest={message}&RelayState=r1"),
            signed_in,
        )
        .await
    }

    async fn audit(&self) -> Vec<String> {
        let mut t = TenantTx::begin(&self.c.w.db.app, self.c.route.tenant, self.c.route.realm)
            .await
            .unwrap();
        let rows = t.list_audit(10_000).await.unwrap();
        t.commit().await.unwrap();
        rows.into_iter().map(|r| r.event_type).collect()
    }

    async fn core(&self) -> EdgeCore {
        EdgeCore::connect(channel(
            self.edge_addr,
            &self.server_roots,
            &self.gateway.0,
            &self.gateway.1,
        ))
        .await
        .unwrap()
    }
}

fn binding_value(xml: &[u8]) -> String {
    access_identity_saml::binding::encode(&b64::encode(xml))
}

fn channel(addr: std::net::SocketAddr, roots: &str, chain: &str, key: &str) -> Channel {
    Channel::new(&ChannelConfig {
        addr: addr.to_string(),
        server_name: String::from("localhost"),
        roots_pem: roots.as_bytes().to_vec(),
        chain_pem: chain.as_bytes().to_vec(),
        key_pem: key.as_bytes().to_vec(),
    })
    .unwrap()
}

/// The gateway's part of a forward, with the worker's facts scripted: `sp` for the certificates,
/// then `issue` with the handle, over the real edge channel.
async fn stand_in(listener: tokio::net::TcpListener, channel: Channel, script: Script) {
    let mut core: Option<EdgeCore> = None;
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            return;
        };
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 8192];
        let body = loop {
            let n = s.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..at]).to_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                while buf.len() < at + 4 + len {
                    let n = s.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                }
                break buf[at + 4..at + 4 + len].to_vec();
            }
        };
        let f = Forward::decode(&body).unwrap();
        if core.is_none() {
            core = Some(EdgeCore::connect(channel.clone()).await.unwrap());
        }
        let edge = core.as_ref().unwrap();
        let scripted = script.lock().unwrap().take();
        let done = match (f.binding, scripted) {
            (
                access_identity_saml::wire::Binding::Unsolicited
                | access_identity_saml::wire::Binding::Wsfed,
                _,
            ) => issue(edge, &f, None).await,
            (_, Some(Ok(facts))) => {
                let sp = Attest::Sp {
                    realm: f.realm.clone(),
                    entity: facts.issuer.clone(),
                };
                edge.raw(Call::SessionAttest, &sp.encode()).await.unwrap();
                issue(edge, &f, Some(facts.encode().unwrap())).await
            }
            (_, Some(Err(code))) => Done::Refused(code),
            (_, None) => Done::Refused(String::from("worker-failed")),
        };
        let out = done.encode();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            out.len()
        );
        s.write_all(head.as_bytes()).await.unwrap();
        s.write_all(&out).await.unwrap();
    }
}

async fn issue(edge: &EdgeCore, f: &Forward, facts: Option<Vec<u8>>) -> Done {
    let a = Attest::Issue {
        realm: f.realm.clone(),
        handle: f.handle,
        facts,
        redirect_signed: false,
    };
    match edge.raw(Call::SessionAttest, &a.encode()).await {
        Ok(_) => Done::Done,
        Err(access_edge_core::EdgeError::Channel(ChannelError::Refused { code, .. })) => {
            Done::Refused(code)
        }
        Err(e) => panic!("{e:?}"),
    }
}

fn field(page: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let at = page.find(&marker).unwrap() + marker.len();
    let end = page[at..].find('"').unwrap();
    page[at..at + end]
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
}

fn response_xml(page: &str) -> String {
    String::from_utf8(b64::decode(&field(page, "SAMLResponse")).unwrap()).unwrap()
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> &'a str {
    let at = s.find(open).unwrap() + open.len();
    let end = s[at..].find(close).unwrap();
    &s[at..at + end]
}

fn name_id(xml: &str) -> &str {
    let inner = between(xml, "<saml:NameID ", "</saml:NameID>");
    assert!(inner.contains("nameid-format:persistent"), "{inner}");
    inner.split_once('>').unwrap().1
}

fn sp(name: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut v = serde_json::json!({
        "name": name,
        "entity_id": format!("https://{name}.sp.test/metadata"),
        "acs": [{ "url": format!("https://{name}.sp.test/acs"), "index": 0, "binding": "post", "default": true }],
        "attributes": [{ "name": "urn:oid:0.9.2342.19200300.100.1.3", "friendly_name": "mail", "source": "email" }],
    });
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

// IDI-7, CVE-2022-39299, IDP-15, MD-10, IDP-24, Ek B 4760
#[tokio::test]
async fn idi_7_signed_responses_come_only_from_an_attested_session() {
    let idp = Idp::new("saml-sso").await;
    idp.register(sp("alpha", serde_json::json!({}))).await;
    idp.register(sp("beta", serde_json::json!({}))).await;

    // IDI-7
    let core = idp.core().await;
    let forged = Attest::Issue {
        realm: String::from("acme"),
        handle: access_crypto::random::bytes().unwrap(),
        facts: None,
        redirect_signed: false,
    };
    match core.raw(Call::SessionAttest, &forged.encode()).await {
        Err(access_edge_core::EdgeError::Channel(ChannelError::Refused { status, code })) => {
            assert_eq!((status, code.as_str()), (403, "edge-attest"));
        }
        other => panic!("{other:?}"),
    }

    let alpha = "https://alpha.sp.test/metadata";
    let (r, _) = idp
        .sso(idp.facts(alpha, "_a1", "https://alpha.sp.test/acs"), false)
        .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let to = location(&r);
    assert!(
        to.starts_with("/realms/acme/login?return_to=%2Frealms%2Facme%2Fsaml%2Fsso%3Fflow%3D"),
        "{to}"
    );

    let passive = Facts {
        is_passive: true,
        force_authn: true,
        ..idp.facts(alpha, "_a2", "https://alpha.sp.test/acs")
    };
    let (r, page) = idp.sso(passive, false).await;
    assert_eq!(r.status(), StatusCode::OK, "{page}");
    let xml = response_xml(&page);
    assert!(xml.contains(uri::STATUS_NO_PASSIVE));
    assert!(!xml.contains("ds:Signature") && !xml.contains("saml:Assertion"));

    // IDP-15
    let before = idp
        .audit()
        .await
        .iter()
        .filter(|e| *e == "saml.signed")
        .count();
    let (r, page) = idp
        .sso(idp.facts(alpha, "_a3", "https://alpha.sp.test/acs/"), true)
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(page.contains("saml-acs-mismatch") && !page.contains("SAMLResponse"));

    let (r, page) = idp
        .sso(idp.facts(alpha, "_a4", "https://alpha.sp.test/acs"), true)
        .await;
    assert_eq!(r.status(), StatusCode::OK, "{page}");
    let csp = r.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(
        csp.contains("script-src 'nonce-") && csp.contains("form-action https://alpha.sp.test")
    );
    assert!(page.contains("action=\"https://alpha.sp.test/acs\""));
    assert_eq!(field(&page, "RelayState"), "r1");
    let xml = response_xml(&page);
    assert_eq!(xml.matches("<ds:Signature xmlns:ds=").count(), 2);
    assert!(xml.contains("Destination=\"https://alpha.sp.test/acs\""));
    assert!(xml.contains("InResponseTo=\"_a4\""));
    assert!(xml.contains("<saml:Audience>https://alpha.sp.test/metadata</saml:Audience>"));
    assert!(xml.contains("xmldsig-more#rsa-sha256"));
    assert!(xml.contains(uri::AC_PPT));
    let alpha_id = String::from(name_id(&xml));
    assert_eq!(alpha_id.len(), 43);
    let after = idp.audit().await;
    assert_eq!(
        after.iter().filter(|e| *e == "saml.signed").count(),
        before + 2
    );
    assert!(after.iter().any(|e| e == "saml.requester"));

    let (r, page) = idp
        .sso(idp.facts(alpha, "_a4", "https://alpha.sp.test/acs"), true)
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(page.contains("saml-replay"));

    // MD-10
    let (_, page) = idp
        .sso(
            idp.facts(
                "https://beta.sp.test/metadata",
                "_b1",
                "https://beta.sp.test/acs",
            ),
            true,
        )
        .await;
    let beta_id = String::from(name_id(&response_xml(&page)));
    assert_ne!(alpha_id, beta_id);
    let (_, page) = idp
        .sso(idp.facts(alpha, "_a5", "https://alpha.sp.test/acs"), true)
        .await;
    assert!(response_xml(&page).contains(&alpha_id));

    let unknown = idp
        .sso(
            idp.facts("https://nobody.test", "_n1", "https://nobody.test/acs"),
            true,
        )
        .await;
    assert!(unknown.1.contains("saml-unknown-sp"));
    idp.c.w.domains.release().await;
}

// IDP-15, Ek B 4774
#[tokio::test]
async fn unsolicited_sso_needs_the_opt_in() {
    let idp = Idp::new("saml-idp-init").await;
    idp.register(sp("closed", serde_json::json!({}))).await;
    idp.register(sp(
        "open",
        serde_json::json!({ "allow_idp_initiated": true }),
    ))
    .await;
    let (r, page) = idp.get("/realms/acme/saml/sso/closed", true).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(page.contains("saml-unsolicited"));
    let (r, page) = idp.get("/realms/acme/saml/sso/open", true).await;
    assert_eq!(r.status(), StatusCode::OK, "{page}");
    let xml = response_xml(&page);
    assert!(!xml.contains("InResponseTo"));
    assert!(xml.contains("Destination=\"https://open.sp.test/acs\""));
    let (r, page) = idp
        .get("/realms/acme/saml/sso/open?RelayState=%2Fapp", true)
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(page.contains("saml-relay-state"));

    // IDP-28, IDP-40, Ek B 4779, 4780, 4935
    let mut slack = sp("slack", serde_json::json!({ "template": "slack" }));
    slack["entity_id"] = serde_json::json!("https://slack.com");
    let w = idp
        .c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/saml-sps",
            ("registerSamlSp", None),
            slack.clone(),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::BAD_REQUEST, "{}", w.body);
    assert_eq!(w.body["code"], "invalid-saml-sp");
    slack["attributes"] = serde_json::json!([{ "name": "User.Email", "source": "email" }]);
    idp.register(slack).await;
    let list = idp.c.admin_get("/admin/v1/realms/acme/saml-sps").await;
    let item = list.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "slack")
        .unwrap()
        .clone();
    assert_eq!(item["nameid_format"], "persistent");
    assert_eq!(item["status"], "live");
    idp.c.w.domains.release().await;
}

// §10.6.1, MD-7, Ek B 4782, 4761
#[tokio::test]
async fn single_logout_signs_out_locally_and_answers_the_sp() {
    let idp = Idp::new("saml-slo").await;
    idp.register(sp(
        "gone",
        serde_json::json!({ "slo": [{ "url": "https://gone.sp.test/slo", "binding": "redirect" }] }),
    ))
    .await;
    let entity = "https://gone.sp.test/metadata";
    let logout = Facts {
        kind: Kind::Logout,
        acs_url: None,
        protocol_binding: None,
        requester_ids: vec![],
        name_id: Some(String::from("opaque")),
        session_indexes: vec![String::from("_s1")],
        ..idp.facts(entity, "_l1", "")
    };
    *idp.script.lock().unwrap() = Some(Ok(logout));
    let message = binding_value(b"<samlp:LogoutRequest/>");
    let (r, _) = idp
        .get(
            &format!("/realms/acme/saml/slo?SAMLRequest={message}&RelayState=back"),
            true,
        )
        .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let to = location(&r);
    assert!(
        to.starts_with("https://gone.sp.test/slo?SAMLResponse="),
        "{to}"
    );
    assert!(to.contains("&RelayState=back&SigAlg=") && to.contains("&Signature="));
    let cleared = r.headers().get_all(header::SET_COOKIE).iter().any(|v| {
        v.to_str()
            .unwrap()
            .starts_with(&format!("{SESSION_COOKIE}=;"))
    });
    assert!(cleared);
    let (r, _) = idp
        .sso(idp.facts(entity, "_g1", "https://gone.sp.test/acs"), true)
        .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(location(&r).contains("/login?return_to="));
    idp.c.w.domains.release().await;
}

// §10.6.1, CR-4, Ek B 4765
#[tokio::test]
async fn an_encrypted_assertion_opens_with_the_sp_key() {
    use aws_lc_rs::rsa::{
        KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey,
    };
    let idp = Idp::new("saml-enc").await;
    let key = aws_lc_rs::rsa::KeyPair::generate(KeySize::Rsa2048).unwrap();
    let pkcs8 =
        aws_lc_rs::encoding::AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&key).unwrap();
    let rc = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let cert = rcgen::CertificateParams::new(vec![String::from("enc.sp.test")])
        .unwrap()
        .self_signed(&rc)
        .unwrap();
    idp.register(sp(
        "enc",
        serde_json::json!({ "encrypt_assertion": true, "encryption_certificate": b64::encode(cert.der()) }),
    ))
    .await;
    let (r, page) = idp
        .sso(
            idp.facts(
                "https://enc.sp.test/metadata",
                "_e1",
                "https://enc.sp.test/acs",
            ),
            true,
        )
        .await;
    assert_eq!(r.status(), StatusCode::OK, "{page}");
    let xml = response_xml(&page);
    assert!(xml.contains("<saml:EncryptedAssertion"));
    assert!(xml.contains("xmlenc11#aes256-gcm") && xml.contains("xmlenc11#rsa-oaep"));
    assert!(!xml.contains("rsa-1_5") && !xml.contains("EncryptedAttribute"));
    let values: Vec<&str> = xml
        .split("<xenc:CipherValue>")
        .skip(1)
        .map(|s| s.split('<').next().unwrap())
        .collect();
    let wrapped = b64::decode(values[0]).unwrap();
    let body = b64::decode(values[1]).unwrap();
    let oaep =
        OaepPrivateDecryptingKey::new(PrivateDecryptingKey::from_pkcs8(pkcs8.as_ref()).unwrap())
            .unwrap();
    let mut k = vec![0; oaep.min_output_size()];
    let k = oaep
        .decrypt(&OAEP_SHA256_MGF1SHA256, &wrapped, &mut k, None)
        .unwrap()
        .to_vec();
    let opening = aws_lc_rs::aead::LessSafeKey::new(
        aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::AES_256_GCM, &k).unwrap(),
    );
    let (nonce, rest) = body.split_at(12);
    let mut rest = rest.to_vec();
    let plain = opening
        .open_in_place(
            aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce).unwrap(),
            aws_lc_rs::aead::Aad::empty(),
            &mut rest,
        )
        .unwrap();
    let assertion = String::from_utf8(plain.to_vec()).unwrap();
    assert!(assertion.starts_with("<saml:Assertion xmlns:saml="));
    assert!(assertion.contains("<ds:Signature"));
    idp.c.w.domains.release().await;
}

// §10.6.1, Ek B 4763
#[tokio::test]
async fn metadata_is_signed_and_ws_federation_issues_a_token() {
    let idp = Idp::new("saml-meta").await;
    let (r, doc) = idp.get("/realms/acme/saml/metadata", false).await;
    assert_eq!(r.status(), StatusCode::OK, "{doc}");
    assert!(doc.starts_with("<md:EntityDescriptor"));
    assert!(doc.contains("cacheDuration=\"PT6H\"") && doc.contains("validUntil=\""));
    assert!(doc.contains("<md:KeyDescriptor use=\"signing\">"));
    assert!(doc.contains("<ds:Signature") && doc.contains("xmldsig-more#rsa-sha256"));
    let (_, again) = idp.get("/realms/acme/saml/metadata", false).await;
    assert_ne!(doc, again);

    idp.register(sp(
        "legacy",
        serde_json::json!({ "protocol": "wsfed-saml11" }),
    ))
    .await;
    let (r, page) = idp
        .get(
            "/realms/acme/wsfed?wa=wsignin1.0&wtrealm=https%3A%2F%2Flegacy.sp.test%2Fmetadata&wreply=https%3A%2F%2Flegacy.sp.test%2Facs&wctx=c1",
            true,
        )
        .await;
    assert_eq!(r.status(), StatusCode::OK, "{page}");
    assert_eq!(field(&page, "wa"), "wsignin1.0");
    assert_eq!(field(&page, "wctx"), "c1");
    let wresult = field(&page, "wresult")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    assert!(wresult.contains("<t:RequestSecurityTokenResponse"));
    assert!(wresult.contains("MajorVersion=\"1\"") && wresult.contains("<ds:Signature"));
    let (r, _) = idp
        .get("/realms/acme/wsfed?wa=wsignin1.0&wtrealm=https%3A%2F%2Flegacy.sp.test%2Fmetadata&wreply=https%3A%2F%2Fevil.test%2F", true)
        .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    idp.c.w.domains.release().await;
}
