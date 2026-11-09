//! A workload's first presentation on the real server (OP-154 m.3 (d), (r), U20, AG-30, L25,
//! OP-153 m.3 (gg)): a workload client registered by REST authenticates at the realm's token
//! endpoint with a JWT-SVID and a DPoP proof; the realm issuer's `identity_binding_workload`
//! Claim about its agent follows through the courier, and the key's own `instance_create`
//! stands on that Claim alone, while the Instance still has no authority without a Grant. A
//! trust domain the domain does not accept gets nothing.

use access_identity_account::domain::claims::workload_line;
use access_identity_admin::ports::{AgentRegistration, WorkloadInstance};
use access_internal_api::idp::{Submission, Verdict};
use access_internal_api::instances::{
    SelfSigned, bootstrap_basis, register_nonce, self_signed_intent, terminate_intent,
    terminate_payload,
};
use access_kernel::meta::{ActorKind, Payload, Root};
use access_kernel::model::{Id, Window};
use access_kernel::verify::cose::PublicKey;

use super::writes::Written;
use super::*;

pub(super) const AGENT: Id = Id([0x0e; 16]);
pub(super) const BUNDLE: &str = "https://bundle.acme.example/bundle.json";
const OTHER_BUNDLE: &str = "https://bundle.beta.example/bundle.json";
pub(super) const WORKLOAD: &str = "spiffe://acme.example/agent/mail/w1";
const ISSUER: &str = "https://access.test/realms/acme";
const TOKEN: &str = "https://access.test/realms/acme/token";

pub(super) fn signer() -> Browser {
    Browser {
        jar: Vec::new(),
        csrf: String::new(),
        key: SoftSigner::generate_p256().unwrap().0,
    }
}

fn window() -> Window {
    Window {
        from: now() - 60_000,
        until: now() + 600_000,
    }
}

fn xy(key: &PublicKey) -> (String, String) {
    let PublicKey::P256(sec1) = key else {
        panic!("not P-256");
    };
    (b64url_encode(&sec1[1..33]), b64url_encode(&sec1[33..65]))
}

fn jws(by: &SoftSigner, header: &serde_json::Value, claims: &serde_json::Value) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(claims.to_string().as_bytes())
    );
    let sig = by.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(&sig))
}

/// A trust domain's bundle with the JWT-SVID key `by`.
pub(super) fn bundle(by: &SoftSigner) -> String {
    let (x, y) = xy(&by.public_key());
    serde_json::json!({
        "keys": [{ "use": "jwt-svid", "kty": "EC", "crv": "P-256", "kid": "k1", "x": x, "y": y }],
        "spiffe_sequence": 1,
        "spiffe_refresh_hint": 300,
    })
    .to_string()
}

pub(super) fn svid(by: &SoftSigner, sub: &str) -> String {
    jws(
        by,
        &serde_json::json!({ "alg": "ES256", "kid": "k1", "typ": "JWT" }),
        &serde_json::json!({
            "sub": sub,
            "aud": [ISSUER],
            "exp": now() / 1000 + 120,
            "iat": now() / 1000,
            "jti": b64url_encode(&access_crypto::random::bytes::<16>().unwrap()),
        }),
    )
}

fn dpop(by: &SoftSigner, nonce: Option<&str>) -> String {
    let (x, y) = xy(&by.public_key());
    let mut claims = serde_json::json!({
        "jti": b64url_encode(&access_crypto::random::bytes::<16>().unwrap()),
        "htm": "POST",
        "htu": TOKEN,
        "iat": now() / 1000,
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::Value::from(n);
    }
    jws(
        by,
        &serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y },
        }),
        &claims,
    )
}

/// One `client_credentials` request at the realm's token endpoint with the JWT-SVID
/// `assertion` and a DPoP proof by `key` carrying `nonce`.
async fn token(
    c: &Console,
    assertion: &str,
    key: &SoftSigner,
    nonce: Option<&str>,
) -> (StatusCode, serde_json::Value, Option<String>) {
    let form = format!(
        "grant_type=client_credentials&client_assertion_type={}&client_assertion={assertion}",
        "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-spiffe",
    );
    let (r, body) = send(
        &c.oauth,
        Request::post("/realms/acme/token")
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("dpop", dpop(key, nonce))
            .body(Body::from(form))
            .unwrap(),
    )
    .await;
    let next = r
        .headers()
        .get("dpop-nonce")
        .map(|h| h.to_str().unwrap().to_owned());
    (
        r.status(),
        serde_json::from_slice(&body).unwrap_or_default(),
        next,
    )
}

/// `client_credentials` with a fresh JWT-SVID from `assertion` each time, retried once with
/// the nonce the server hands out (TN-29); the answer and the nonce to go on with.
pub(super) async fn present(
    c: &Console,
    assertion: &dyn Fn() -> String,
    key: &SoftSigner,
) -> (StatusCode, serde_json::Value, Option<String>) {
    let (status, body, nonce) = token(c, &assertion(), key, None).await;
    if body["error"] != "use_dpop_nonce" {
        return (status, body, nonce);
    }
    token(c, &assertion(), key, nonce.as_deref()).await
}

/// Registers the agent AGENT of the founder with the founder as its sponsor (OP-154 m.3 (c)).
pub(super) async fn agent(c: &Console) {
    let one_time = signer();
    let register = Payload::PartyRegister {
        party: AGENT,
        root: Root::Sole(c.root),
        actor_kind: ActorKind::Agent,
    };
    let nonce = register_nonce(&access_crypto::random::bytes::<32>().unwrap());
    let validity = window();
    let intent = self_signed_intent(&register, AGENT, validity).unwrap();
    let ais = b64url_decode(&one_time.ais(
        c.domain,
        &nonce,
        intent_digest(&intent).unwrap(),
        Mode::Commit,
        bootstrap_basis(&c.domain),
    ))
    .unwrap();
    let registered =
        c.w.plane
            .register_agent(AgentRegistration {
                tenant: *c.route.tenant.as_bytes(),
                domain: c.domain,
                party: AGENT,
                operator: c.root,
                key: one_time.key.public_key(),
                register: SelfSigned {
                    ais,
                    nonce,
                    validity,
                },
                pep: String::from(access_identity_ui::domain::frontend::IDENTITY_PEP),
            })
            .await
            .unwrap();
    assert!(
        matches!(
            registered,
            access_identity_admin::ports::OrgRegistered::Registered { .. }
        ),
        "{registered:?}"
    );
    let accounts = c.admin_get("/admin/v1/realms/acme/accounts").await;
    let sponsor = accounts.body["items"][0]["account_id"].clone();
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/agents",
            ("registerAgent", None),
            serde_json::json!({
                "agent": b64url_encode(&AGENT.0),
                "operator": b64url_encode(&c.root.0),
                "agent_kind": "cloud",
                "display_name": "Mail worker",
                "sponsors": [sponsor],
            }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
}

/// A workload client of AGENT selecting `spiffe_id`, by REST (OP-154 m.3 (r)).
pub(super) async fn workload_client(c: &Console, spiffe_id: &str, endpoint: &str) -> Written {
    c.rest_write(
        &Method::POST,
        "/admin/v1/realms/acme/clients",
        ("createClient", None),
        serde_json::json!({
            "display_name": "Mail worker",
            "token_endpoint_auth_method": "spiffe_jwt",
            "spiffe_id": spiffe_id,
            "spiffe_bundle_endpoint": endpoint,
            "agent": b64url_encode(&AGENT.0),
            "redirect_uris": [],
        }),
        None,
    )
    .await
}

/// Whether the realm issuer issued AGENT's workload binding of `key`.
async fn bound(c: &Console, key: &PublicKey) -> bool {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let issued = access_store::issuer::last_in_line(
        &mut t,
        &AGENT.0,
        &access_store::scope::DomainId::from_bytes(c.domain.0),
        &workload_line(&AGENT.0, &thumbprint(key)),
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    issued.is_some()
}

/// Steps the realm issuer's courier until AGENT's workload binding of `key` is issued.
pub(super) async fn issued(c: &Console, key: &PublicKey) {
    let k = super::super::recovery::courier(c);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !bound(c, key).await {
        let r = k.step().await.unwrap();
        assert!(std::time::Instant::now() < deadline, "{r:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The key `by` opens its own Instance of AGENT through `POST /v1/workloads/instances`
/// (OP-154 m.3 (d)): the Instance, or the refusal's status and code.
pub(super) async fn open(c: &Console, by: &Browser) -> Result<(Id, serde_json::Value), (StatusCode, String)> {
    let nonce = access_crypto::random::bytes::<32>().unwrap().to_vec();
    let validity = window();
    let r = WorkloadInstance {
        domain: c.domain,
        party: AGENT,
        key: by.key.public_key(),
        create: SelfSigned {
            nonce: nonce.clone(),
            validity,
            ais: Vec::new(),
        },
        pep: String::from(access_identity_ui::domain::frontend::IDENTITY_PEP),
    };
    let intent = self_signed_intent(&r.payload(), AGENT, validity).unwrap();
    let ais = by.ais(
        c.domain,
        &nonce,
        intent_digest(&intent).unwrap(),
        Mode::Commit,
        bootstrap_basis(&c.domain),
    );
    let router = access_http::login::workloads_router(
        access_identity_oauth::app::Discovery::new(
            access_identity_oauth::adapters::PgDirectory::new(c.w.db.router.clone()),
            access_identity_oauth::adapters::SignerKeys::new(c.w.identity_signer.clone()),
        ),
        super::super::vault::Lab::hosted(&c.w),
        c.w.plane.clone(),
        access_identity_ui::app::workloads::AttestRoots::embedded(),
    );
    let rfc = access_identity_ui::domain::frontend::rfc3339;
    let body = serde_json::json!({
        "party": b64url_encode(&AGENT.0),
        "key": b64url_encode(&access_internal_api::instances::cose_key(&by.key.public_key())),
        "nonce": b64url_encode(&nonce),
        "valid_from": rfc(validity.from),
        "valid_until": rfc(validity.until),
        "ais": ais,
    });
    let (resp, bytes) = send(
        &router,
        Request::post("/realms/acme/v1/workloads/instances")
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    let answer: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    if resp.status() != StatusCode::CREATED {
        return Err((
            resp.status(),
            answer["code"].as_str().unwrap_or_default().to_owned(),
        ));
    }
    let instance = Id(<[u8; 16]>::try_from(
        b64url_decode(answer["instance"].as_str().unwrap()).unwrap(),
    )
    .unwrap());
    Ok((instance, answer))
}

// U20, OP-154 m.3 (d), (r), AG-30, L25, L21, §11.21.1, OP-153 m.3 (gg), Ek B 4133, 4183, 4200, 4325, 4326, 4489, 4546
#[tokio::test]
async fn a_workload_presents_once_and_its_key_opens_an_instance_that_still_needs_a_grant() {
    let c = console("mgmt-workloads", true).await;
    agent(&c).await;
    let td = signer();
    c.bundles.serve(BUNDLE, &bundle(&td.key));
    // §11.12.1, MD-4
    let wildcard = workload_client(&c, "spiffe://acme.example/agent/*/w1", BUNDLE).await;
    assert_eq!(
        wildcard.status,
        StatusCode::BAD_REQUEST,
        "{}",
        wildcard.body
    );
    assert_eq!(wildcard.body["code"], "invalid-workload-client");
    let w = workload_client(&c, "spiffe://acme.example/agent/mail/*", BUNDLE).await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);

    let runtime = signer();
    c.trust
        .scripted
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, body, _) = present(&c, &|| svid(&td.key, WORKLOAD), &runtime.key).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_ne!(body["error"], "invalid_client", "{body}");
    issued(&c, &runtime.key.public_key()).await;

    // OP-154 m.3 (d)
    let stranger = signer();
    assert_eq!(
        open(&c, &stranger).await.unwrap_err(),
        (StatusCode::FORBIDDEN, String::from("workload-not-bound"))
    );
    let (instance, answer) = open(&c, &runtime).await.unwrap();
    assert_eq!(answer["party"], b64url_encode(&AGENT.0));
    assert_eq!(
        answer["kid"],
        b64url_encode(&thumbprint(&runtime.key.public_key()))
    );
    let live = c.w.plane.instances(c.domain, AGENT).await.unwrap();
    assert_eq!(live, vec![instance]);

    // §11.21.1, OP-154 m.3 (d)
    let root_instances = c.w.plane.instances(c.domain, c.root).await.unwrap();
    let target = root_instances[0];
    let validity = window();
    let intent = terminate_intent(target, validity).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let basis = c.idp_anchor();
    let ais = b64url_decode(&runtime.ais(
        c.domain,
        &nonce,
        intent_digest(&intent).unwrap(),
        Mode::Commit,
        basis,
    ))
    .unwrap();
    let v =
        c.w.plane
            .decide(Submission {
                domain: c.domain,
                nonce,
                intent,
                payload: Some(Box::new(terminate_payload(target))),
                basis,
                capacity: Capacity::Own,
                ais,
                contributions: Vec::new(),
                pep: String::from(access_identity_ui::domain::frontend::IDENTITY_PEP),
                actor: Some(AGENT),
            })
            .await
            .unwrap();
    assert!(!matches!(v, Verdict::Committed(_)), "{v:?}");

    // U20
    let view = c
        .admin_get(&format!(
            "/admin/v1/realms/acme/agents/{}",
            b64url_encode(&AGENT.0)
        ))
        .await;
    assert_eq!(view.status, StatusCode::OK, "{}", view.body);
    let text = view.body.to_string();
    assert!(
        !text.contains("spiffe") && !text.contains(WORKLOAD),
        "{text}"
    );
}

// OP-154 m.3 (r), AG-30, OP-153 m.3 (gg), Ek B 4133, 4546
#[tokio::test]
async fn a_trust_domain_without_acceptance_gets_no_instance() {
    let c = console("mgmt-workloads-td", true).await;
    agent(&c).await;
    let td = signer();
    c.bundles.serve(OTHER_BUNDLE, &bundle(&td.key));
    let w = workload_client(&c, "spiffe://beta.example/agent/mail/*", OTHER_BUNDLE).await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    let runtime = signer();
    let (status, body, _) = present(
        &c,
        &|| svid(&td.key, "spiffe://beta.example/agent/mail/w1"),
        &runtime.key,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    assert!(!bound(&c, &runtime.key.public_key()).await);
    assert_eq!(
        open(&c, &runtime).await.unwrap_err(),
        (StatusCode::FORBIDDEN, String::from("workload-not-bound"))
    );
    assert_eq!(
        c.w.plane.instances(c.domain, AGENT).await.unwrap(),
        Vec::<Id>::new()
    );
}

// OP-154 m.3 (r), AG-30, OP-153 m.3 (gg), Ek B 4133
#[tokio::test]
async fn a_bundle_older_than_twice_its_refresh_interval_refuses_jwt_svids() {
    let c = console("mgmt-workloads-stale", true).await;
    agent(&c).await;
    let td = signer();
    let w = workload_client(&c, "spiffe://acme.example/agent/mail/*", BUNDLE).await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    access_store::workloads::keep_bundle(
        &mut t,
        "acme.example",
        &access_store::workloads::KeptBundle {
            bundle_endpoint: String::from(BUNDLE),
            document: bundle(&td.key).into_bytes(),
            fetched_ms: now() - 601_000,
        },
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    c.trust
        .scripted
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let runtime = signer();
    let (status, body, _) = present(&c, &|| svid(&td.key, WORKLOAD), &runtime.key).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    c.bundles.serve(BUNDLE, &bundle(&td.key));
    let (status, body, _) = present(&c, &|| svid(&td.key, WORKLOAD), &runtime.key).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "{body}");
    // OP-154 m.3 (r)
    let (_, _, nonce) = present(&c, &|| svid(&td.key, WORKLOAD), &runtime.key).await;
    let once = svid(&td.key, WORKLOAD);
    let (status, body, nonce) = token(&c, &once, &runtime.key, nonce.as_deref()).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, body, _) = token(&c, &once, &runtime.key, nonce.as_deref()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

/// The base64 of a DER certificate, as an `x5c` member holds it: its PEM body.
fn x5c(cert: &rcgen::Certificate) -> String {
    cert.pem()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
}

// OP-154 m.3 (r), §11.15, AG-30, AG-34, OP-153 m.3 (gg), Ek B 4133, 4447
#[tokio::test]
async fn an_x509_svid_over_mutual_tls_presents_the_workload() {
    let c = console("mgmt-workloads-x509", true).await;
    agent(&c).await;
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let root = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    c.bundles.serve(
        BUNDLE,
        &serde_json::json!({
            "keys": [{ "use": "x509-svid", "kty": "EC", "crv": "P-256", "x5c": [x5c(&root)] }],
            "spiffe_sequence": 1,
            "spiffe_refresh_hint": 300,
        })
        .to_string(),
    );
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/clients",
            ("createClient", None),
            serde_json::json!({
                "display_name": "Mail worker",
                "token_endpoint_auth_method": "spiffe_x509",
                "spiffe_id": "spiffe://acme.example/agent/mail/*",
                "spiffe_bundle_endpoint": BUNDLE,
                "agent": b64url_encode(&AGENT.0),
                "redirect_uris": [],
            }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    let mut leaf = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf.subject_alt_names = vec![rcgen::SanType::URI(WORKLOAD.try_into().unwrap())];
    leaf.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    leaf.is_ca = rcgen::IsCa::ExplicitNoCa;
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let chain: std::sync::Arc<[Vec<u8>]> = std::sync::Arc::from(vec![
        leaf.signed_by(&leaf_key, &issuer).unwrap().der().to_vec(),
    ]);
    c.trust
        .scripted
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let runtime = signer();
    let mtls = |client_id: &str, nonce: Option<String>| {
        let form = format!(
            "grant_type=client_credentials&client_id={}",
            client_id.replace(':', "%3A").replace('/', "%2F")
        );
        Request::post("/realms/acme/token")
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("dpop", dpop(&runtime.key, nonce.as_deref()))
            .extension(access_http::tls::ClientChain(chain.clone()))
            .body(Body::from(form))
            .unwrap()
    };
    let (r, body) = send(&c.oauth, mtls(WORKLOAD, None)).await;
    let first: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    assert_ne!(r.status(), StatusCode::UNAUTHORIZED, "{first}");
    let nonce = r
        .headers()
        .get("dpop-nonce")
        .map(|h| h.to_str().unwrap().to_owned());
    let (r, body) = send(&c.oauth, mtls(WORKLOAD, nonce.clone())).await;
    assert_ne!(
        r.status(),
        StatusCode::UNAUTHORIZED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    issued(&c, &runtime.key.public_key()).await;
    assert!(open(&c, &runtime).await.is_ok());
    // RFC 8705 §2.1
    let (r, _) = send(&c.oauth, mtls("spiffe://acme.example/agent/mail/w2", nonce)).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}
