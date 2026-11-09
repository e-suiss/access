//! The hosted consent of a CIMD client on the real server path (§11.6, P58, EI-18, OP-154 m.3
//! (k), OP-153 m.3 (gg)): the realm's CIMD policy and protected resource are REST writes, the
//! person's own `grant.issue` is committed through the real ADP router with their device
//! Instance's AIS, and the consent record is kept only for that allowed Exercise, read back from
//! the authority plane. Revoking the Grant above it asks for consent again.

use access_authority_core::domain::Request as CoreRequest;
use access_kernel::meta::{self as kmeta, GrantBasis, GrantContent, Payload};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id,
    ResourceSelector, Structural, SubjectSelector, Window,
};
use access_store::clients::CimdSnapshot;
use access_store::identity::TenantTx;

use super::*;

const APP: &str = "https://app.example/client.json";
const CB: &str = "https://app.example/cb";
const MCP: &str = "https://mcp.example.com/mcp";
const VERIFIER_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn work_authority(depth: u64) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: std::collections::BTreeSet::from([ActionRef {
                    namespace: String::from("work"),
                    name: String::from("read"),
                    major: 1,
                    schema: Digest([3; 32]),
                }]),
                prefix: std::collections::BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: String::from("work"),
                prefix: Vec::new(),
                kind: None,
                attrs: std::collections::BTreeMap::new(),
            }),
            params: std::collections::BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            conditions: std::collections::BTreeSet::new(),
            budget: std::collections::BTreeSet::new(),
        },
        delegation: DelegationTerms {
            depth,
            downstream_holder_class: None,
        },
        requirements: std::collections::BTreeSet::new(),
    }
}

/// Commits the domain root's meta `payload` on the meta-anchor; the Exercise.
async fn root_commit(c: &Console, payload: Payload, party: Id) -> Digest {
    let root = root_key(&c.w.keys).unwrap();
    let at = server_time(&c.w.db.app).await.unwrap();
    let intent = access_internal_api::instances::self_signed_intent(
        &payload,
        party,
        Window {
            from: at - 60_000,
            until: at + 600_000,
        },
    )
    .unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let basis = ExerciseBasis::Anchor(kmeta::meta_anchor(&c.domain));
    let ais = sign(
        &root,
        &Statement {
            domain: c.domain,
            nonce: nonce.clone(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
            basis,
            iat: at,
            exercise: None,
        },
    )
    .unwrap();
    MetaExercises::lead(&c.w.plane, c.domain).await.unwrap();
    let verdict = MetaExercises::meta(
        &c.w.plane,
        CoreRequest {
            domain: c.domain,
            mode: Mode::Commit,
            nonce,
            intent,
            payload: Some(payload),
            basis,
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        },
        ais,
        String::from(IDENTITY_PEP),
    )
    .await
    .unwrap();
    let Verdict::Committed(done) = verdict else {
        panic!("{verdict:?}");
    };
    assert!(c.w.domains.derive().await.is_empty());
    done.exercise
}

/// A live realm session of the console's person.
async fn session(c: &Console) -> String {
    let value: [u8; 32] = access_crypto::random::bytes().unwrap();
    let at = now();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
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
    b64url_encode(&value)
}

async fn authorize(c: &Console, query: &str, cookie: &str) -> (Response<Body>, Vec<u8>) {
    send(
        &c.oauth,
        Request::get(format!("/realms/acme/authorize?{query}"))
            .header(header::HOST, HOST)
            .header(header::COOKIE, format!("{SESSION}={cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn page(
    c: &Console,
    path: &str,
    cookie: &str,
    csrf: Option<&str>,
    body: &serde_json::Value,
) -> (Response<Body>, serde_json::Value) {
    let mut b = Request::post(format!("/realms/acme{path}"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("https://{HOST}"))
        .header("sec-fetch-site", "same-origin")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION}={cookie}"));
    if let Some(t) = csrf {
        b = b.header("x-csrf-token", t);
    }
    let (r, bytes) = send(&c.oauth, b.body(Body::from(body.to_string())).unwrap()).await;
    (
        r,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn query_of(url: &str, name: &str) -> Option<String> {
    Params::parse(url.split_once('?')?.1)
        .ok()?
        .get(name)
        .map(String::from)
}

// EI-18 §11.6 rule 1–5 P58 AS-M14 AG-6 Ek B 4246 4247 4248 4249 4251 4538 4539 4540 4541 4542
#[tokio::test]
async fn a_cimd_client_is_approved_only_by_the_persons_own_grant_issue() {
    let c = console("mgmt-consent", true).await;
    let w = c
        .put_setting(
            "cimd-policy",
            "putCimdPolicy",
            serde_json::json!({ "enabled": true, "domains": ["app.example"] }),
        )
        .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/resources",
            ("registerProtectedResource", None),
            serde_json::json!({ "resource": MCP, "display_name": "Example MCP" }),
            None,
        )
        .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let document =
        format!(r#"{{"client_id":"{APP}","client_name":"Example App","redirect_uris":["{CB}"]}}"#);
    let at = now();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    t.insert_cimd_client(
        APP,
        &CimdSnapshot {
            document: document.as_bytes(),
            document_hash: suiss_crypto::digest::sha256(document.as_bytes()),
            authority_hash: [1; 32],
            visual_hash: [2; 32],
            logo: None,
            fetched_ms: at,
            fresh_until_ms: at + 3_600_000,
        },
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let parent = root_commit(
        &c,
        Payload::GrantIssue(GrantContent {
            basis: GrantBasis::Anchor(kmeta::meta_anchor(&c.domain)),
            holder: SubjectSelector::Party(c.root),
            authority: work_authority(1),
            agency: std::collections::BTreeSet::from([Capacity::Own]),
            named: None,
        }),
        c.root,
    )
    .await;
    let cookie = session(&c).await;
    let enc = |v: &str| {
        let mut out = String::new();
        access_identity_oauth::domain::issuer::form_encode(v, &mut out);
        out
    };
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&resource={}&state=s1&code_challenge={VERIFIER_CHALLENGE}&code_challenge_method=S256",
        enc(APP),
        enc(CB),
        enc(MCP),
    );
    let (r, body) = authorize(&c, &query, &cookie).await;
    assert_eq!(
        r.status(),
        StatusCode::SEE_OTHER,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let login = location(&r);
    assert_eq!(query_of(&login, "reason").as_deref(), Some("approve"));
    // §11.6 rule 2, Ek B 4539
    assert!(
        r.headers().get(header::SET_COOKIE).is_none(),
        "no cookie before consent"
    );
    let return_to = query_of(&login, "return_to").unwrap();

    // §11.6 rule 5, Ek B 4541
    let (r, _) = page(
        &c,
        "/v1/login/approval/preview",
        "AAAA",
        None,
        &serde_json::json!({ "return_to": return_to }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let (r, view) = page(
        &c,
        "/v1/login/approval/preview",
        &cookie,
        None,
        &serde_json::json!({ "return_to": return_to }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "{view}");
    // §11.4.5 Ek B 4538
    assert_eq!(r.headers()[header::X_FRAME_OPTIONS], "DENY");
    assert!(
        r.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert!(r.headers().get(header::SET_COOKIE).is_none());
    // AS-M14, §11.3, Ek B 4247, 4249
    assert_eq!(view["client_host"], "app.example");
    assert_eq!(view["client_says"], "Example App");
    assert_eq!(view["redirect_hosts"], serde_json::json!(["app.example"]));
    assert_eq!(view["loopback_only"], false);
    assert_eq!(view["resource"], MCP);
    let csrf = view["csrf"].as_str().unwrap().to_owned();
    let draft = view["draft"].clone();
    assert_eq!(draft["intent"]["action"]["name"], "grant_issue", "{draft}");
    assert_eq!(
        draft["basis"]["holding"]["grant"],
        b64url_encode(&kmeta::object_id(&parent, kind::GRANT, 0).0)
    );

    // §11.4.5
    let (r, _) = page(
        &c,
        "/v1/login/approval",
        &cookie,
        None,
        &serde_json::json!({ "return_to": return_to, "domain": draft["domain"], "exercise": b64url_encode(&[5; 32]) }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // EI-18
    let elsewhere = root_commit(
        &c,
        Payload::GrantIssue(GrantContent {
            basis: GrantBasis::Anchor(kmeta::meta_anchor(&c.domain)),
            holder: SubjectSelector::Party(Id([0x42; 16])),
            authority: work_authority(0),
            agency: std::collections::BTreeSet::from([Capacity::Own]),
            named: None,
        }),
        Id([0x42; 16]),
    )
    .await;
    let (r, refused) = page(
        &c,
        "/v1/login/approval",
        &cookie,
        Some(&csrf),
        &serde_json::json!({ "return_to": return_to, "domain": draft["domain"], "exercise": b64url_encode(&elsewhere.0) }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(refused["code"], "consent-grant-required");

    // EI-18
    let envelope = draft["envelope"].as_str().unwrap();
    let basis = ExerciseBasis::Holding(kmeta::HoldingRef {
        grant: Id(<[u8; 16]>::try_from(
            b64url_decode(draft["basis"]["holding"]["grant"].as_str().unwrap()).unwrap(),
        )
        .unwrap()),
        holder: c.root,
        since: draft["basis"]["holding"]["since"].as_u64().unwrap(),
    });
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let pep = access_http::account::domain::ACCOUNT_PEP;
    let ais = c.browser.ais_for(
        pep,
        c.domain,
        &nonce,
        envelope_digest(envelope),
        Mode::Commit,
        basis,
    );
    let adp = access_http::adp::adapters::router(
        access_http::adp::app::Service::new(c.w.domains.clone(), 64 * 1024),
        access_http::adp::adapters::Discovery {
            issuer: String::from("https://access.test"),
        },
    );
    let body = serde_json::json!({
        "subject": { "type": "access_party", "id": b64url_encode(&c.root.0) },
        "action": { "name": "grant_issue" },
        "resource": { "type": draft["intent"]["resources"][0]["namespace"], "id": draft["intent"]["resources"][0]["path"][0] },
        "context": {
            "domain": draft["domain"],
            "mode": "commit",
            "nonce": b64url_encode(&nonce),
            "intent": draft["intent"],
            "payload": draft["payload"],
            "basis": draft["basis"],
            "capacity": "own",
            "ais": ais,
        },
    });
    let mut req = Request::post("/access/v1/evaluation")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut()
        .insert(access_http::adp::adapters::Pep(String::from(pep)));
    let (r, bytes) = send(&adp, req).await;
    let answer: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{answer}");
    assert_eq!(answer["decision"], true, "{answer}");
    let exercise = answer["context"]["exercise"].as_str().unwrap().to_owned();

    // EI-18, §11.6, P58, Ek B 4246, 4251, 4542
    let (r, ok) = page(
        &c,
        "/v1/login/approval",
        &cookie,
        Some(&csrf),
        &serde_json::json!({ "return_to": return_to, "domain": draft["domain"], "exercise": exercise }),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "{ok}");
    assert!(r.headers().get(header::SET_COOKIE).is_none());
    let back = ok["redirect_to"].as_str().unwrap().to_owned();
    let (r, _) = authorize(&c, back.split_once('?').unwrap().1, &cookie).await;
    let to = location(&r);
    assert!(
        to.starts_with(CB) && query_of(&to, "code").is_some(),
        "{to}"
    );
    // §11.6 rule 3, Ek B 4540
    let (r, _) = authorize(&c, back.split_once('?').unwrap().1, &cookie).await;
    assert!(
        r.headers()
            .get(header::LOCATION)
            .is_none_or(|l| !l.to_str().unwrap().starts_with(CB)),
        "the stored request is used once"
    );

    // §11.6 rule 1 P58
    let (r, _) = authorize(&c, &query, &cookie).await;
    assert!(location(&r).starts_with(CB), "{}", location(&r));
    root_commit(
        &c,
        Payload::GrantRevoke {
            grant: kmeta::object_id(&parent, kind::GRANT, 0),
        },
        c.root,
    )
    .await;
    let (r, _) = authorize(&c, &query, &cookie).await;
    assert_eq!(
        query_of(&location(&r), "reason").as_deref(),
        Some("approve"),
        "asked again once the Grant ended"
    );
    c.w.domains.release().await;
}
