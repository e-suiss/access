//! First-contact tokens end to end on the real router, store and sequencer (E58, OP-156 m.3
//! (z), Ek B 4495): the realm's public issuer directory, a signed-in person's blind issuance,
//! the client's finalization into an RFC 9578 type `0x0002` token that the existing redemption
//! check accepts, the daily limit, and nothing kept that links a token to the person.

use access_crypto::blind_rsa;
use access_crypto::privacy_pass::{self, Issuer};
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::accounts::{change_status, create};
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_kernel::json::{b64url_decode, b64url_encode};
use axum::body::Body;
use axum::http::{Method, StatusCode};

use super::management::{Console, console, now, send};
use super::*;

const WHO: Actor<'static> = Actor {
    actor: "test",
    correlation: "first-contact",
};

/// The hosted login surface and the first-contact routes over one `Hosted`, as `main` mounts
/// them.
fn hosted_router(c: &Console) -> axum::Router {
    use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::app::local::LocalLimiter;
    use access_identity_account::app::login::LoginGate;
    use access_identity_account::domain::password::Argon2Params;
    use access_identity_account::domain::throttle::ThrottlePolicy;
    use access_identity_oauth::adapters::PgDirectory;
    use access_identity_oauth::app::Discovery as RealmDiscovery;
    use access_identity_session::domain::session::SessionPolicy;
    use access_identity_ui::adapters::Outbox;
    use access_identity_ui::app::Hosted;
    let w = &c.w;
    let hosted = Arc::new(Hosted {
        kits: crate::login::HsmKits::new(
            crate::login::RealmKeks::new(Arc::clone(&w.keys)),
            w.db.router.clone(),
            w.db.app.clone(),
            SessionPolicy::DEFAULT,
        ),
        db: w.db.app.clone(),
        products: w.db.reader.clone(),
        clock: SystemClock,
        messages: Outbox,
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(HasherConfig::sized(
            Argon2Params::CANONICAL,
            cores(),
            cgroup_memory_budget(),
        )),
        redirect_to: String::from("/"),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        risk: access_identity_session::app::RiskServices::without_sources(),
        signup: access_identity_ui::app::signup::Signup::without_providers().unwrap(),
    });
    let discovery = || {
        RealmDiscovery::new(
            PgDirectory::new(w.db.router.clone()),
            SignerKeys::new(w.identity_signer.clone()),
        )
    };
    access_http::login::router(discovery(), hosted.clone(), None).merge(
        access_http::login::first_contact_router(discovery(), hosted),
    )
}

fn call(
    method: &Method,
    path: &str,
    cookie: Option<&str>,
    body: &str,
) -> axum::http::Request<Body> {
    let mut b = axum::http::Request::builder()
        .method(method.clone())
        .uri(format!("/realms/acme{path}"))
        .header(axum::http::header::HOST, "access.test");
    if let Some(c) = cookie {
        b = b.header(
            axum::http::header::COOKIE,
            format!("__Host-access-session={c}"),
        );
    }
    if *method != Method::GET {
        b = b
            .header(axum::http::header::ORIGIN, "https://access.test")
            .header("sec-fetch-site", "same-origin")
            .header(
                "idempotency-key",
                b64url_encode(&access_crypto::random::bytes::<16>().unwrap()),
            )
            .header(axum::http::header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

/// An active account of the realm with a live session; its cookie.
async fn signed_in(c: &Console, address: &str) -> ([u8; 16], String) {
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let v = crate::login::RealmKeks::new(c.w.keys.clone())
        .vault(c.route.realm)
        .unwrap();
    let realm = Realm {
        tenant: c.route.tenant,
        realm: c.route.realm,
        kek: &*v.kek,
        ids: &ids,
    };
    let db = PgAccounts::sealed(c.w.db.app.clone(), v.clone());
    let email = Identifier::new(IdentifierKind::Email, address).unwrap();
    let subject = create(&db, &realm, &[email], &WHO).await.unwrap();
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(&db, &realm, subject, to, &WHO).await.unwrap();
    }
    let value: [u8; 32] = access_crypto::random::bytes().unwrap();
    let at = now();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    t.insert_session(&access_store::sessions::NewSession {
        cookie_hash: &access_identity_session::domain::session::cookie_digest(&value),
        subject,
        session_epoch: 0,
        keep_signed_in: false,
        created_ms: i64::try_from(at).unwrap(),
        auth_time_ms: i64::try_from(at).unwrap(),
        idle_ms: 3_600_000,
        expires_ms: i64::try_from(at + 3_600_000).unwrap(),
        assurance: &serde_json::to_vec(&access_identity_session::domain::assurance::vector(&[
            access_identity_session::domain::assurance::Factor::password(at),
        ]))
        .unwrap(),
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    (subject, b64url_encode(&value))
}

/// The client side of one token (RFC 9578 §6.1): its input, blinded request and the inverse.
struct Pending {
    input: Vec<u8>,
    blinded: blind_rsa::Blinded,
}

fn prepare(token_key: &[u8], challenge: &[u8; 32]) -> Pending {
    let n = blind_rsa::token_key_modulus(token_key).unwrap();
    let nonce: [u8; 32] = access_crypto::random::bytes().unwrap();
    let mut input = privacy_pass::TOKEN_TYPE.to_be_bytes().to_vec();
    input.extend_from_slice(&nonce);
    input.extend_from_slice(challenge);
    input.extend_from_slice(&privacy_pass::token_key_id(token_key));
    let blinded = blind_rsa::blind(n, &input).unwrap();
    Pending { input, blinded }
}

fn request(key_id: &[u8; 32], p: &Pending) -> String {
    serde_json::json!({
        "token_type": 2,
        "truncated_key_id": key_id[31],
        "blinded_msg": b64url_encode(&p.blinded.message),
    })
    .to_string()
}

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap()
}

// E58, OP-156 m.3 (z), RFC 9578 §6, Ek B 4495
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "a person's tokens from the directory to the daily limit"
)]
async fn first_contact_tokens_are_blind_unlinkable_limited_and_produce_no_authority() {
    let c = console("first-contact", false).await;
    let app = hosted_router(&c);
    let (pia, cookie) = signed_in(&c, "pia@example.com").await;
    let (_, other) = signed_in(&c, "ozan@example.com").await;

    // OP-156 m.3 (z)
    let period = access_identity_account::app::first_contact::PERIOD_MS;
    let (old, _) = blind_rsa::IssuerKey::generate().unwrap();
    let old_key = old.token_key();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let previous = i64::try_from(now() / period).unwrap() - 1;
    assert!(
        t.insert_first_contact_key(&access_store::first_contact::FirstContactKey {
            period: previous,
            token_key_id: privacy_pass::token_key_id(&old_key),
            token_key: old_key.clone(),
            sealed_key: vec![0],
        })
        .await
        .unwrap()
    );
    t.commit().await.unwrap();

    // RFC 9578 §4
    let (r, body) = send(&app, call(&Method::GET, "/v1/first-contact/keys", None, "")).await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let dir = json(&body);
    assert_eq!(dir["issuer-request-uri"], "tokens");
    assert_eq!(dir["daily-limit"], 20);
    let keys = dir["token-keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "{dir}");
    assert_eq!(keys[0]["token-type"], 2);
    assert_eq!(
        keys[1]["token-key"].as_str().unwrap(),
        b64url_encode(&old_key)
    );
    assert_eq!(
        keys[0]["not-before"].as_u64().unwrap() - keys[1]["not-before"].as_u64().unwrap(),
        period / 1000
    );
    let token_key = b64url_decode(keys[0]["token-key"].as_str().unwrap()).unwrap();
    let key_id = privacy_pass::token_key_id(&token_key);
    let issuers = [Issuer {
        key: blind_rsa::token_key_public(&token_key).unwrap().to_vec(),
        key_id,
    }];
    let (_, again) = send(&app, call(&Method::GET, "/v1/first-contact/keys", None, "")).await;
    assert_eq!(
        json(&again)["token-keys"],
        dir["token-keys"],
        "one key per period"
    );
    let challenge = privacy_pass::challenge_digest("relay.example", &[], "relay.example");
    let head = c.w.domains.head(c.domain).await.unwrap().0;

    // G57
    let p = prepare(&token_key, &challenge);
    let (r, _) = send(
        &app,
        call(
            &Method::POST,
            "/v1/first-contact/tokens",
            None,
            &request(&key_id, &p),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // E58
    let mut tokens = Vec::new();
    let mut seen_blinded = Vec::new();
    for (who, p) in [
        (&cookie, prepare(&token_key, &challenge)),
        (&cookie, prepare(&token_key, &challenge)),
        (&other, prepare(&token_key, &challenge)),
    ] {
        let (r, body) = send(
            &app,
            call(
                &Method::POST,
                "/v1/first-contact/tokens",
                Some(who),
                &request(&key_id, &p),
            ),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let sig = b64url_decode(json(&body)["blind_sig"].as_str().unwrap()).unwrap();
        let authenticator = blind_rsa::finalize(
            blind_rsa::token_key_modulus(&token_key).unwrap(),
            &p.input,
            &p.blinded,
            &sig,
        )
        .unwrap();
        let mut token = p.input.clone();
        token.extend_from_slice(&authenticator);
        assert!(privacy_pass::verify(&token, &challenge, &issuers));
        seen_blinded.push(p.blinded.message.to_vec());
        tokens.push(token);
    }
    // E58
    for t in &tokens {
        assert_eq!(&t[66..98], key_id.as_slice());
    }
    assert_ne!(tokens[0][2..34], tokens[1][2..34]);
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let dump = format!("{:?}", t.list_audit(200).await.unwrap());
    t.commit().await.unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    for t in &tokens {
        assert!(!dump.contains(&hex(&t[2..34])) && !dump.contains(&hex(&t[98..])));
    }
    for b in &seen_blinded {
        assert!(!dump.contains(&hex(b)));
    }

    // RFC 9578 §6.2
    let old_id = privacy_pass::token_key_id(&old_key);
    if old_id[31] != key_id[31] {
        let p = prepare(&old_key, &challenge);
        let (r, body) = send(
            &app,
            call(
                &Method::POST,
                "/v1/first-contact/tokens",
                Some(&cookie),
                &request(&old_id, &p),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["code"], "token-key-unknown");
    }
    let p = prepare(&token_key, &challenge);
    let mut wrong = key_id;
    wrong[31] ^= 0xff;
    let (r, body) = send(
        &app,
        call(
            &Method::POST,
            "/v1/first-contact/tokens",
            Some(&cookie),
            &request(&wrong, &p),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["code"], "token-key-unknown");
    let bad = serde_json::json!({
        "token_type": 1,
        "truncated_key_id": key_id[31],
        "blinded_msg": b64url_encode(&p.blinded.message),
    })
    .to_string();
    let (r, body) = send(
        &app,
        call(
            &Method::POST,
            "/v1/first-contact/tokens",
            Some(&cookie),
            &bad,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["code"], "invalid-token-request");

    // OP-156 m.3 (z)
    for _ in 2..20 {
        let p = prepare(&token_key, &challenge);
        let (r, _) = send(
            &app,
            call(
                &Method::POST,
                "/v1/first-contact/tokens",
                Some(&cookie),
                &request(&key_id, &p),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
    }
    let p = prepare(&token_key, &challenge);
    let (r, body) = send(
        &app,
        call(
            &Method::POST,
            "/v1/first-contact/tokens",
            Some(&cookie),
            &request(&key_id, &p),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json(&body)["code"], "first-contact-limit");
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let day = i32::try_from(now() / 86_400_000).unwrap();
    assert_eq!(t.first_contact_issued(pia, day).await.unwrap(), 20);
    let audit = t.list_audit(200).await.unwrap();
    t.commit().await.unwrap();
    let count = |e: &str| audit.iter().filter(|a| a.event_type == e).count();
    assert_eq!(count("first_contact.tokens_issued"), 21);
    assert_eq!(count("first_contact.limit_reached"), 1);

    // E58
    assert_eq!(c.w.domains.head(c.domain).await.unwrap().0, head);
}
