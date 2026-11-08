//! Data subject rights end to end against the real sequencer, router and token (OP-153 m.3
//! (aa), (bb), (gg)): an administrator's `idp.account.delete` through the management API with the
//! browser's AIS, the cancellation window, the tombstone and its 404, a hold that keeps the keys
//! past their delay, and the destruction with its proof that leaves the rows and the blind index.

#![allow(
    clippy::many_single_char_names,
    reason = "test code; short names for the console, transaction and vault"
)]

use access_authority_core::genesis::IDP_ANCHOR;
use access_http::console::domain::read_intent;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::accounts::{change_status, create};
use access_identity_account::app::privacy;
use access_identity_account::app::vault::{self, Vault};
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::ports::{AccountDb, AccountTx};
use access_kernel::combinator::Mode;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, kind};
use access_store::privacy::NewHold;
use access_store::testing::{DeletionStep, age_deletion};
use axum::body::Body;
use axum::http::{Method, StatusCode};

use super::management::{Console, console, now, send};
use super::*;

const WHO: Actor<'static> = Actor {
    actor: "test",
    correlation: "test",
};

fn vault_of(c: &Console) -> Vault {
    crate::login::RealmKeks::new(c.w.keys.clone())
        .vault(c.route.realm)
        .unwrap()
}

// TN-76, TN-77, TN-78, U58, OP-42, OP-73, OP-74 m.3, OP-147 m.2, HL-9, OP-153 m.3 (aa), (bb), (gg)
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one account's whole erasure, step by step"
)]
async fn an_account_deletion_runs_from_the_exercise_to_destruction_with_proof() {
    let c = console("privacy-delete", false).await;
    let route = c.route.clone();
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let keks = crate::login::RealmKeks::new(c.w.keys.clone());
    let v = vault_of(&c);
    let realm = Realm {
        tenant: route.tenant,
        realm: route.realm,
        kek: &*v.kek,
        ids: &ids,
    };
    let db = PgAccounts::sealed(c.w.db.app.clone(), v.clone());
    let email = Identifier::new(IdentifierKind::Email, "Erin@Example.com").unwrap();
    let victim = create(&db, &realm, &[email], &WHO).await.unwrap();
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(&db, &realm, victim, to, &WHO).await.unwrap();
    }
    let mut tx = db.begin(route.tenant, route.realm).await.unwrap();
    vault::set_profile(&mut tx.0, &v, victim, "name", "Erin Example")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let account = realm.external(victim).unwrap();

    // TN-110, OP-153 m.3 (bb)
    let domain = c.domain;
    let basis = ExerciseBasis::Anchor(access_kernel::meta::object_id(
        &domain,
        kind::ANCHOR,
        IDP_ANCHOR,
    ));
    let ask = serde_json::json!({"operation": "deleteAccount", "key": account}).to_string();
    let proof = c.browser.ais(
        domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::POST, "/admin/v1/realms/acme/intents"),
        Mode::Check,
        basis,
    );
    let (r, body) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                "/console/api/proxy/admin/realms/acme/intents",
                "x",
            )
            .header("x-access-ais", proof)
            .body(Body::from(ask))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let draft: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let digest = Digest(
        <[u8; 32]>::try_from(b64url_decode(draft["intent_digest"].as_str().unwrap()).unwrap())
            .unwrap(),
    );
    let before = c.w.domains.head(domain).await.unwrap().0;
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let ais = c.browser.ais(domain, &nonce, digest, Mode::Commit, basis);
    let (r, body) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                &format!("/console/api/proxy/admin/realms/acme/accounts/{account}/delete"),
                "x",
            )
            .header("x-access-ais", ais)
            .header("idempotency-key", b64url_encode(&nonce))
            .body(Body::from(draft["body"].to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let written: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let position: u64 = written["position"].as_str().unwrap().parse().unwrap();
    assert!(position > before, "one recorded Exercise");

    let mut t = TenantTx::begin(&c.w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let d = t.deletions(victim).await.unwrap();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].source, "admin");
    assert!(d[0].deleted_ms.is_none(), "inside the cancellation window");
    assert!(
        d[0].effective_ms - d[0].requested_ms >= 86_400_000 - 5_000,
        "the CT3 delay is the cancellation window"
    );
    let requests = t
        .data_requests(Some(victim), true, [0; 16], 10)
        .await
        .unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].kind, "erasure");
    // KVKK m.13, TN-78
    assert!(requests[0].due_ms - requests[0].received_ms <= 30 * 86_400_000);
    assert_eq!(
        t.subject(victim, false).await.unwrap().unwrap().status,
        "active"
    );
    t.commit().await.unwrap();

    // TN-76 m.2, TN-78
    age_deletion(&c.w.db, victim, DeletionStep::Effective)
        .await
        .unwrap();
    let pass = crate::retention::tick(
        (&c.w.db.app, &c.w.db.router),
        &keks,
        &ids,
        (crate::retention::RETENTION, "privacy-test"),
        now(),
    )
    .await
    .unwrap();
    assert_eq!(pass.tombstoned, 1, "{pass:?}");
    assert_eq!(pass.destroyed, 0, "the destruction delay runs");
    let mut t = TenantTx::begin(&c.w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    assert_eq!(
        t.subject(victim, false).await.unwrap().unwrap().status,
        "tombstone"
    );
    assert!(
        access_store::idp::realm::account(&mut t, victim)
            .await
            .unwrap()
            .is_none(),
        "a deleted account is not found, never gone"
    );
    t.commit().await.unwrap();

    // OP-74 m.3, OP-147 m.2
    let mut t = TenantTx::begin(&c.w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let hold = t
        .insert_hold(&NewHold {
            scope: "subject",
            subject: Some(victim),
            classes: &[],
            kind: "litigation",
            suspicious_activity: false,
            until_ms: None,
        })
        .await
        .unwrap();
    t.commit().await.unwrap();
    age_deletion(&c.w.db, victim, DeletionStep::DestroyAfter)
        .await
        .unwrap();
    let mut kept = crate::retention::Pass::default();
    crate::retention::retain_realm(&c.w.db.app, &keks, &ids, &route, &mut kept)
        .await
        .unwrap();
    assert_eq!(
        (kept.destroyed, kept.kept),
        (0, 1),
        "the hold keeps the keys past their period"
    );
    let mut t = TenantTx::begin(&c.w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    assert!(
        t.subject_key(victim, "contact")
            .await
            .unwrap()
            .unwrap()
            .wrapped_dek
            .is_some()
    );
    assert!(t.end_hold(hold).await.unwrap());
    t.commit().await.unwrap();

    // U58, TN-77, OP-42, HL-9
    let mut after = crate::retention::Pass::default();
    crate::retention::retain_realm(&c.w.db.app, &keks, &ids, &route, &mut after)
        .await
        .unwrap();
    assert_eq!(after.destroyed, 1, "{after:?}");
    let mut tx = db.begin(route.tenant, route.realm).await.unwrap();
    let row = tx.subject(victim, false).await.unwrap().unwrap();
    assert_eq!(row.status, "purging");
    assert!(row.wrapped_dek.is_none());
    let ident = tx.0.identifiers(victim).await.unwrap();
    assert_eq!(ident.len(), 1, "the row stays");
    assert_eq!(tx.reveal(victim, &ident[0].stored).await.unwrap(), None);
    assert_eq!(
        vault::profile(&mut tx.0, &v, victim).await.unwrap(),
        Vec::<(String, String)>::new()
    );
    assert_eq!(
        tx.subject_by_identifier("erin@example.com").await.unwrap(),
        Some(victim),
        "the blind index stays as the tombstone"
    );
    let fact = tx.0.deletions(victim).await.unwrap().remove(0);
    let proof = fact.proof.unwrap();
    assert!(fact.destroyed_ms.is_some());
    let audit =
        tx.0.history(
            &format!("{account}:proof:{}", {
                use std::fmt::Write as _;
                proof.iter().fold(String::new(), |mut s, b| {
                    let _ = write!(s, "{b:02x}");
                    s
                })
            }),
            0,
            10,
        )
        .await
        .unwrap();
    assert_eq!(audit.len(), 1, "the audit chain carries the proof");
    assert_eq!(audit[0].event_type, "account.destroyed");
    tx.commit().await.unwrap();
}

/// The realm's hosted surface over the token's realm keys, as `main` mounts it.
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
    });
    access_http::login::router(
        RealmDiscovery::new(
            PgDirectory::new(w.db.router.clone()),
            SignerKeys::new(w.identity_signer.clone()),
        ),
        hosted,
        None,
    )
}

fn call(method: &Method, path: &str, cookie: &str, body: &str) -> axum::http::Request<Body> {
    let mut b = axum::http::Request::builder()
        .method(method.clone())
        .uri(format!("/realms/acme{path}"))
        .header(axum::http::header::HOST, "access.test")
        .header(
            axum::http::header::COOKIE,
            format!("__Host-access-session={cookie}"),
        );
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

fn has_key(v: &serde_json::Value, needle: &str) -> bool {
    match v {
        serde_json::Value::Object(m) => m
            .iter()
            .any(|(k, x)| k.contains(needle) || has_key(x, needle)),
        serde_json::Value::Array(a) => a.iter().any(|x| has_key(x, needle)),
        _ => false,
    }
}

// IDP-37, E60, OP-43, TN-78, X38, XI-21, SI-15, OP-153 m.3 (bb), (ee), (ff), (gg), Ek B 3945, 4026, 4054
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the whole S11 privacy surface of one account"
)]
async fn the_s11_privacy_surface_keeps_records_never_authority() {
    let c = console("privacy-s11", false).await;
    let route = c.route.clone();
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let v = vault_of(&c);
    let realm = Realm {
        tenant: route.tenant,
        realm: route.realm,
        kek: &*v.kek,
        ids: &ids,
    };
    let db = PgAccounts::sealed(c.w.db.app.clone(), v.clone());
    let email = Identifier::new(IdentifierKind::Email, "Pia@Example.com").unwrap();
    let pia = create(&db, &realm, &[email], &WHO).await.unwrap();
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(&db, &realm, pia, to, &WHO).await.unwrap();
    }
    let account = realm.external(pia).unwrap();
    let value: [u8; 32] = access_crypto::random::bytes().unwrap();
    let at = now();
    let mut t = TenantTx::begin(&c.w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    t.insert_session(&access_store::sessions::NewSession {
        cookie_hash: &access_identity_session::domain::session::cookie_digest(&value),
        subject: pia,
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
    t.audit(&access_store::audit::AuditEvent {
        event_type: "session.created",
        actor: &account,
        target: &account,
        correlation: "s11",
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    let cookie = b64url_encode(&value);
    let app = hosted_router(&c);
    let json = |b: &[u8]| serde_json::from_slice::<serde_json::Value>(b).unwrap();

    // G57
    let (r, _) = send(
        &app,
        call(&Method::GET, "/v1/account/preferences", "nope", ""),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // IDP-37, OP-153 m.3 (ee)
    let (r, body) = send(
        &app,
        call(&Method::GET, "/v1/account/preferences", &cookie, ""),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json(&body)["current"]["email:newsletter"], false);
    let head = c.w.domains.head(c.domain).await.unwrap().0;
    let change = serde_json::json!({"changes": [
        {"channel": "email", "topic": "newsletter", "granted": true},
        {"channel": "sms", "topic": "campaign", "granted": false},
    ]})
    .to_string();
    let (r, body) = send(
        &app,
        call(&Method::PUT, "/v1/account/preferences", &cookie, &change),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let prefs = json(&body);
    assert_eq!(prefs["current"]["email:newsletter"], true);
    assert_eq!(prefs["history"].as_array().unwrap().len(), 2);
    let bad = serde_json::json!({"changes": [{"channel": "fax", "topic": "newsletter", "granted": true}]})
        .to_string();
    let (r, _) = send(
        &app,
        call(&Method::PUT, "/v1/account/preferences", &cookie, &bad),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // IDP-37, Ek B 3945, 4026
    assert_eq!(
        c.w.domains.head(c.domain).await.unwrap().0,
        head,
        "a preference writes no authority record"
    );

    // IDP-37, E60, TN-132
    let doc = serde_json::json!({
        "document_type": "terms",
        "version": "2026-11",
        "document_digest": b64url_encode(&[7_u8; 32]),
        "locale": "tr-TR",
        "method": "checkbox",
    })
    .to_string();
    let (r, body) = send(
        &app,
        call(&Method::POST, "/v1/account/documents", &cookie, &doc),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::NO_CONTENT,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (r, body) = send(
        &app,
        call(&Method::GET, "/v1/account/documents", &cookie, ""),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let docs = json(&body);
    assert_eq!(docs["acceptances"][0]["version"], "2026-11");
    let record = docs["acceptances"][0]["record_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        privacy_must_accept(&c, &realm, pia, "2026-12").await,
        "a new version asks again"
    );
    assert!(!privacy_must_accept(&c, &realm, pia, "2026-11").await);

    let mut t = TenantTx::begin(&c.w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    // IDP-37
    assert_eq!(
        t.history(&format!("{account}:doc:{record}"), 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    t.commit().await.unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let kinds: Vec<String> = loop {
        let kinds: Vec<String> = access_store::identity::poll(
            &c.w.db.reader,
            access_store::identity::Cursor::default(),
            10_000,
        )
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.kind)
        .collect();
        if kinds.iter().any(|k| k == "event.document.accepted") {
            break kinds;
        }
        assert!(std::time::Instant::now() < deadline, "{kinds:?}");
        tokio::task::yield_now().await;
    };
    assert!(
        kinds.iter().any(|k| k == "event.preference.changed"),
        "{kinds:?}"
    );

    // OP-43, Ek B 4054, XI-21
    let (r, body) = send(
        &app,
        call(&Method::GET, "/v1/account/security-history", &cookie, ""),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let history = json(&body);
    assert_eq!(history["days"], 90);
    assert_eq!(history["entries"][0]["category"], "sign_in");
    for word in ["risk", "score", "level", "ip_pseudonym"] {
        assert!(!has_key(&history, word), "{word}");
    }

    // OP-153 m.3 (bb), X38, CR-32, TN-78
    let (r, body) = send(
        &app,
        call(&Method::GET, "/v1/account/deletion", &cookie, ""),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(json(&body)["scheduled"], false);
    let mut tx = db.begin(route.tenant, route.realm).await.unwrap();
    privacy::request_deletion(
        &mut tx,
        &realm,
        pia,
        privacy::DeletionSource::SelfService,
        None,
        access_kernel::meta::CT3_DELAY_DEFAULT_S,
        &WHO,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (r, body) = send(
        &app,
        call(&Method::GET, "/v1/account/deletion", &cookie, ""),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let d = json(&body);
    assert_eq!(d["scheduled"], true);
    assert_eq!(d["cancellable"], true);
    let statement = d["statement"].as_str().unwrap().to_lowercase();
    assert!(statement.contains("redacted, not removed") && statement.contains("cancel"));
    for claim in [
        "instantly",
        "permanently erased",
        "all your data",
        "can't see your data",
    ] {
        assert!(!statement.contains(claim), "{claim}");
    }
    let (r, body) = send(
        &app,
        call(&Method::GET, "/v1/account/data-requests", &cookie, ""),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(json(&body)["requests"][0]["kind"], "erasure");
    let (r, _) = send(
        &app,
        call(&Method::DELETE, "/v1/account/deletion", &cookie, ""),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let (r, body) = send(
        &app,
        call(&Method::GET, "/v1/account/deletion", &cookie, ""),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(json(&body)["scheduled"], false);

    // XI-21
    let (_, body) = send(
        &app,
        call(&Method::GET, "/v1/account/security-history", &cookie, ""),
    )
    .await;
    let later = json(&body);
    let before = history["entries"].as_array().unwrap();
    let after = later["entries"].as_array().unwrap();
    assert!(after.len() > before.len());
    assert_eq!(&after[after.len() - before.len()..], &before[..]);
}

async fn privacy_must_accept(
    c: &Console,
    realm: &Realm<'_>,
    subject: [u8; 16],
    version: &str,
) -> bool {
    privacy::must_accept(
        &PgAccounts::sealed(c.w.db.app.clone(), vault_of(c)),
        realm,
        subject,
        "terms",
        version,
    )
    .await
    .unwrap()
}
