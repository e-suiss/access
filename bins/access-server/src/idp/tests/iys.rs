//! İYS consent records on the real plane and store (IDP-37 (4), B23, E42, OP-156 m.3 (c)): the
//! realm's `idp.realm.iys` and `idp.realm.preference_topics` through commit, a preference change
//! that hands Relay one sealed consent record per commercial channel, the event that names the
//! channels and never the address, and Relay's reports through `POST /relay/v1/iys-status` under
//! its platform client's RFC 7523 assertion, shown back in the person's preferences.

use access_http::relay_callback::router as iys_router;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::app::accounts::{change_status, create};
use access_identity_account::app::privacy::{self, PreferenceChange};
use access_identity_account::app::sealing::subject_key;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::notify::envelope::parse;
use access_identity_account::notify::message::{Address, Body, IysChannel, IysRecipient};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_identity_admin::domain::Change;
use axum::body::Body as HttpBody;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use serde_json::{Value as Json, json};
use tower::ServiceExt as _;

use super::platform::{ISSUER, products};
use core::fmt::Write as _;

use super::*;

const WHO: Actor<'static> = Actor {
    actor: "test",
    correlation: "iys",
};

fn uuid(b: &[u8; 16]) -> String {
    let h = b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    });
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

async fn post(app: &axum::Router, bearer: &str, body: &Json) -> (StatusCode, Json) {
    let r = app
        .clone()
        .oneshot(
            Request::post("/relay/v1/iys-status")
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(HttpBody::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(Json::Null);
    (status, v)
}

// IDP-37 (3), (4), B23, E42, OP-156 m.3 (c), OP-153 m.3 (ee), Ek B 5305, 5337, 5370
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one account's consent from the switch to Relay's report"
)]
async fn iys_records_reach_relay_with_every_field_and_relay_reports_back() {
    let w = World::new().await;
    let (ps, _, _) = products(&w, &[("relay", 61), ("work", 62)]).await;
    let (tenant, realm_id, d) = w.realm("shop").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let kek = Arc::new(SoftKek::new("realm-kek", [5; 32]));
    let vault = access_identity_account::app::vault::Vault::in_memory(kek.clone(), [9; 32]);
    let realm = Realm {
        tenant,
        realm: realm_id,
        kek: &*kek,
        ids: &w.ids,
    };
    let db = PgAccounts::sealed(w.db.app.clone(), vault);
    let email = Identifier::new(IdentifierKind::Email, "Ece@Example.com").unwrap();
    let phone = Identifier::new(IdentifierKind::Phone, "+905551112233").unwrap();
    let ece = create(&db, &realm, &[email, phone], &WHO).await.unwrap();
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(&db, &realm, ece, to, &WHO).await.unwrap();
    }
    let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock);
    let change = |channel, topic, granted| PreferenceChange {
        channel,
        topic,
        granted,
    };

    // OP-153 m.3 (ee)
    let loyalty = [change("email", "loyalty", true)];
    assert!(matches!(
        privacy::set_preferences(&db, &realm, ece, &loyalty, "self_service", &WHO, &notifier).await,
        Err(access_identity_account::AccountError::Invalid)
    ));
    written(
        &exercise(
            &w,
            &proposal(
                (tenant, realm_id),
                Change::PreferenceTopics(vec![String::from("loyalty")]),
                3,
                idp_anchor(d),
                1,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    privacy::set_preferences(&db, &realm, ece, &loyalty, "self_service", &WHO, &notifier)
        .await
        .unwrap();
    // OP-156 m.3 (c)
    let first = identity_events(&w.db, "event.preference.changed", 1).await;
    let payload = |e: &access_store::identity::OutboxEvent| {
        serde_json::from_slice::<Json>(&e.payload).unwrap()["payload"].clone()
    };
    assert!(
        payload(&first[0]).get("iys").is_none(),
        "{}",
        payload(&first[0])
    );

    // OP-156 m.3 (c)
    let on = proposal(
        (tenant, realm_id),
        Change::Iys {
            enabled: true,
            recipient_type: String::from("individual"),
        },
        4,
        idp_anchor(d),
        1,
    );
    assert_eq!(
        on.change.action(),
        access_internal_api::idp::IdpAction::RealmIys
    );
    written(&exercise(&w, &on, ROOT_KEY).await.unwrap());
    let head = w.plane.domains.head(d).await.unwrap();
    let changes = [
        change("sms", "campaign", true),
        change("email", "newsletter", false),
        change("email", "loyalty", false),
        change("push", "product_news", true),
    ];
    privacy::set_preferences(&db, &realm, ece, &changes, "self_service", &WHO, &notifier)
        .await
        .unwrap();
    // IDP-37 (3)
    assert_eq!(w.plane.domains.head(d).await.unwrap(), head);

    let events = identity_events(&w.db, "event.preference.changed", 2).await;
    let event = payload(&events[1]);
    assert_eq!(event["iys"]["channels"], json!(["sms", "email"]), "{event}");
    assert_eq!(event["iys"]["recipient_type"], "individual");
    assert_eq!(event["iys"]["source"], "self_service");
    assert!(
        event["iys"].get("consent").is_none(),
        "the channels ended apart"
    );
    assert!(event["at"].as_u64().unwrap() > 0);
    let text = event.to_string().to_lowercase();
    assert!(!text.contains("ece@example.com") && !text.contains("5551112233"));
    let schema: Json = serde_json::from_str(include_str!(
        "../../../../../sdks/openapi/events/preference.changed.schema.json"
    ))
    .unwrap();
    for k in event["iys"].as_object().unwrap().keys() {
        assert!(
            schema["properties"]["iys"]["properties"].get(k).is_some(),
            "{k}"
        );
    }

    // B23
    let records = identity_events(&w.db, "relay.message.iys_consent", 2).await;
    assert_eq!(records.len(), 2, "push is no İYS channel");
    let mut tx = db.begin(tenant, realm_id).await.unwrap();
    let row = tx.subject(ece, false).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    let dek = subject_key(&realm, &row).unwrap();
    let mut ids = Vec::new();
    for e in &records {
        let env = parse(&e.payload).unwrap();
        let m = env.open(&e.kind, &dek).unwrap();
        let Body::IysConsent {
            channel,
            recipient_type,
            approved,
            source,
            consent_at_ms,
        } = &m.body
        else {
            panic!("{m:?}");
        };
        assert_eq!(*recipient_type, IysRecipient::Individual);
        assert_eq!(source, "self_service");
        assert_eq!(*consent_at_ms, event["at"].as_u64().unwrap());
        match channel {
            IysChannel::Sms => {
                assert!(*approved);
                assert_eq!(m.to, Address::Phone(String::from("+905551112233")));
            }
            IysChannel::Email => {
                assert!(!*approved);
                let Address::Email(to) = &m.to else {
                    panic!("{m:?}");
                };
                assert_eq!(to.to_lowercase(), "ece@example.com");
            }
            IysChannel::Call => panic!("no call channel changed"),
        }
        ids.push((*channel, env.header.event.0));
    }

    let prefs = privacy::preferences(&db, &realm, ece).await.unwrap();
    assert_eq!(prefs["current"]["email:loyalty"], false);
    assert_eq!(
        prefs["iys"]["channels"]["sms"]["status"], "pending",
        "{prefs}"
    );

    // E42 (2)
    let relay = &ps[0];
    let app = iys_router(
        Arc::clone(&relay.api),
        crate::iys::PgIysReports {
            app: w.db.app.clone(),
            ids: Arc::new(IdKey::new(Secret::new([8; 32]))),
        },
        String::from("https://api.id.test"),
        Some(String::from("relay")),
    );
    let tnt =
        access_identity_events::ports::TenantIds::external(&w.ids, tenant.as_bytes()).unwrap();
    let report = |record: &[u8; 16], status: &str| {
        let mut r = json!({
            "tenant": tnt,
            "realm": uuid(realm_id.as_bytes()),
            "record": uuid(record),
            "status": status,
            "at": 1_793_750_400_000_u64,
        });
        if status == "failed" {
            r["reason"] = json!("recipient-blocked");
        }
        r
    };
    let sms = ids.iter().find(|(c, _)| *c == IysChannel::Sms).unwrap().1;
    let mail = ids.iter().find(|(c, _)| *c == IysChannel::Email).unwrap().1;
    let (s, v) = post(&app, &ps[1].assertion(ISSUER), &report(&sms, "recorded")).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "another product is not Relay: {v}"
    );
    let (s, _) = post(&app, "not-an-assertion", &report(&sms, "recorded")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = post(
        &app,
        &relay.assertion(ISSUER),
        &report(&[7; 16], "recorded"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = post(&app, &relay.assertion(ISSUER), &report(&sms, "recorded")).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let (s, v) = post(&app, &relay.assertion(ISSUER), &report(&mail, "failed")).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");

    let prefs = privacy::preferences(&db, &realm, ece).await.unwrap();
    assert_eq!(
        prefs["iys"]["channels"]["sms"]["status"], "recorded",
        "{prefs}"
    );
    assert_eq!(prefs["iys"]["channels"]["sms"]["consent"], "approved");
    assert_eq!(prefs["iys"]["channels"]["email"]["status"], "failed");
    assert_eq!(
        prefs["current"]["sms:campaign"], true,
        "a report changes no preference"
    );
    assert_eq!(w.plane.domains.head(d).await.unwrap(), head);
    let mut t = TenantTx::begin(&w.db.app, tenant, realm_id).await.unwrap();
    let audit = t.list_audit(100).await.unwrap();
    t.commit().await.unwrap();
    for (event, n) in [("iys.recorded", 1), ("iys.failed", 1)] {
        assert_eq!(audit.iter().filter(|a| a.event_type == event).count(), n);
    }

    // OP-156 m.3 (c)
    let off = proposal(
        (tenant, realm_id),
        Change::Iys {
            enabled: false,
            recipient_type: String::from("individual"),
        },
        5,
        idp_anchor(d),
        1,
    );
    assert_eq!(
        off.change.action(),
        access_internal_api::idp::IdpAction::RealmIysClose
    );
    written(&exercise(&w, &off, ROOT_KEY).await.unwrap());
    privacy::set_preferences(
        &db,
        &realm,
        ece,
        &[change("sms", "campaign", false)],
        "self_service",
        &WHO,
        &notifier,
    )
    .await
    .unwrap();
    let events = identity_events(&w.db, "event.preference.changed", 3).await;
    assert!(payload(&events[2]).get("iys").is_none());
    assert_eq!(
        identity_events(&w.db, "relay.message.iys_consent", 2)
            .await
            .len(),
        2
    );
}
