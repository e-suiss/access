//! Inline hooks, webhooks and the realm's extension policy through the realm-admin resources
//! and commit against real PostgreSQL and the authority plane (TN-135, TN-136, MD-14, TN-110,
//! OP-151 m.10, m.11): each registration is an `idp.*` Exercise, its key is shown once, and the
//! registered hook and webhook then fire, signed with that key.

use std::sync::Mutex;
use std::time::Duration;

use access_crypto::webhook::WebhookPublicKey;
use access_identity_admin::app::rest::{Kind, Op, compile};
use access_identity_admin::domain::{HOOK_PREFIX, Invalid, WEBHOOK_PREFIX};
use access_identity_events::app::webhooks::{WebhookCourier, WebhookFanout};
use access_identity_events::app::{Db, emit};
use access_identity_events::domain::catalog::IdentityEvent;
use access_identity_events::ports::{PostError, Reply as EventReply, Transport};
use access_identity_hooks::app::Hooks;
use access_identity_hooks::domain::{Call, Outcome, PostLogin, Refusal, Reply};
use access_identity_hooks::ports::HookTransport;
use access_identity_oauth::adapters::dpop::SystemClock;
use serde_json::{Value as Json, json};

use super::*;

async fn ready(slug: &str) -> (World, (TenantId, RealmId), Digest) {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm(slug).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    (w, (tenant, realm), d)
}

async fn run(
    w: &World,
    at: (TenantId, RealmId),
    d: Digest,
    change: Change,
    nonce: u8,
) -> Result<Applied, AdminError> {
    exercise(w, &proposal(at, change, nonce, idp_anchor(d), 1), ROOT_KEY).await
}

/// Why the realm refuses `change` before anything is signed.
async fn refused(
    w: &World,
    at: (TenantId, RealmId),
    d: Digest,
    change: Change,
    nonce: u8,
) -> Invalid {
    match w
        .admin()
        .prepare(&proposal(at, change, nonce, idp_anchor(d), 1))
        .await
    {
        Err(AdminError::Invalid(i)) => i,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("prepared"),
    }
}

/// The world's vault, over the same KEK.
fn vault(w: &World) -> access_identity_events::adapters::KekSealer<TestKek> {
    access_identity_events::adapters::KekSealer(TestKek(w.vault.0.0.clone()))
}

/// The key a written registration showed once.
fn shown(a: &Applied) -> String {
    match a {
        Applied::Written {
            secret: Some(k), ..
        } => k.expose().to_owned(),
        other => panic!("{other:?}"),
    }
}

/// One request a receiver got: its headers and body.
type Got = Arc<Mutex<Vec<(Vec<(String, String)>, Vec<u8>)>>>;

/// The tenant's hook endpoint: records the call and refuses the sign-in.
#[derive(Clone, Default)]
struct HookReceiver(Got);

impl HookTransport for HookReceiver {
    fn post(
        &self,
        url: &str,
        headers: &[(&'static str, String)],
        body: &[u8],
        _: Duration,
    ) -> impl Future<Output = Reply> + Send {
        assert_eq!(url, "https://hooks.shop.example/check");
        self.0.lock().unwrap().push((
            headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
            body.to_vec(),
        ));
        std::future::ready(Reply::Answered {
            status: 200,
            body: br#"{"decision":"deny","reason_code":"blocked"}"#.to_vec(),
        })
    }
}

/// The tenant's webhook endpoint: records each delivery and answers 204.
#[derive(Clone, Default)]
struct WebhookReceiver(Got);

impl Transport for WebhookReceiver {
    fn post(
        &self,
        url: &str,
        _: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> impl Future<Output = Result<EventReply, PostError>> + Send {
        assert_eq!(url, "https://sync.shop.example/events");
        self.0.lock().unwrap().push((
            headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
            body.to_vec(),
        ));
        std::future::ready(Ok(EventReply {
            status: 204,
            retry_after_ms: None,
        }))
    }
}

fn header(headers: &[(String, String)], name: &str) -> String {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
        .unwrap()
}

fn verified(key: &str, got: &Got) {
    let key = WebhookPublicKey::parse(key).unwrap();
    let got = got.lock().unwrap();
    assert_eq!(got.len(), 1);
    let (headers, body) = &got[0];
    let ts: u64 = header(headers, "webhook-timestamp").parse().unwrap();
    assert!(key.verify(
        &header(headers, "webhook-id"),
        ts,
        body,
        &header(headers, "webhook-signature"),
        ts
    ));
}

// TN-135, TN-136, MD-14, TN-110, OP-151 m.10 (d), m.11: a hook and a webhook registered through
// the realm-admin resources are each one idp.* Exercise; the verification key is shown once
// and never read back; the hook is then called and the webhook delivered, signed with it
#[tokio::test]
async fn a_hook_and_a_webhook_registered_through_rest_then_fire() {
    let (w, at, d) = ready("hooks").await;
    let hook_id = w.ids.encode(HOOK_PREFIX, [0x11; 16]).unwrap();
    let hook = compile(
        Op::RegisterHook,
        None,
        &json!({"hook_id": hook_id, "point": "post_login",
                "url": "https://hooks.shop.example/check"}),
        &w.ids,
    )
    .unwrap();
    let hook_key = shown(&run(&w, at, d, hook, 1).await.unwrap());
    assert!(hook_key.starts_with("whpk_"), "{hook_key}");
    let hooks = w
        .admin()
        .read(at.0, at.1, Kind::Hooks, None, None, 10)
        .await
        .unwrap();
    assert_eq!(hooks.items.len(), 1);
    let view = &hooks.items[0].0;
    assert_eq!(view["hook_id"], hook_id.as_str());
    assert_eq!(view["public_key"], hook_key.as_str());
    assert_eq!(view["status"], "active");
    // TN-61: only the public key is ever read back
    let mut members: Vec<&String> = view.as_object().unwrap().keys().collect();
    members.sort();
    assert_eq!(
        members,
        [
            "disclose",
            "hook_id",
            "on_no_answer",
            "point",
            "public_key",
            "signing",
            "status",
            "url"
        ]
    );
    // OP-151 m.10 (d): one live hook per call point
    let second = compile(
        Op::RegisterHook,
        None,
        &json!({"hook_id": w.ids.encode(HOOK_PREFIX, [0x12; 16]).unwrap(),
                "point": "post_login", "url": "https://hooks.shop.example/other"}),
        &w.ids,
    )
    .unwrap();
    assert_eq!(refused(&w, at, d, second, 2).await, Invalid::HookPointTaken);

    let receiver = HookReceiver::default();
    let caller = Hooks::new(
        access_identity_hooks::adapters::PgRegistry::new(w.db.app.clone(), vault(&w)),
        receiver.clone(),
        access_identity_hooks::adapters::SystemClock,
    );
    let outcome = caller
        .run(
            at.0,
            at.1,
            Call::PostLogin(PostLogin {
                account: String::from("usr_x"),
                aal: 2,
                methods: vec!["hwk"],
            }),
        )
        .await;
    assert_eq!(
        outcome,
        Outcome::Refused(Refusal::Denied {
            reason_code: Some(String::from("blocked"))
        })
    );
    verified(&hook_key, &receiver.0);

    let webhook_id = w.ids.encode(WEBHOOK_PREFIX, [0x21; 16]).unwrap();
    let webhook = compile(
        Op::RegisterWebhook,
        None,
        &json!({"webhook_id": webhook_id, "url": "https://sync.shop.example/events",
                "events": ["login.failed_surge"]}),
        &w.ids,
    )
    .unwrap();
    let webhook_key = shown(&run(&w, at, d, webhook, 3).await.unwrap());
    assert!(webhook_key.starts_with("whpk_"), "{webhook_key}");
    let webhooks = w
        .admin()
        .read(at.0, at.1, Kind::Webhooks, Some(&webhook_id), None, 1)
        .await
        .unwrap();
    assert_eq!(webhooks.items[0].0["events"], json!(["login.failed_surge"]));

    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let now = access_store::authority::server_time(&w.db.app)
        .await
        .unwrap();
    emit(
        &mut t,
        &IdentityEvent::login_failed_surge([0x31; 32], at.1.as_bytes(), 50, 60_000, now),
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let db = || Db {
        app: w.db.app.clone(),
        reader: w.db.reader.clone(),
        ids: Arc::new(IdKey::new(Secret::new([8; 32]))),
    };
    // the outbox is read behind the cluster's oldest running transaction
    let fanout = WebhookFanout::new(db(), SystemClock);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while fanout.step().await.unwrap() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "not fanned out in 30 s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let receiver = WebhookReceiver::default();
    WebhookCourier::new(db(), receiver.clone(), vault(&w), SystemClock)
        .step()
        .await
        .unwrap();
    verified(&webhook_key, &receiver.0);
    let body = receiver.0.lock().unwrap()[0].1.clone();
    let event: Json = serde_json::from_slice(&body).unwrap();
    assert!(
        event["type"]
            .as_str()
            .unwrap()
            .ends_with("login.failed_surge"),
        "{event}"
    );

    // TN-135, TN-136: retiring narrows; the hook is no longer called
    let retire = compile(Op::RetireHook, Some(&hook_id), &json!({}), &w.ids).unwrap();
    written(&run(&w, at, d, retire, 4).await.unwrap());
    let quiet = HookReceiver::default();
    let outcome = Hooks::new(
        access_identity_hooks::adapters::PgRegistry::new(w.db.app.clone(), vault(&w)),
        quiet.clone(),
        access_identity_hooks::adapters::SystemClock,
    )
    .run(
        at.0,
        at.1,
        Call::PostLogin(PostLogin {
            account: String::from("usr_x"),
            aal: 2,
            methods: vec!["hwk"],
        }),
    )
    .await;
    assert_eq!(outcome, Outcome::proceed());
    assert!(quiet.0.lock().unwrap().is_empty());
}

// OP-151 m.10 (e), OP-149 m.23: a private target needs both the realm's extension policy and
// the operator's declaration; a disclosure needs the policy's permission; the policy is itself
// an idp.realm.extension_policy Exercise and shows in the settings
#[tokio::test]
async fn private_targets_and_disclosure_need_the_extension_policy() {
    let (w, at, d) = ready("policy").await;
    let private = "https://hooks.shop.internal:8443/check";
    let hook = |n: u8, url: &str, disclose: &[&str]| {
        compile(
            Op::RegisterHook,
            None,
            &json!({"hook_id": w.ids.encode(HOOK_PREFIX, [n; 16]).unwrap(),
                    "point": "pre_registration", "url": url, "disclose": disclose}),
            &w.ids,
        )
        .unwrap()
    };
    assert_eq!(
        refused(&w, at, d, hook(1, private, &[]), 1).await,
        Invalid::ExtensionTarget
    );
    assert_eq!(
        refused(
            &w,
            at,
            d,
            hook(2, "https://hooks.shop.example/check", &["email"]),
            2
        )
        .await,
        Invalid::Disclosure
    );
    let policy = compile(
        Op::PutExtensionPolicy,
        None,
        &json!({"allow_private_targets": true, "hook_disclosure": ["email"]}),
        &w.ids,
    )
    .unwrap();
    assert_eq!(
        policy.action(),
        access_internal_api::idp::IdpAction::RealmExtensionPolicy
    );
    written(&run(&w, at, d, policy, 3).await.unwrap());
    let settings = w
        .admin()
        .read(at.0, at.1, Kind::Settings, None, None, 1)
        .await
        .unwrap();
    assert_eq!(
        settings.items[0].0["extension_policy"],
        json!({"allow_private_targets": true, "hook_disclosure": ["email"]})
    );
    // OP-149 m.23: the realm allows private targets, the operator has not declared this one
    assert_eq!(
        refused(&w, at, d, hook(4, private, &[]), 4).await,
        Invalid::ExtensionTarget
    );
    let declared = Admin {
        declared: DeclaredTargets::new([String::from(private)]),
        ..w.admin()
    };
    let p = proposal(at, hook(5, private, &["email"]), 5, idp_anchor(d), 1);
    let prepared = declared.prepare(&p).await.unwrap();
    let ais = sign(
        &statement(prepared.domain, &p.nonce, prepared.digest, p.basis),
        ROOT_KEY,
    );
    let key = shown(&declared.apply(&p, ais).await.unwrap());
    assert!(key.starts_with("whpk_"));
}

// TN-136: a key rotation keeps the webhook's URL and events and shows the new key once; an
// update changes them; both are idp.webhook.update Exercises
#[tokio::test]
async fn a_webhook_is_updated_and_its_key_rotated() {
    let (w, at, d) = ready("rotate").await;
    let id = w.ids.encode(WEBHOOK_PREFIX, [0x51; 16]).unwrap();
    let register = compile(
        Op::RegisterWebhook,
        None,
        &json!({"webhook_id": id, "url": "https://sync.shop.example/events",
                "events": ["account.created"], "signing": "hmac"}),
        &w.ids,
    )
    .unwrap();
    let first = shown(&run(&w, at, d, register, 1).await.unwrap());
    assert!(first.starts_with("whsec_"));
    let rotate = compile(Op::RotateWebhookKey, Some(&id), &json!({}), &w.ids).unwrap();
    let rotate = w.admin().resolve(at.0, at.1, rotate).await.unwrap();
    assert!(
        matches!(&rotate, Change::Webhook(access_identity_admin::domain::WebhookChange::Update { url, rotate: true, .. }) if url == "https://sync.shop.example/events")
    );
    let second = shown(&run(&w, at, d, rotate, 2).await.unwrap());
    assert!(second.starts_with("whsec_") && second != first);
    let update = compile(
        Op::PutWebhook,
        Some(&id),
        &json!({"url": "https://crm.shop.example/events",
                "events": ["account.created", "session.revoked"]}),
        &w.ids,
    )
    .unwrap();
    let applied = run(&w, at, d, update, 3).await.unwrap();
    assert!(matches!(applied, Applied::Written { secret: None, .. }));
    let read = w
        .admin()
        .read(at.0, at.1, Kind::Webhooks, Some(&id), None, 1)
        .await
        .unwrap();
    assert_eq!(read.items[0].0["url"], "https://crm.shop.example/events");
    let retire = compile(Op::RetireWebhook, Some(&id), &json!({}), &w.ids).unwrap();
    written(&run(&w, at, d, retire, 4).await.unwrap());
    let again = compile(Op::RotateWebhookKey, Some(&id), &json!({}), &w.ids).unwrap();
    assert!(matches!(
        w.admin().resolve(at.0, at.1, again).await,
        Err(AdminError::Invalid(Invalid::NoWebhook))
    ));
}
