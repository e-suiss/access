//! TN-135, MD-8, OP-151 m.3 (j): the hook caller signs every call per Standard Webhooks, waits
//! at most 3 s, and refuses whenever it cannot read an answer.

#![allow(
    unreachable_pub,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use access_crypto::webhook::{WebhookPublicKey, WebhookSigningKey};
use access_identity_hooks::app::Hooks;
use access_identity_hooks::domain::{
    Call, HookPoint, OnNoAnswer, Outcome, PostLogin, Refusal, Registration, Reply, TIMEOUT_MS,
    TokenIssuance,
};
use access_identity_hooks::ports::{
    HookCaller, HookClock, HookKey, HookRegistry, HookTransport, LiveHook, NoHooks, Unavailable,
};
use access_store::identity::{RealmId, TenantId};

const SEED: [u8; 32] = [7; 32];
const NOW_MS: u64 = 1_793_784_600_000;

struct Registry(Option<OnNoAnswer>, bool);

impl HookRegistry for Registry {
    async fn live(
        &self,
        _: TenantId,
        _: RealmId,
        point: HookPoint,
    ) -> Result<Option<LiveHook>, Unavailable> {
        if self.1 {
            return Err(Unavailable);
        }
        Ok(self.0.map(|on_no_answer| LiveHook {
            registration: Registration {
                id: [1; 16],
                point,
                url: String::from("https://hooks.shop.example/access"),
                on_no_answer,
                disclose: Vec::new(),
            },
            key: HookKey::Ed25519(WebhookSigningKey::from_seed(&SEED).unwrap()),
            realm_allows_disclosure: false,
        }))
    }
}

#[derive(Default)]
struct Seen {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    deadline: Option<Duration>,
}

enum Behaviour {
    Answer(u16, &'static str),
    Hang,
}

struct Transport(Behaviour, Arc<Mutex<Seen>>);

impl HookTransport for Transport {
    async fn post(
        &self,
        _: &str,
        headers: &[(&'static str, String)],
        body: &[u8],
        deadline: Duration,
    ) -> Reply {
        {
            let mut s = self.1.lock().unwrap();
            s.headers = headers
                .iter()
                .map(|(k, v)| (String::from(*k), v.clone()))
                .collect();
            s.body = body.to_vec();
            s.deadline = Some(deadline);
        }
        match self.0 {
            Behaviour::Answer(status, body) => Reply::Answered {
                status,
                body: body.as_bytes().to_vec(),
            },
            Behaviour::Hang => std::future::pending().await,
        }
    }
}

struct Clock;

impl HookClock for Clock {
    fn now_ms(&self) -> Option<u64> {
        Some(NOW_MS)
    }
}

fn ids() -> (TenantId, RealmId) {
    (TenantId::from_bytes([3; 16]), RealmId::from_bytes([4; 16]))
}

fn login() -> Call {
    Call::PostLogin(PostLogin {
        account: String::from("usr_01jc4x0f8c2q4a7r5w3v9y6k1m"),
        aal: 2,
        methods: vec!["passkey"],
    })
}

fn token() -> Call {
    Call::TokenIssuance(TokenIssuance {
        client_id: String::from("cli_x"),
        subject: String::from("pairwise"),
        scope: String::from("openid"),
        acr: String::from("urn:suiss:aal2"),
    })
}

fn header<'a>(s: &'a Seen, name: &str) -> &'a str {
    &s.headers.iter().find(|(k, _)| k == name).unwrap().1
}

// TN-135, TN-136, E42: a call is signed v1a over webhook-id.webhook-timestamp.body, verifiable
// with the registration's public key by any Standard Webhooks verifier
#[tokio::test]
async fn tn_135_calls_are_signed_per_standard_webhooks() {
    let shared = Arc::new(Mutex::new(Seen::default()));
    let hooks = Hooks::new(
        Registry(Some(OnNoAnswer::Refuse), false),
        Transport(
            Behaviour::Answer(200, r#"{"decision":"allow"}"#),
            Arc::clone(&shared),
        ),
        Clock,
    );
    let (t, r) = ids();
    assert_eq!(hooks.call(t, r, login()).await, Outcome::proceed());
    let pk: WebhookPublicKey = WebhookSigningKey::from_seed(&SEED).unwrap().public_key();
    let seen = shared.lock().unwrap();
    let ts: u64 = header(&seen, "webhook-timestamp").parse().unwrap();
    assert_eq!(ts, NOW_MS / 1000);
    assert_eq!(
        header(&seen, "hook-timestamp"),
        header(&seen, "webhook-timestamp")
    );
    assert_eq!(
        header(&seen, "hook-id"),
        "01010101-0101-0101-0101-010101010101"
    );
    assert!(pk.verify(
        header(&seen, "webhook-id"),
        ts,
        &seen.body,
        header(&seen, "webhook-signature"),
        ts
    ));
    assert_eq!(seen.deadline, Some(Duration::from_millis(TIMEOUT_MS)));
    let body: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
    assert_eq!(body["type"], "urn:suiss:access:hook:post_login");
    assert_eq!(body["data"]["account"], "usr_01jc4x0f8c2q4a7r5w3v9y6k1m");
}

// TN-135, MD-8: a hook that does not answer within 3 s refuses the sign-in; a token_issuance
// hook with continue_without_claims lets the token through without claims
#[tokio::test(start_paused = true)]
async fn md_8_a_silent_hook_refuses() {
    let (t, r) = ids();
    let silent = Hooks::new(
        Registry(Some(OnNoAnswer::Refuse), false),
        Transport(Behaviour::Hang, Arc::default()),
        Clock,
    );
    assert_eq!(
        silent.call(t, r, login()).await,
        Outcome::Refused(Refusal::Unanswered)
    );
    assert_eq!(
        silent.call(t, r, token()).await,
        Outcome::Refused(Refusal::Unanswered)
    );
    let lenient = Hooks::new(
        Registry(Some(OnNoAnswer::ContinueWithoutClaims), false),
        Transport(Behaviour::Hang, Arc::default()),
        Clock,
    );
    assert_eq!(lenient.call(t, r, token()).await, Outcome::proceed());
}

// TN-135, MD-8: no live hook changes nothing; a registry that cannot answer refuses
#[tokio::test]
async fn md_8_no_hook_changes_nothing_and_an_unreadable_registry_refuses() {
    let (t, r) = ids();
    let none = Hooks::new(
        Registry(None, false),
        Transport(Behaviour::Answer(500, ""), Arc::default()),
        Clock,
    );
    assert_eq!(none.call(t, r, login()).await, Outcome::proceed());
    assert_eq!(NoHooks.call(t, r, token()).await, Outcome::proceed());
    let down = Hooks::new(
        Registry(Some(OnNoAnswer::ContinueWithoutClaims), true),
        Transport(Behaviour::Answer(200, "{}"), Arc::default()),
        Clock,
    );
    assert_eq!(
        down.call(t, r, token()).await,
        Outcome::Refused(Refusal::Unavailable)
    );
}
