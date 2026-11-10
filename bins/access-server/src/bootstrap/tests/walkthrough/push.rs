//! Push verification on the real server (OP-156 m.3 (d), TN-102, OP-153 m.3 (gg)): the realm's
//! push setting is a root-signed `idp.realm.push` Exercise through the sequencer and `SoftHSM`, an
//! approver registers with the public SDK's `approver` module, and a CIBA approval sign-in of the
//! person waits on that approver as its suspended second step (OP-155 m.14 (j)).

use access_identity_admin::domain::Change;
use access_local_client::login::{Jar, post_json};
use access_sdk::approver::{registration_body, registration_message, thumbprint, to_raw_signature};
use serde_json::{Value as JsonValue, json};
use suiss_crypto::cose::PublicKey as CosePublicKey;
use suiss_crypto::signer::SoftSigner;

use super::*;

fn approver() -> (SoftSigner, Vec<u8>) {
    let (key, _) = SoftSigner::generate_p256().unwrap();
    let CosePublicKey::P256(public) = key.public_key() else {
        panic!("p-256")
    };
    (key, public)
}

impl Desk {
    /// Signs P in with the password up to the second step, as the login page does.
    async fn second_step(&self, jar: &mut Jar) -> JsonValue {
        let issuer = &self.user.issuer;
        let started = post_json(&self.http, &format!("{issuer}/v1/login/flows"), jar, None)
            .await
            .unwrap();
        assert_eq!(started.status, 201);
        let action = |v: &JsonValue| format!("{issuer}{}", v["action"].as_str().unwrap());
        let named = post_json(
            &self.http,
            &action(&started.json()),
            jar,
            Some(
                json!({ "method": "identifier", "fields": { "identifier": self.user.identifier } }),
            ),
        )
        .await
        .unwrap();
        let password = local_plan().test_user.unwrap().password;
        let second = post_json(
            &self.http,
            &action(&named.json()),
            jar,
            Some(json!({ "method": "password", "fields": { "password": password.expose() } })),
        )
        .await
        .unwrap();
        assert_eq!(second.json()["step"], "second_factor", "{}", second.json());
        second.json()
    }
}

fn offers_push(step: &JsonValue) -> bool {
    step["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["type"] == "submit" && n["method"] == "push")
}

// OP-156 m.3 (d), TN-102, IDP-14, OP-155 m.14 (j), Ek B 5087, 5394, 5398
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ciba_sign_in_waits_on_the_persons_approver_once_the_realm_offers_push() {
    let d = Desk::open("q5-push-ciba", false).await;
    let issuer = d.user.issuer.clone();
    let (key, public) = approver();
    let print = thumbprint(&public).unwrap();
    let mut jar = d.person().await;
    let proof =
        to_raw_signature(&key.sign(&registration_message(&issuer, &print)).unwrap()).unwrap();
    let body: JsonValue =
        serde_json::from_str(&registration_body("P's phone", &public, &proof)).unwrap();
    let made = post_json(
        &d.http,
        &format!("{issuer}/v1/approvers"),
        &mut jar,
        Some(body),
    )
    .await
    .unwrap();
    assert_eq!(made.status, 201, "{}", made.json());

    // OP-156 m.3 (d)
    let mut off = Jar::default();
    assert!(!offers_push(&d.second_step(&mut off).await));
    d.root_change(Change::Push(true)).await;

    let client = d.ciba_client("Mail agent", false).await;
    d.ciba_on(false, &[]).await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let hint = d.hint_token(&client).await;
    let (status, asked) = d
        .bc_authorize(
            &client,
            &d.ciba_params(&ex, &intent, ("login_hint_token", &hint), None),
        )
        .await;
    assert_eq!(status, 200, "{asked}");
    identity_events_until(
        &d.w.db,
        "relay.message.ciba_invite.v1",
        |q| !q.is_empty(),
        "the invitation",
    )
    .await;

    // TN-102
    let mut browser = Jar::default();
    let second = d.second_step(&mut browser).await;
    assert!(offers_push(&second), "{second}");
    let waiting = post_json(
        &d.http,
        &format!("{issuer}{}", second["action"].as_str().unwrap()),
        &mut browser,
        Some(json!({ "method": "push", "fields": {} })),
    )
    .await
    .unwrap();
    assert_eq!(waiting.status, 200, "{}", waiting.json());
    let node = waiting.json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["type"] == "push_number")
        .cloned()
        .unwrap();
    assert!((10..=99).contains(&node["number"].as_u64().unwrap()));
    assert_eq!(node["approver"], "P's phone");
    let pushed = identity_events_until(
        &d.w.db,
        "relay.message.push_approval.v1",
        |q| !q.is_empty(),
        "the push",
    )
    .await;
    assert_eq!(pushed.len(), 1);
    let (status, _) = d
        .ciba_poll(&client, asked["auth_req_id"].as_str().unwrap())
        .await;
    assert_eq!(status, 400, "the request waits while the sign-in does");

    // OP-156 m.3 (d)
    d.root_change(Change::Push(false)).await;
    let mut later = Jar::default();
    assert!(!offers_push(&d.second_step(&mut later).await));
}
