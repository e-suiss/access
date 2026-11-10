//! Push verification and approvers on the hosted surface (OP-156 m.3 (d), §10.2.3, TN-102): the
//! approver is the public SDK's `approver` module with a software P-256 key, as any app embeds it.

use access_identity_session::domain::requirement::AuthPolicy;
use access_sdk::approver::{
    Answer as PushAnswer, Decision, answer_body, registration_body, registration_message,
    same_device_body, same_device_message, thumbprint, to_raw_signature,
};
use suiss_crypto::cose::PublicKey;

use super::*;

const PUSH: AuthPolicy = AuthPolicy {
    push: true,
    ..AuthPolicy::DEFAULT
};

struct Approver {
    key: SoftSigner,
    public: Vec<u8>,
    thumbprint: [u8; 32],
}

impl Approver {
    fn new() -> Self {
        let (key, _) = SoftSigner::generate_p256().unwrap();
        let PublicKey::P256(public) = key.public_key() else {
            panic!("p-256")
        };
        let thumbprint = thumbprint(&public).unwrap();
        Self {
            key,
            public,
            thumbprint,
        }
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        to_raw_signature(&self.key.sign(message).unwrap()).unwrap()
    }

    fn address(&self) -> String {
        b64url_encode(&self.thumbprint)
    }

    async fn register(&self, b: &mut Web, name: &str) -> Answer {
        let proof = self.sign(&registration_message(
            &format!("https://{HOST}"),
            &self.thumbprint,
        ));
        let body: Value =
            serde_json::from_str(&registration_body(name, &self.public, &proof)).unwrap();
        b.post("/v1/approvers", Some(body)).await
    }

    fn answer(&self, challenge: [u8; 32], number: Option<u8>, decision: Decision) -> Value {
        self.answer_as(self.thumbprint, challenge, number, decision)
    }

    fn answer_as(
        &self,
        device_key: [u8; 32],
        challenge: [u8; 32],
        number: Option<u8>,
        decision: Decision,
    ) -> Value {
        let signed = PushAnswer {
            challenge,
            number,
            decision,
            device_key,
            pin_verified: None,
        }
        .to_be_signed();
        serde_json::from_str(&answer_body(&signed, &self.sign(&signed))).unwrap()
    }
}

/// What the approver app sends: no cookie, only its signature.
async fn answer(e: &Env, body: Value) -> Answer {
    e.browser("approver")
        .send("POST", "/v1/push/answer", Some(body), None)
        .await
}

fn number(a: &Answer) -> u8 {
    let node = a.json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["type"] == "push_number")
        .cloned()
        .unwrap_or_else(|| panic!("{}", String::from_utf8_lossy(&a.body)));
    u8::try_from(node["number"].as_u64().unwrap()).unwrap()
}

impl Env {
    /// The challenge of the last push, as the device the Relay seam reached saw it.
    fn pushed(&self, to: &Approver) -> (Vec<String>, [u8; 32]) {
        let (device, texts) = self.outbox.2.lock().unwrap().last().cloned().unwrap();
        assert_eq!(device, to.address());
        let challenge = <[u8; 32]>::try_from(b64url_decode(&texts[0]).unwrap()).unwrap();
        (texts, challenge)
    }

    fn pushes(&self) -> usize {
        self.outbox.2.lock().unwrap().len()
    }
}

impl Web {
    /// Signs in with the password and sends a push from the second step.
    async fn push(&mut self, who: &str) -> Answer {
        let second = self.sign_in(who).await;
        assert_eq!(
            second.step(),
            "second_factor",
            "{}",
            String::from_utf8_lossy(&second.body)
        );
        assert!(node_types(&second).contains(&String::from("submit")));
        self.submit(&second, "push", json!({})).await
    }

    async fn poll(&mut self, at: &Answer) -> Answer {
        self.get(&at.action()).await
    }
}

// OP-156 m.3 (d), §10.1.3, §10.2.3, IDP-4, TN-100, TN-102, SEC18, Ek B 5394, 5398, 5399
#[tokio::test]
async fn an_approved_push_with_the_pages_number_is_the_second_step() {
    use access_identity_account::domain::claims::Content;
    use access_kernel::claim::body::{AuthenticatorKind, Body};
    let e = env(0x91, "q5-push", PUSH).await;
    let subject = e.account("pia@example.com").await;
    let phone = Approver::new();
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("pia@example.com").await.step(), "complete");

    // OP-156 m.3 (d)
    e.advance(301_000);
    let stale = phone.register(&mut b, "Pia's phone").await;
    assert_eq!(
        stale.json()["code"],
        "step-up-required",
        "{}",
        String::from_utf8_lossy(&stale.body)
    );
    let mut b = e.browser("b2");
    assert_eq!(b.sign_in("pia@example.com").await.step(), "complete");
    let forged = {
        let other = Approver::new();
        let proof = other.sign(&registration_message(
            &format!("https://{HOST}"),
            &phone.thumbprint,
        ));
        let body: Value =
            serde_json::from_str(&registration_body("x", &phone.public, &proof)).unwrap();
        b.post("/v1/approvers", Some(body)).await
    };
    assert_eq!(forged.json()["code"], "approver-proof");
    let made = phone.register(&mut b, "Pia's phone").await;
    assert_eq!(
        made.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&made.body)
    );
    assert_eq!(made.json()["device_key"], phone.address());
    assert_eq!(
        phone.register(&mut b, "again").await.json()["code"],
        "approver-known"
    );
    // SEC18
    let told = *e.sent().last().unwrap();
    assert_eq!(told.0, "relay.message.new_method.v1");
    assert_eq!(told.2, subject);
    // §10.1.3
    let orders = claim_orders(&e, |o| {
        o.iter().any(|c| {
            matches!(&c.content, Content::Body { body: Body::AuthenticatorBinding(a), .. }
                if a.kind == AuthenticatorKind::DeviceKey)
        })
    })
    .await;
    assert!(orders.iter().any(|c| c.class == "authenticator_binding"));
    let listed = b.get("/v1/approvers").await.json();
    assert_eq!(listed["approvers"][0]["name"], "Pia's phone");
    assert!(listed["approvers"][0].get("public_key").is_none());

    let mut c = e.browser("c");
    let waiting = c.push("pia@example.com").await;
    assert_eq!(
        waiting.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&waiting.body)
    );
    assert_eq!(waiting.messages(), ["push.waiting"]);
    let n = number(&waiting);
    assert!((10..=99).contains(&n));
    // OP-156 m.3 (d), §8.17.11.4
    let (texts, challenge) = e.pushed(&phone);
    assert_eq!(texts[1], "Acme");
    assert_eq!(texts[2], "Sign in");
    assert_eq!(
        texts.len(),
        4,
        "challenge, application, action and expiry only: no number, and no location is known"
    );
    let still = c.poll(&waiting).await;
    assert_eq!(number(&still), n);

    let approved = answer(&e, phone.answer(challenge, Some(n), Decision::Approve)).await;
    assert_eq!(
        approved.json()["state"],
        "approved",
        "{}",
        String::from_utf8_lossy(&approved.body)
    );
    let done = c.poll(&waiting).await;
    assert_eq!(
        done.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    // IDP-8, §10.2.3
    let orders = claim_orders(&e, |o| {
        o.iter()
            .filter(|c| c.class == "authentication")
            .any(|c| c.assurance.get("aal") == Some(&2))
    })
    .await;
    let auth = orders
        .iter()
        .filter(|c| c.class == "authentication")
        .find(|c| c.assurance.get("aal") == Some(&2))
        .unwrap();
    assert_eq!(auth.assurance.get("phishing_resistant"), Some(&0));
    // TN-102
    let again = answer(&e, phone.answer(challenge, Some(n), Decision::Approve)).await;
    assert_eq!(again.json()["code"], "push-challenge-answered");
}

// OP-156 m.3 (d), Ek B 5399
#[tokio::test]
async fn a_wrong_number_a_late_answer_and_another_devices_key_are_refused() {
    let e = env(0x92, "q5-refuse", PUSH).await;
    e.account("rui@example.com").await;
    let phone = Approver::new();
    let mut b = e.browser("b");
    b.sign_in("rui@example.com").await;
    assert_eq!(
        phone.register(&mut b, "phone").await.status,
        StatusCode::CREATED
    );

    // OP-156 m.3 (d)
    let mut c = e.browser("c");
    let waiting = c.push("rui@example.com").await;
    let n = number(&waiting);
    let (_, challenge) = e.pushed(&phone);
    let wrong = if n == 99 { 10 } else { n + 1 };
    let refused = answer(&e, phone.answer(challenge, Some(wrong), Decision::Approve)).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json()["code"], "push-number-mismatch");
    let spent = answer(&e, phone.answer(challenge, Some(n), Decision::Approve)).await;
    assert_eq!(spent.json()["code"], "push-challenge-answered");
    let back = c.poll(&waiting).await;
    assert_eq!(back.step(), "second_factor");
    assert_eq!(back.messages(), ["push.denied"]);
    // OP-156 m.3 (d)
    e.advance(15 * 60_000);

    // OP-156 m.3 (d)
    let mut d = e.browser("d");
    let waiting = d.push("rui@example.com").await;
    let n = number(&waiting);
    let (_, challenge) = e.pushed(&phone);
    e.advance(120_000);
    let late = answer(&e, phone.answer(challenge, Some(n), Decision::Approve)).await;
    assert_eq!(late.status, StatusCode::GONE);
    assert_eq!(late.json()["code"], "push-challenge-expired");
    let expired = d.poll(&waiting).await;
    assert_eq!(expired.messages(), ["push.expired"]);

    // OP-156 m.3 (d)
    let thief = Approver::new();
    let mut f = e.browser("f");
    let waiting = f.push("rui@example.com").await;
    let n = number(&waiting);
    let (_, challenge) = e.pushed(&phone);
    let forged = answer(
        &e,
        thief.answer_as(phone.thumbprint, challenge, Some(n), Decision::Approve),
    )
    .await;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);
    assert_eq!(forged.json()["code"], "push-answer-refused");
    let unknown = answer(&e, thief.answer(challenge, Some(n), Decision::Approve)).await;
    assert_eq!(unknown.json()["code"], "push-answer-refused");
    // OP-156 m.3 (d)
    let bare = answer(&e, phone.answer(challenge, None, Decision::Approve)).await;
    assert_eq!(bare.json()["code"], "push-number-mismatch");
    assert_ne!(f.poll(&waiting).await.step(), "complete");
}

// OP-156 m.3 (d), §12, Ek B 5400
#[tokio::test]
async fn the_fourth_push_in_ten_minutes_and_a_push_after_a_refusal_are_held() {
    let e = env(0x93, "q5-fatigue", PUSH).await;
    e.account("fay@example.com").await;
    let phone = Approver::new();
    let mut b = e.browser("b");
    b.sign_in("fay@example.com").await;
    phone.register(&mut b, "phone").await;
    let mut open = Vec::new();
    for i in 0..3 {
        let mut w = e.browser(&format!("w{i}"));
        let waiting = w.push("fay@example.com").await;
        assert_eq!(waiting.status, StatusCode::OK);
        open.push((e.pushed(&phone).1, number(&waiting)));
    }
    let sent = e.pushes();
    let mut fourth = e.browser("w3");
    let held = fourth.push("fay@example.com").await;
    assert_eq!(held.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(held.messages(), ["push.held"]);
    assert!(held.headers.get(header::RETRY_AFTER).is_some());
    assert_eq!(e.pushes(), sent, "a held push reaches no device");
    for (challenge, n) in open {
        let ok = answer(&e, phone.answer(challenge, Some(n), Decision::Approve)).await;
        assert_eq!(ok.json()["state"], "approved");
    }

    // OP-156 m.3 (d)
    e.advance(10 * 60_000);
    let mut g = e.browser("g");
    g.push("fay@example.com").await;
    let (_, challenge) = e.pushed(&phone);
    let denied = answer(&e, phone.answer(challenge, None, Decision::Deny)).await;
    assert_eq!(denied.json()["state"], "denied");
    e.advance(14 * 60_000);
    let mut h = e.browser("h");
    assert_eq!(
        h.push("fay@example.com").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    e.advance(60_000);
    let mut i = e.browser("i");
    assert_eq!(i.push("fay@example.com").await.status, StatusCode::OK);
}

// OP-156 m.3 (d), Ek B 5400
#[tokio::test]
async fn three_unanswered_pushes_in_a_row_hold_push_for_an_hour() {
    let e = env(0x94, "q5-unanswered", PUSH).await;
    e.account("uma@example.com").await;
    let phone = Approver::new();
    let mut b = e.browser("b");
    b.sign_in("uma@example.com").await;
    phone.register(&mut b, "phone").await;
    for i in 0..3 {
        let mut w = e.browser(&format!("w{i}"));
        assert_eq!(w.push("uma@example.com").await.status, StatusCode::OK);
        e.advance(4 * 60_000);
    }
    let mut w = e.browser("late");
    let held = w.push("uma@example.com").await;
    assert_eq!(held.status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = held.headers[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry > 50 * 60, "{retry}");
    e.advance(retry * 1000);
    let mut x = e.browser("x");
    assert_eq!(x.push("uma@example.com").await.status, StatusCode::OK);
}

// OP-156 m.3 (d), §7.6 TN-O4, Ek B 5400
#[tokio::test]
async fn this_wasnt_me_stops_the_sign_in_signals_risk_and_tells_the_person() {
    use access_identity_account::domain::claims::Content;
    use access_kernel::model::EqValue;
    let e = env(0x95, "q5-not-me", PUSH).await;
    let subject = e.account("nia@example.com").await;
    let phone = Approver::new();
    let mut b = e.browser("b");
    b.sign_in("nia@example.com").await;
    phone.register(&mut b, "phone").await;
    let mut c = e.browser("c");
    let waiting = c.push("nia@example.com").await;
    let (_, challenge) = e.pushed(&phone);
    let not_me = answer(&e, phone.answer(challenge, None, Decision::NotMe)).await;
    assert_eq!(not_me.json()["state"], "not_me");
    let told = *e.sent().last().unwrap();
    assert_eq!(told.0, "relay.message.semantic_notice.v1");
    assert_eq!(told.2, subject);
    let orders = claim_orders(&e, |o| o.iter().any(|c| c.class == "risk_signal")).await;
    assert!(orders.iter().any(|c| c.class == "risk_signal"
        && c.content == Content::Scalar(EqValue::Text(String::from("push_not_me")))));
    let stopped = c.poll(&waiting).await;
    assert_eq!(stopped.messages(), ["push.not_me"]);
    let submits: Vec<Value> = stopped.json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["type"] == "submit")
        .map(|n| n["method"].clone())
        .collect();
    assert_eq!(submits, [json!("restart")]);
    assert_eq!(
        c.get(&waiting.action()).await.status,
        StatusCode::GONE,
        "the stopped sign-in is over"
    );
}

// OP-156 m.3 (d), OP-73
#[tokio::test]
async fn a_retired_approver_gets_no_push_and_its_answers_are_refused() {
    let e = env(0x96, "q5-retire", PUSH).await;
    e.account("ray@example.com").await;
    let phone = Approver::new();
    let mut b = e.browser("b");
    b.sign_in("ray@example.com").await;
    let id = phone.register(&mut b, "phone").await.json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut c = e.browser("c");
    let waiting = c.push("ray@example.com").await;
    let n = number(&waiting);
    let (_, challenge) = e.pushed(&phone);
    let retired = b.post(&format!("/v1/approvers/{id}/retire"), None).await;
    assert_eq!(retired.status, StatusCode::NO_CONTENT);
    assert_eq!(
        b.post(&format!("/v1/approvers/{id}/retire"), None)
            .await
            .json()["code"],
        "no-such-approver"
    );
    let refused = answer(&e, phone.answer(challenge, Some(n), Decision::Approve)).await;
    assert_eq!(refused.json()["code"], "push-answer-refused");
    let mut d = e.browser("d");
    assert_eq!(d.sign_in("ray@example.com").await.step(), "complete");
}

// OP-156 m.3 (d)
#[tokio::test]
async fn an_approver_that_started_the_sign_in_itself_approves_without_the_number() {
    let e = env(0x97, "q5-same", PUSH).await;
    e.account("sam@example.com").await;
    let phone = Approver::new();
    let mut b = e.browser("b");
    b.sign_in("sam@example.com").await;
    phone.register(&mut b, "phone").await;
    let mut app = e.browser("in-app");
    let second = app.sign_in("sam@example.com").await;
    let handle = second.json()["flow"].as_str().unwrap().to_owned();
    let other = Approver::new();
    let bad = other.sign(&same_device_message(&format!("https://{HOST}"), &handle));
    let refused = app
        .post(
            "/v1/push/challenge",
            Some(
                serde_json::from_str(&same_device_body(&handle, &phone.thumbprint, &bad)).unwrap(),
            ),
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    let proof = phone.sign(&same_device_message(&format!("https://{HOST}"), &handle));
    let waiting = app
        .post(
            "/v1/push/challenge",
            Some(
                serde_json::from_str(&same_device_body(&handle, &phone.thumbprint, &proof))
                    .unwrap(),
            ),
        )
        .await;
    assert_eq!(
        waiting.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&waiting.body)
    );
    let (_, challenge) = e.pushed(&phone);
    let ok = answer(&e, phone.answer(challenge, None, Decision::Approve)).await;
    assert_eq!(ok.json()["state"], "approved");
    assert_eq!(app.poll(&waiting).await.step(), "complete");
}

// OP-156 m.3 (d)
#[tokio::test]
async fn a_realm_without_push_offers_none() {
    let e = env(0x98, "q5-off", AuthPolicy::DEFAULT).await;
    e.account("off@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("off@example.com").await.step(), "complete");
    let phone = Approver::new();
    assert_eq!(
        phone.register(&mut b, "phone").await.status,
        StatusCode::CREATED
    );
    let mut c = e.browser("c");
    assert_eq!(c.sign_in("off@example.com").await.step(), "complete");
    let handle = c.start().await.json()["flow"].as_str().unwrap().to_owned();
    let refused = c
        .post("/v1/push/challenge", Some(json!({ "flow": handle })))
        .await;
    assert_ne!(refused.status, StatusCode::OK);
    assert_eq!(e.pushes(), 0);
}
