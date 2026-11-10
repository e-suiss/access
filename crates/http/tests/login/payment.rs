//! Payment-class authentication on the hosted surface (OP-156 m.3 (e), (f), MD-11, IDP-4, IDP-9,
//! §10.3.4): the restricted SMS code, the SIM change rule, the TR payment profile and the
//! app-controlled factor. The approver is the public SDK's `approver` module with a P-256 key
//! that a test attestation CA certifies, as an Android app's key attestation would.

use std::sync::OnceLock;
use std::time::Duration;

use access_identity_session::domain::assurance::AssuranceProfile;
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_ui::app::payment::attestation_challenge;
use access_sdk::approver::{
    Answer as PushAnswer, Decision, answer_body, registration_body, registration_message,
    thumbprint, to_raw_signature,
};
use access_store::authority::{CommitBatch, HeadRow, NonceRow, acquire_lease, commit_batch};
use access_store::payment::{SimChange, record_sim_change};
use suiss_crypto::cose::PublicKey;

use super::*;

const SMS: AuthPolicy = AuthPolicy {
    sms: true,
    ..AuthPolicy::DEFAULT
};

const TR: AuthPolicy = AuthPolicy {
    sms: true,
    push: true,
    profile: AssuranceProfile::TrPayment,
    ..AuthPolicy::DEFAULT
};

const DAY_MS: u64 = 24 * 60 * 60_000;

/// The attestation CA of these tests, made once per run.
pub(super) fn attestation_ca() -> &'static (rcgen::Issuer<'static, rcgen::KeyPair>, Vec<u8>) {
    static CA: OnceLock<(rcgen::Issuer<'static, rcgen::KeyPair>, Vec<u8>)> = OnceLock::new();
    CA.get_or_init(|| {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test Attestation Root");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = params.self_signed(&key).unwrap().der().to_vec();
        (rcgen::Issuer::new(params, key), root)
    })
}

fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    let n = content.len();
    if n < 0x80 {
        out.push(u8::try_from(n).unwrap());
    } else {
        out.extend([0x81, u8::try_from(n).unwrap()]);
    }
    out.extend_from_slice(content);
    out
}

/// An Android `KeyDescription` of a TEE key generated in hardware on a verified, locked device.
fn key_description(challenge: &[u8]) -> Vec<u8> {
    let root = tlv(
        &[0x30],
        &[
            tlv(&[0x04], &[7; 32]),
            tlv(&[0x01], &[0xff]),
            tlv(&[0x0a], &[0]),
            tlv(&[0x04], &[8; 32]),
        ]
        .concat(),
    );
    let hardware = [
        tlv(&[0xbf, 0x85, 0x3e], &tlv(&[0x02], &[0])),
        tlv(&[0xbf, 0x85, 0x40], &root),
    ]
    .concat();
    tlv(
        &[0x30],
        &[
            tlv(&[0x02], &[0, 200]),
            tlv(&[0x0a], &[1]),
            tlv(&[0x02], &[0, 200]),
            tlv(&[0x0a], &[1]),
            tlv(&[0x04], challenge),
            tlv(&[0x04], &[]),
            tlv(&[0x30], &[]),
            tlv(&[0x30], &hardware),
        ]
        .concat(),
    )
}

/// An approver app with its key in "hardware": the same P-256 key signs answers and is the
/// subject of the attestation leaf.
struct App {
    key: SoftSigner,
    leaf: rcgen::KeyPair,
    public: Vec<u8>,
    thumbprint: [u8; 32],
}

impl App {
    fn new() -> Self {
        let (key, pkcs8) = SoftSigner::generate_p256().unwrap();
        let leaf = rcgen::KeyPair::try_from(pkcs8.expose().as_slice()).unwrap();
        let PublicKey::P256(public) = key.public_key() else {
            panic!("p-256")
        };
        let thumbprint = thumbprint(&public).unwrap();
        Self {
            key,
            leaf,
            public,
            thumbprint,
        }
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        to_raw_signature(&self.key.sign(message).unwrap()).unwrap()
    }

    /// Registers the approver; its external id.
    async fn register(&self, b: &mut Web) -> String {
        let proof = self.sign(&registration_message(
            &format!("https://{HOST}"),
            &self.thumbprint,
        ));
        let body: Value =
            serde_json::from_str(&registration_body("Bank app", &self.public, &proof)).unwrap();
        let made = b.post("/v1/approvers", Some(body)).await;
        assert_eq!(
            made.status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&made.body)
        );
        made.json()["id"].as_str().unwrap().to_owned()
    }

    /// The attestation chain for `challenge`, issued for `subject_key`.
    fn chain(&self, subject_key: &rcgen::KeyPair, challenge: &[u8]) -> Vec<String> {
        let ca = attestation_ca();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                key_description(challenge),
            ));
        let leaf = params.signed_by(subject_key, &ca.0).unwrap().der().to_vec();
        vec![b64url_encode(&leaf), b64url_encode(&ca.1)]
    }

    fn activation(&self, at: u64, chain: Vec<String>, code: Option<&str>) -> Value {
        let mut body = json!({ "at": at, "format": "android-key", "x5c": chain });
        if let Some(c) = code {
            body["activation_code"] = json!(c);
        }
        body
    }

    fn answer(&self, challenge: [u8; 32], number: u8, pin_verified: Option<bool>) -> Value {
        let signed = PushAnswer {
            challenge,
            number: Some(number),
            decision: Decision::Approve,
            device_key: self.thumbprint,
            pin_verified,
        }
        .to_be_signed();
        serde_json::from_str(&answer_body(&signed, &self.sign(&signed))).unwrap()
    }
}

impl Env {
    /// An active account with an e-mail address and a phone number.
    async fn phone_account(&self, who: &str, phone: &str) -> [u8; 16] {
        let pg = PgAccounts::sealed(self.db.app.clone(), self.kit.vault());
        let ids = [
            Identifier::new(IdentifierKind::Email, who).unwrap(),
            Identifier::new(IdentifierKind::Phone, phone).unwrap(),
        ];
        let s = create(&pg, &self.realm(), &ids, &ADMIN).await.unwrap();
        let services = PasswordServices {
            hasher: &self.hasher,
            ranges: &Corpus,
            entropy: &SystemEntropy,
        };
        set_password(&pg, &self.realm(), &services, s, PW, &ADMIN)
            .await
            .unwrap();
        for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
            change_status(&pg, &self.realm(), s, to, &ADMIN)
                .await
                .unwrap();
        }
        s
    }

    /// Binds `subject` to a Party of its own, as its first device Instance would.
    async fn bind_party(&self, subject: [u8; 16]) {
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        access_store::idp::bind_subject_party(&mut tx, &subject, &party_of(subject))
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// An operator's admitted `sim_change` Claim about `subject`'s Party, as the ingest keeps
    /// its disclosed body: a `claim` record in the governing domain, then the signal.
    async fn sim_signal(&self, subject: [u8; 16], last_change_ms: u64, checked_ms: u64) {
        let (lease, head) = acquire_lease(
            &self.db.sequencer,
            &self.domain,
            "t",
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        let pos = head.pos + 1;
        let leaf = [u8::try_from(pos % 200).unwrap().wrapping_add(31); 32];
        let next = HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        };
        commit_batch(
            &self.db.sequencer,
            &self.domain,
            *self.tenant.as_bytes(),
            &CommitBatch {
                epoch: lease.epoch,
                after: head.pos,
                records: vec![LogRecord {
                    pos,
                    kind: "claim",
                    recorded_at: 2,
                    leaf_hash: leaf,
                    envelope: vec![0xa1, 1],
                }],
                head: next,
                nonces: Vec::<NonceRow>::new(),
                outbox: vec![],
                proofs: vec![],
                reads: vec![],
                writes: vec![],
                draws: vec![],
                single_use: vec![],
                effects: vec![],
            },
        )
        .await
        .unwrap();
        let mut tx = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let party = access_store::idp::subject_party(&mut tx, &subject)
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        let mut claim = [0x5d; 16];
        claim[..8].copy_from_slice(&pos.to_be_bytes());
        record_sim_change(
            &self.db.sequencer,
            &self.domain,
            &SimChange {
                subject: party,
                claim,
                issuer: [0x0e; 16],
                pos,
                last_change_ms,
                checked_ms,
            },
        )
        .await
        .unwrap();
    }

    fn now(&self) -> u64 {
        self.clock.now_ms()
    }

    fn sms_count(&self) -> usize {
        self.sent()
            .iter()
            .filter(|s| s.0 == "relay.message.sms_otp.v1")
            .count()
    }
}

fn party_of(subject: [u8; 16]) -> [u8; 16] {
    let mut p = subject;
    p[0] ^= 0xa5;
    p
}

fn has_node(a: &Answer, method: &str) -> bool {
    a.json()["nodes"]
        .as_array()
        .is_some_and(|n| n.iter().any(|x| x["method"] == method))
}

impl Web {
    async fn second(&mut self, who: &str) -> Answer {
        let second = self.sign_in(who).await;
        assert_eq!(
            second.step(),
            "second_factor",
            "{}",
            String::from_utf8_lossy(&second.body)
        );
        second
    }
}

// OP-156 m.3 (f), §10.2.2, IDP-4, IDP-8, Ek B 5397
#[tokio::test]
async fn an_sms_code_is_a_second_step_of_six_digits_five_minutes_and_three_tries() {
    let off = env(0x61, "q6-sms-off", AuthPolicy::DEFAULT).await;
    off.phone_account("ova@example.com", "+905321110001").await;
    let mut b = off.browser("off");
    let first = b.sign_in("ova@example.com").await;
    assert!(!has_node(&first, "send_sms"));

    let e = env(0x62, "q6-sms", SMS).await;
    e.phone_account("sena@example.com", "+905321110002").await;
    let mut b = e.browser("b");
    let second = b.second("sena@example.com").await;
    assert!(has_node(&second, "send_sms") && has_node(&second, "sms"));
    let sent = b.submit(&second, "send_sms", json!({})).await;
    assert_eq!(
        sent.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&sent.body)
    );
    assert!(sent.messages().contains(&String::from("sms.sent")));
    assert!(sent.json().to_string().contains("ending in 02"));
    assert_eq!(e.sms_count(), 1);
    let code = e.outbox.last();
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|c| c.is_ascii_digit()));
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..3 {
        let r = b.submit(&sent, "sms", json!({ "sms_code": wrong })).await;
        assert_eq!(r.messages(), ["second_factor.failed"]);
        e.advance(10_000);
    }
    let spent = b.submit(&sent, "sms", json!({ "sms_code": code })).await;
    assert_eq!(spent.messages(), ["second_factor.failed"]);

    e.advance(30_000);
    let sent = b.submit(&second, "send_sms", json!({})).await;
    let code = e.outbox.last();
    e.advance(300_000);
    let late = b.submit(&sent, "sms", json!({ "sms_code": code })).await;
    assert_eq!(late.messages(), ["second_factor.failed"]);

    e.advance(60_000);
    let sent = b.submit(&second, "send_sms", json!({})).await;
    let code = e.outbox.last();
    let done = b.submit(&sent, "sms", json!({ "sms_code": code })).await;
    assert_eq!(
        done.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    let again = b.submit(&sent, "sms", json!({ "sms_code": code })).await;
    assert_ne!(again.step(), "complete");
}

// IDP-9, §10.2.2, §10.3.4, OP-156 m.3 (f), Ek B 5124
#[tokio::test]
async fn sms_is_refused_thirty_days_after_a_sim_change() {
    let e = env(0x63, "q6-sim", SMS).await;
    let s = e.phone_account("simge@example.com", "+905321110003").await;
    e.bind_party(s).await;
    e.sim_signal(s, e.now() - 30 * DAY_MS, e.now()).await;
    let mut b = e.browser("b");
    let second = b.second("simge@example.com").await;
    let refused = b.submit(&second, "send_sms", json!({})).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(refused.messages().contains(&String::from("sms.refused")));
    assert_eq!(e.sms_count(), 0);

    e.advance(61 * DAY_MS);
    e.sim_signal(s, e.now() - 91 * DAY_MS, e.now()).await;
    let mut b = e.browser("c");
    let second = b.second("simge@example.com").await;
    let sent = b.submit(&second, "send_sms", json!({})).await;
    assert_eq!(sent.status, StatusCode::OK);
    assert_eq!(e.sms_count(), 1);
}

// OP-156 m.3 (e), (f), MD-11, SA-54, Ek B 5116
#[tokio::test]
async fn the_tr_profile_refuses_sms_at_sign_in_and_takes_it_for_activation() {
    let e = env(0x64, "q6-tr-sms", TR).await;
    let s = e.phone_account("tuna@example.com", "+905321110004").await;
    e.bind_party(s).await;
    let mut b = e.browser("b");
    let signed = b.sign_in("tuna@example.com").await;
    assert!(!has_node(&signed, "send_sms"));
    assert_eq!(
        signed.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&signed.body)
    );

    // OP-156 m.3 (f): no fresh SIM signal, no code
    let blind = b.post("/v1/sms/activation", None).await;
    assert_eq!(blind.json()["code"], "sms-refused");
    e.sim_signal(s, e.now() - 200 * DAY_MS, e.now() - 25 * 60 * 60_000)
        .await;
    let stale = b.post("/v1/sms/activation", None).await;
    assert_eq!(stale.json()["code"], "sms-refused");
    assert_eq!(e.sms_count(), 0);
    e.sim_signal(s, e.now() - 200 * DAY_MS, e.now()).await;
    let sent = b.post("/v1/sms/activation", None).await;
    assert_eq!(
        sent.status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(&sent.body)
    );
    assert_eq!(sent.json()["last_digits"], "04");
    assert_eq!(e.sms_count(), 1);

    let app = App::new();
    let id = app.register(&mut b).await;
    let at = e.now();
    let challenge = attestation_challenge(&format!("https://{HOST}"), &app.thumbprint, at);
    let path = format!("/v1/approvers/{id}/activate");
    let without = b
        .post(
            &path,
            Some(app.activation(at, app.chain(&app.leaf, &challenge), None)),
        )
        .await;
    assert_eq!(without.json()["code"], "activation-code-required");
    let code = e
        .outbox
        .0
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|c| c.len() == 6)
        .cloned();
    let activated = b
        .post(
            &path,
            Some(app.activation(at, app.chain(&app.leaf, &challenge), code.as_deref())),
        )
        .await;
    assert_eq!(
        activated.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&activated.body)
    );
    assert_eq!(activated.json()["pin_policy"], "app_pin");
}

// MD-11, IDP-9, §10.3.3, OP-156 m.3 (e), Ek B 5395
#[tokio::test]
async fn only_an_attested_key_with_its_app_pin_is_the_app_controlled_factor() {
    use access_identity_session::domain::assurance::AssuranceVector;
    let e = env(
        0x65,
        "q6-app",
        AuthPolicy {
            push: true,
            ..AuthPolicy::DEFAULT
        },
    )
    .await;
    let subject = e.phone_account("ada@example.com", "+905321110005").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("ada@example.com").await.step(), "complete");
    let app = App::new();
    let id = app.register(&mut b).await;
    let path = format!("/v1/approvers/{id}/activate");
    let at = e.now();
    let challenge = attestation_challenge(&format!("https://{HOST}"), &app.thumbprint, at);

    // L21: the attested key must be the approver's, for this approver's challenge, now
    let stranger = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let other = b
        .post(
            &path,
            Some(app.activation(at, app.chain(&stranger, &challenge), None)),
        )
        .await;
    assert_eq!(other.json()["code"], "attestation-other-key");
    let wrong = b
        .post(
            &path,
            Some(app.activation(at, app.chain(&app.leaf, &[9; 32]), None)),
        )
        .await;
    assert_eq!(wrong.json()["code"], "attestation-refused");
    let old = at - 600_000;
    let stale_challenge = attestation_challenge(&format!("https://{HOST}"), &app.thumbprint, old);
    let stale = b
        .post(
            &path,
            Some(app.activation(old, app.chain(&app.leaf, &stale_challenge), None)),
        )
        .await;
    assert_eq!(stale.json()["code"], "attestation-stale");

    // a plain push: the approver is not activated yet, so the step is push
    let push_step = |e: &Env| {
        let (_, texts) = e.outbox.2.lock().unwrap().last().cloned().unwrap();
        <[u8; 32]>::try_from(b64url_decode(&texts[0]).unwrap()).unwrap()
    };
    let methods = async |e: &Env, pin: Option<bool>, name: &str| {
        let mut c = e.browser(name);
        let second = c.second("ada@example.com").await;
        let waiting = c.submit(&second, "push", json!({})).await;
        let number = waiting.json()["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["type"] == "push_number")
            .and_then(|n| n["number"].as_u64())
            .unwrap();
        let challenge = push_step(e);
        let answered = e
            .browser("approver")
            .send(
                "POST",
                "/v1/push/answer",
                Some(app.answer(challenge, u8::try_from(number).unwrap(), pin)),
                None,
            )
            .await;
        assert_eq!(answered.status, StatusCode::OK);
        let done = c.get(&waiting.action()).await;
        assert_eq!(
            done.step(),
            "complete",
            "{}",
            String::from_utf8_lossy(&done.body)
        );
        let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
        let newest = tx.live_sessions(subject).await.unwrap().remove(0);
        tx.commit().await.unwrap();
        let v: AssuranceVector = serde_json::from_slice(&newest.assurance).unwrap();
        v.app_controlled_factor
    };
    assert!(!methods(&e, Some(true), "plain").await);

    let activated = b
        .post(
            &path,
            Some(app.activation(at, app.chain(&app.leaf, &challenge), None)),
        )
        .await;
    assert_eq!(
        activated.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&activated.body)
    );
    e.advance(11 * 60_000);
    assert!(!methods(&e, None, "nopin").await);
    e.advance(11 * 60_000);
    assert!(!methods(&e, Some(false), "pinfalse").await);
    e.advance(11 * 60_000);
    assert!(methods(&e, Some(true), "pin").await);
}

/// A signed-in approver with a passkey and a device Instance, and the coordinator that pushes
/// requests to the Approval Surface, as in `an_approval_runs_on_the_hosted_surface`.
struct Approving {
    c: Web,
    coordinator: Web,
    key: Authenticator,
    id: String,
    user: String,
    ais: Vec<u8>,
    uri: String,
}

const REDIRECT: &str = "https://shop.example/approved";

impl Env {
    async fn approving(&self, who: &str) -> Approving {
        use access_kernel::verify::key_scope::thumbprint;
        self.client(REDIRECT).await;
        let mut b = self.browser("b-approve");
        assert_eq!(b.sign_in(who).await.step(), "complete");
        let (mut key, id, user) = register_passkey(&mut b, who).await;
        let mut c = self.browser("c-approve");
        let second = c.sign_in(who).await;
        assert_eq!(second.step(), "second_factor");
        let options = passkey_node(&second);
        let challenge = b64url_decode(options["challenge"].as_str().unwrap()).unwrap();
        let signed = c
            .submit(
                &second,
                "passkey",
                json!({ "passkey_credential": assertion_json(&mut key, &id, &user, &challenge).to_string() }),
            )
            .await;
        assert_eq!(
            signed.step(),
            "complete",
            "{}",
            String::from_utf8_lossy(&signed.body)
        );
        let (device, _) = SoftSigner::generate_ed25519().unwrap();
        let ch = c.post("/v1/me/instances/challenges", None).await;
        let registered = c
            .post(
                "/v1/me/instances",
                Some(json!({
                    "challenge": ch.json()["challenge"],
                    "party": b64url_encode(&[8; 16]),
                    "key": b64url_encode(&access_identity_session::domain::device::cose_key(&device.public_key())),
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2026-01-01T00:05:00Z",
                    "ais": b64url_encode(&[0xd2; 40]),
                    "register_ais": b64url_encode(&[0xd2; 40]),
                })),
            )
            .await;
        assert_eq!(registered.status, StatusCode::CREATED);
        let kid = thumbprint(&device.public_key());
        let ais = sign_sign1(&device, kid, "application/access-ais+cbor", b"contribute").unwrap();
        Approving {
            c,
            coordinator: self.browser("work"),
            key,
            id,
            user,
            ais,
            uri: String::new(),
        }
    }
}

impl Approving {
    /// Pushes a request and opens it: the started flow.
    async fn open(&mut self, e: &Env, nonce: u8) -> Value {
        let push = json!({
            "request": {
                "requester": { "party": b64url_encode(&[1; 16]), "instance": b64url_encode(&[2; 16]) },
                "action": { "namespace": "shop", "name": "refund", "major": 1, "schema": b64url_encode(&[1; 32]) },
                "resource": { "namespace": "shop", "path": ["orders", "o-1042"], "incarnation": 0 },
                "params": { "amount": { "amount": { "value": 4200, "unit": "eur" } } },
                "capacity": "own",
                "reason": "Pay for the coffee order.",
                "require_action": {
                    "domain": b64url_encode(e.domain.as_bytes()),
                    "nonce": b64url_encode(&[nonce; 16]),
                    "intent": b64url_encode(&[0x44; 32]),
                },
                "expires_at": e.clock.now_ms() + 3_600_000,
            },
            "contribution": {
                "nonce": b64url_encode(&[nonce; 16]),
                "basis": { "grant": b64url_encode(&[1; 16]), "holder": b64url_encode(&[8; 16]), "since": 0 },
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-01-01T00:05:00Z",
                "ais": b64url_encode(&self.ais),
            },
        });
        let pushed = self
            .coordinator
            .post("/v1/approve/requests", Some(push))
            .await;
        assert_eq!(pushed.status, StatusCode::CREATED);
        let uri = pushed.json()["request_uri"].as_str().unwrap().to_owned();
        self.uri.clone_from(&uri);
        let started = self
            .c
            .post(
                "/v1/approve/flows",
                Some(json!({ "request": uri, "redirect_uri": REDIRECT, "state": "st-1" })),
            )
            .await;
        assert_eq!(
            started.status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&started.body)
        );
        started.json()
    }

    fn statement(started: &Value) -> Vec<u8> {
        b64url_decode(started["options"]["challenge"].as_str().unwrap()).unwrap()
    }

    /// A Secure Payment Confirmation assertion over `challenge` that shows `payment`.
    fn spc(&mut self, challenge: &[u8], payment: &Value) -> Value {
        self.key.counter += 1;
        let cdj = json!({
            "type": "payment.get",
            "challenge": b64url_encode(challenge),
            "origin": ORIGIN,
            "crossOrigin": false,
            "payment": payment,
        })
        .to_string()
        .into_bytes();
        let ad = self.key.auth_data(RP_ID, false);
        let mut message = ad.clone();
        message.extend_from_slice(&support::sha256(&cdj));
        let sig = self.key.key.sign(&message);
        json!({
            "id": self.id, "rawId": self.id, "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(&cdj),
                "authenticatorData": b64url_encode(&ad),
                "signature": b64url_encode(&sig),
                "userHandle": self.user,
            },
            "clientExtensionResults": {},
        })
    }

    async fn finish(&mut self, started: &Value, credential: Value, app: Option<Value>) -> Answer {
        let mut body =
            json!({ "credential": credential, "redirect_uri": REDIRECT, "state": "st-1" });
        if let Some(a) = app {
            body["app_factor"] = a;
        }
        self.c
            .post(
                &format!("/v1/approve/flows/{}", started["flow"].as_str().unwrap()),
                Some(body),
            )
            .await
    }
}

fn shown(value: &str) -> Value {
    json!({
        "rpId": RP_ID,
        "topOrigin": ORIGIN,
        "payeeName": "Kahve Evi",
        "total": { "currency": "EUR", "value": value },
        "instrument": { "displayName": "Acme", "icon": "" },
    })
}

const SPC: AuthPolicy = AuthPolicy {
    spc: true,
    ..AuthPolicy::DEFAULT
};

// §9.4 G, §9.4.1, OP-156 m.3 (g), Ek B 5120
#[tokio::test]
async fn an_spc_assertion_counts_only_for_the_canonical_render() {
    use access_identity_account::domain::claims::Bind;
    let e = env(0x66, "q6-spc", SPC).await;
    e.account("pay@example.com").await;
    e.surface.payment.store(true, Ordering::SeqCst);
    let mut a = e.approving("pay@example.com").await;

    let started = a.open(&e, 30).await;
    // OP-156 m.3 (g): payment opens on the Approval Surface only
    let page =
        a.c.get(&format!(
            "/v1/approve?request={}&redirect_uri=https%3A%2F%2Fshop.example%2Fapproved&state=st-1",
            a.uri
        ))
        .await;
    assert_eq!(page.status, StatusCode::OK);
    let policies: Vec<&str> = page
        .headers
        .get_all("permissions-policy")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(
        policies,
        [access_identity_ui::domain::spc::SPC_PERMISSIONS_POLICY]
    );
    let login = a.c.get("/login").await;
    assert!(
        login.headers["permissions-policy"]
            .to_str()
            .unwrap()
            .contains("payment=()")
    );
    assert_eq!(started["spc"]["payeeName"], "Kahve Evi", "{started}");
    assert_eq!(
        started["spc"]["total"],
        json!({ "currency": "EUR", "value": "42.00" })
    );
    let statement = Approving::statement(&started);
    // §9.4.1: one cent more is no confirmation
    let more = a.spc(&statement, &shown("42.01"));
    let refused = a.finish(&started, more, None).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.json()["code"], "spc-mismatch");
    assert!(e.surface.contributions.lock().unwrap().is_empty());
    let exact = a.spc(&statement, &shown("42.00"));
    let done = a.finish(&started, exact, None).await;
    assert_eq!(
        done.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    let orders = e.claims.0.lock().unwrap().clone();
    let last = orders.last().unwrap();
    assert_eq!(last.class, "authentication");
    assert_eq!(
        last.bind,
        Bind::Statement {
            statement: <[u8; 32]>::try_from(statement.as_slice()).unwrap(),
            instance: [9; 16],
        }
    );
    assert_eq!(e.surface.contributions.lock().unwrap().len(), 1);

    // OP-156 m.3 (g): a realm that did not open SPC takes none
    let closed = env(0x67, "q6-spc-off", AuthPolicy::DEFAULT).await;
    closed.account("pay@example.com").await;
    closed.surface.payment.store(true, Ordering::SeqCst);
    let mut a = closed.approving("pay@example.com").await;
    let started = a.open(&closed, 31).await;
    assert!(started.get("spc").is_none());
    let statement = Approving::statement(&started);
    let spc = a.spc(&statement, &shown("42.00"));
    assert_eq!(
        a.finish(&started, spc, None).await.json()["code"],
        "spc-mismatch"
    );
}

/// The app's signature over the statement: the app-controlled factor of an approval.
fn app_factor(app: &App, statement: &[u8]) -> Value {
    let message = access_identity_ui::domain::approval::app_factor_message(
        &format!("https://{HOST}"),
        &<[u8; 32]>::try_from(statement).unwrap(),
    );
    json!({
        "device_key": b64url_encode(&app.thumbprint),
        "signature": b64url_encode(&app.sign(&message)),
    })
}

// PSD2 RTS Art. 4, 5, §10.3.4, §18.2, H17, MD-11, SA-54, OP-156 m.3 (e), (g), Ek B 5116, 5341
#[tokio::test]
async fn a_tr_payment_approval_needs_two_independent_elements_bound_to_amount_and_payee() {
    let e = env(0x68, "q6-psd2", AuthPolicy { spc: true, ..TR }).await;
    let s = e.phone_account("emre@example.com", "+905321110008").await;
    e.surface.payment.store(true, Ordering::SeqCst);
    e.surface.tier.store(2, Ordering::SeqCst);
    let mut a = e.approving("emre@example.com").await;

    // the app-controlled factor: an approver activated with the SMS activation code
    e.sim_signal(s, e.now() - 200 * DAY_MS, e.now()).await;
    let sent = a.c.post("/v1/sms/activation", None).await;
    assert_eq!(
        sent.status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(&sent.body)
    );
    let code = e.outbox.last();
    let app = App::new();
    let device = app.register(&mut a.c).await;
    let at = e.now();
    let challenge = attestation_challenge(&format!("https://{HOST}"), &app.thumbprint, at);
    let activated =
        a.c.post(
            &format!("/v1/approvers/{device}/activate"),
            Some(app.activation(at, app.chain(&app.leaf, &challenge), Some(&code))),
        )
        .await;
    assert_eq!(
        activated.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&activated.body)
    );
    e.advance(25 * 60 * 60_000);

    // MD-11: the passkey alone, biometrics included, meets no CT2 here
    let started = a.open(&e, 40).await;
    let statement = Approving::statement(&started);
    let alone = assertion_json(&mut a.key, &a.id, &a.user, &statement);
    let refused = a.finish(&started, alone, None).await;
    assert_eq!(refused.json()["code"], "app-factor-required");
    assert!(e.surface.contributions.lock().unwrap().is_empty());

    // dynamic linking: the app's factor over another statement does not count
    let other = app_factor(&app, &[7; 32]);
    let credential = a.spc(&statement, &shown("42.00"));
    let wrong = a.finish(&started, credential, Some(other)).await;
    assert_eq!(wrong.json()["code"], "app-factor-refused");

    // dynamic linking: the amount shown must be the statement's
    let started = a.open(&e, 41).await;
    let statement = Approving::statement(&started);
    let credential = a.spc(&statement, &shown("43.00"));
    let changed = a
        .finish(&started, credential, Some(app_factor(&app, &statement)))
        .await;
    assert_eq!(changed.json()["code"], "spc-mismatch");

    // possession (the passkey over H(AAS)) and knowledge (the app PIN over H(AAS))
    let started = a.open(&e, 42).await;
    let statement = Approving::statement(&started);
    let credential = a.spc(&statement, &shown("42.00"));
    let done = a
        .finish(&started, credential, Some(app_factor(&app, &statement)))
        .await;
    assert_eq!(
        done.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    let orders = e.claims.0.lock().unwrap().clone();
    let last = orders.last().unwrap();
    assert_eq!(last.assurance.get("app_controlled_factor"), Some(&1));
    assert_eq!(last.assurance.get("phishing_resistant"), Some(&1));
    // MD-11: platform UV is no factor under the profile
    assert_eq!(last.assurance.get("uv"), Some(&0));
    assert_eq!(e.surface.contributions.lock().unwrap().len(), 1);
}
