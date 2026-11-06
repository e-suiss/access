//! The PEP side (§9.5, §9.5.2 k.6, k.8, §9.9.2, §13.4 U1, U6, U60, L2-RCP-3, CR-52, X21, TI-9).

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::cell::RefCell;
use std::marker::PhantomData;

use access_kernel::ais::{self, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::ContextRefs;
use access_kernel::json::b64url_encode;
use access_kernel::receipt::ReceiptError;
use access_sdk::authorize::{
    Actor, Ask, AskDecision, Authorized, CausalBinding, Class, Denied, ExerciseRequest, Intent,
    Nonce, Refusal, adp_body,
};
use access_sdk::transport::{Answer, Clock, Fault, FixedClock, Response};
use support::{
    Door, HOLDER_SEED, NOW, Open, PEP, allow_body, ask, basis, domain, envelope, intent,
    intent_hash, nonce, ok, pep, receipt_for, sign1, status,
};

struct Scripted {
    answer: RefCell<Option<Answer>>,
    seen: RefCell<Option<String>>,
}

impl Scripted {
    fn new(answer: Answer) -> Self {
        Self {
            answer: RefCell::new(Some(answer)),
            seen: RefCell::new(None),
        }
    }
}

impl AskDecision for Scripted {
    fn ask(&self, request: &ExerciseRequest<'_>) -> Answer {
        *self.seen.borrow_mut() = adp_body(request);
        self.answer
            .borrow_mut()
            .take()
            .unwrap_or(Answer::Unanswered(Fault::Transport))
    }
}

struct NoClock;
impl Clock for NoClock {
    fn now(&self) -> Option<u64> {
        None
    }
}

fn healthy() -> Answer {
    ok(allow_body(
        &receipt_for(nonce().as_bytes(), PEP, &intent_hash()),
        "",
    ))
}

fn run(answer: Answer) -> Result<Authorized<Door, Open>, Denied> {
    let (i, n, b) = (intent(), nonce(), basis());
    let actor = Actor::Anonymous;
    pep().authorize(
        &ask(&i, &n, &actor, &b),
        &FixedClock(NOW),
        &Scripted::new(answer),
    )
}

// §9.5.2 k.6, CR-52, K08, §13.4 U1
#[test]
fn an_allow_with_a_receipt_for_this_intent_nonce_and_audience_authorizes_once() {
    let a = run(healthy()).unwrap();
    assert_eq!(a.intent(), &intent_hash());
    assert_eq!(a.as_of(), support::RECORD);
    assert_eq!(a.causal_binding(), None);
    let exercise = *a.exercise();
    let ran = a
        .apply(&intent_hash(), |evidence| {
            assert_eq!(evidence.exercise, &exercise);
            assert_eq!(evidence.as_of, support::RECORD);
            7
        })
        .unwrap();
    assert_eq!(ran, 7);
}

// INV-19, §13.4 U6
#[test]
fn the_executed_body_must_be_the_approved_digest() {
    let a = run(healthy()).unwrap();
    let mut ran = false;
    let r = a.apply(&Digest([0xee; 32]), |_| ran = true);
    assert_eq!(r.unwrap_err(), Denied::Body);
    assert!(!ran);
}

// CR-52: the proof is built only here and cannot be duplicated
#[test]
fn authorized_is_not_clone_and_has_no_public_constructor() {
    trait Probe {
        const IS_CLONE: bool = false;
    }
    struct Of<T>(PhantomData<T>);
    impl<T> Probe for Of<T> {}
    impl<T: Clone> Of<T> {
        #[allow(dead_code, reason = "resolved by name")]
        const IS_CLONE: bool = true;
    }
    const {
        assert!(!<Of<Authorized<Door, Open>>>::IS_CLONE);
        assert!(<Of<Digest>>::IS_CLONE);
    }
}

// §9.5 "Access-unavailable", §9.5.2 k.8, MD-8, X21, TI-9, INV-26
#[test]
fn every_fault_is_a_denial_and_never_an_allow() {
    let cases: Vec<(Answer, Denied)> = vec![
        (
            Answer::Unanswered(Fault::Timeout),
            Denied::Unavailable(Fault::Timeout),
        ),
        (
            Answer::Unanswered(Fault::Unreachable),
            Denied::Unavailable(Fault::Unreachable),
        ),
        (status(500), Denied::Status(500)),
        (status(503), Denied::Status(503)),
        (status(400), Denied::Status(400)),
        (status(429), Denied::Status(429)),
        (ok(b"not json".to_vec()), Denied::Malformed),
        (ok(b"{\"context\":{}}".to_vec()), Denied::Malformed),
        (ok(b"{\"decision\":\"true\"}".to_vec()), Denied::Malformed),
        (
            ok(br#"{"decision":false,"context":{"outcome":"deny"}}"#.to_vec()),
            Denied::Refused(Refusal::Deny),
        ),
        (
            ok(br#"{"decision":false,"context":{"outcome":"require_action"}}"#.to_vec()),
            Denied::Refused(Refusal::RequireAction),
        ),
        (
            ok(br#"{"decision":false}"#.to_vec()),
            Denied::Refused(Refusal::Other),
        ),
        (
            ok(br#"{"decision":true,"context":{"outcome":"allow"}}"#.to_vec()),
            Denied::NoReceipt,
        ),
        (
            ok(br#"{"decision":true,"context":{"receipt":{"sign1":"AAAA"}}}"#.to_vec()),
            Denied::NoReceipt,
        ),
        (
            ok(
                br#"{"decision":true,"context":{"receipt":{"sign1":"AAAA","excerpt":"AAAA"}}}"#
                    .to_vec(),
            ),
            Denied::Receipt(ReceiptError::Malformed),
        ),
    ];
    for (answer, expected) in cases {
        let denied = run(answer).unwrap_err();
        assert_eq!(denied, expected);
    }
    assert_eq!(Denied::Unavailable(Fault::Timeout).class(), Class::Unknown);
    assert_eq!(Denied::Refused(Refusal::Deny).class(), Class::Decision);
    assert_eq!(Denied::NoReceipt.class(), Class::Unverified);
}

// T25: no trusted time, no decision
#[test]
fn without_trusted_time_nothing_is_authorized() {
    let (i, n, b) = (intent(), nonce(), basis());
    let actor = Actor::Anonymous;
    let port = Scripted::new(healthy());
    let r = pep().authorize(&ask(&i, &n, &actor, &b), &NoClock, &port);
    assert_eq!(r.unwrap_err(), Denied::Clock);
    assert!(port.seen.borrow().is_none(), "nothing was asked");
}

// L2-RCP-3, §9.8: one intent, one PEP, one Exercise
#[test]
fn a_receipt_for_another_intent_audience_or_nonce_is_denied() {
    let other_intent = receipt_for(nonce().as_bytes(), PEP, &Digest([8; 32]));
    assert_eq!(
        run(ok(allow_body(&other_intent, ""))).unwrap_err(),
        Denied::Receipt(ReceiptError::Intent)
    );
    let other_pep = receipt_for(nonce().as_bytes(), "other.example", &intent_hash());
    assert_eq!(
        run(ok(allow_body(&other_pep, ""))).unwrap_err(),
        Denied::Receipt(ReceiptError::Audience)
    );
    let other_nonce = receipt_for(&[0xcd; 16], PEP, &intent_hash());
    assert_eq!(
        run(ok(allow_body(&other_nonce, ""))).unwrap_err(),
        Denied::Exercise
    );
    let mut future = receipt_for(nonce().as_bytes(), PEP, &intent_hash());
    future.iat = NOW + 10 * ais::SKEW_MS;
    assert_eq!(
        run(ok(allow_body(&future, ""))).unwrap_err(),
        Denied::Receipt(ReceiptError::Future)
    );
}

// §9.9.2, §13.4 U8, E17: the upstream receipt is a causal reference, never authority
#[test]
fn an_upstream_receipt_is_only_a_causal_reference_for_a_downstream_pep() {
    let upstream = run(healthy()).unwrap();
    let mut downstream = pep();
    downstream.audience = "downstream.example".to_owned();
    let mut e = envelope();
    e.context = ContextRefs {
        upstream_exercise: Some(*upstream.exercise()),
        ..ContextRefs::default()
    };
    let i: Intent<Door, Open> = Intent::of(e).unwrap();
    let n = Nonce::new(vec![0x11; 32]).unwrap();
    let (b, actor) = (basis(), Actor::Anonymous);
    // the upstream PEP's receipt, replayed to the downstream PEP
    let replayed = Scripted::new(ok(allow_body(
        &receipt_for(nonce().as_bytes(), PEP, &intent_hash()),
        "",
    )));
    let r = downstream.authorize(&ask(&i, &n, &actor, &b), &FixedClock(NOW), &replayed);
    assert_eq!(r.unwrap_err(), Denied::Receipt(ReceiptError::Audience));
    let body = replayed.seen.borrow().clone().unwrap();
    assert!(body.contains(&format!(
        r#""upstream_exercise":"{}""#,
        b64url_encode(&upstream.exercise().0)
    )));
    // the downstream PEP's own decision names the link
    let own = receipt_for(n.as_bytes(), "downstream.example", i.digest());
    let port = Scripted::new(ok(allow_body(&own, r#","causal_binding":"audit-only""#)));
    let a = downstream
        .authorize(&ask(&i, &n, &actor, &b), &FixedClock(NOW), &port)
        .unwrap();
    assert_eq!(a.causal_binding(), Some(CausalBinding::AuditOnly));
    assert_ne!(a.exercise(), upstream.exercise());
}

// §13.4 U60, §9.7A.3, P44, INV-41
#[test]
fn a_decision_older_than_the_protected_content_is_refused() {
    let (i, n, b) = (intent(), nonce(), basis());
    let actor = Actor::Anonymous;
    let mut a = ask(&i, &n, &actor, &b);
    a.content_position = Some(support::RECORD + 1);
    let r = pep().authorize(&a, &FixedClock(NOW), &Scripted::new(healthy()));
    assert_eq!(r.unwrap_err(), Denied::Stale);
    a.content_position = Some(support::RECORD);
    assert!(
        pep()
            .authorize(&a, &FixedClock(NOW), &Scripted::new(healthy()))
            .is_ok()
    );
}

fn statement(nonce: &[u8], pep: &str, intent: &Digest) -> Actor {
    let s = Statement {
        domain: domain(),
        nonce: nonce.to_vec(),
        intent: *intent,
        mode: Mode::Commit,
        pep: pep.to_owned(),
        capacity: Capacity::Own,
        basis: basis(),
        iat: NOW - 500,
        exercise: None,
    };
    Actor::Statement(sign1(
        HOLDER_SEED,
        ais::CONTENT_TYPE,
        &s.to_bytes().unwrap(),
    ))
}

// §9.5 k.2, k.3, §8.17.10.3, E17, X21, PI-7: the actor is the Instance that signed; the PEP
// forwards the statement and cannot bind it to another request
#[test]
fn the_actor_statement_is_forwarded_as_signed_and_must_be_this_requests() {
    let (i, n, b) = (intent(), nonce(), basis());
    let actor = statement(n.as_bytes(), PEP, &intent_hash());
    let port = Scripted::new(healthy());
    let a = pep()
        .authorize(&ask(&i, &n, &actor, &b), &FixedClock(NOW), &port)
        .unwrap();
    assert_eq!(a.as_of(), support::RECORD);
    let body = port.seen.borrow().clone().unwrap();
    let Actor::Statement(bytes) = &actor else {
        panic!("ed25519 key")
    };
    assert!(body.contains(&format!(r#""ais":"{}""#, b64url_encode(bytes))));
    assert!(body.contains(r#""subject":{"type":"access_actor","id":"-"}"#));
    assert!(
        !body.contains(PEP),
        "the PEP's identity is transport, not a member"
    );
    for (bad, field) in [
        (statement(&[0xcd; 16], PEP, &intent_hash()), "nonce"),
        (
            statement(n.as_bytes(), "other.example", &intent_hash()),
            "pep",
        ),
        (statement(n.as_bytes(), PEP, &Digest([8; 32])), "intent"),
        (Actor::Statement(vec![1, 2, 3]), "payload"),
    ] {
        let port = Scripted::new(healthy());
        let r = pep().authorize(&ask(&i, &n, &bad, &b), &FixedClock(NOW), &port);
        assert_eq!(r.unwrap_err(), Denied::Actor(field));
        assert!(port.seen.borrow().is_none(), "{field}: nothing was asked");
    }
}

// L1-ADP-5 to L1-ADP-8
#[test]
fn the_request_body_carries_the_access_members_in_context() {
    let (i, n, b) = (intent(), nonce(), basis());
    let actor = Actor::Anonymous;
    let request = ExerciseRequest {
        domain: &domain(),
        mode: Mode::Commit,
        nonce: n.as_bytes(),
        intent: i.digest(),
        envelope: i.envelope(),
        actor: &actor,
        basis: &b,
        capacity: Capacity::Own,
        pep: PEP,
        exercise: None,
    };
    let body = adp_body(&request).unwrap();
    assert!(body.starts_with(r#"{"subject":{"type":"access_actor","id":"-"},"action":{"name":"open"},"resource":{"type":"door","id":"1"},"context":{"#));
    assert!(body.contains(&format!(r#""domain":"{}""#, b64url_encode(&domain().0))));
    assert!(body.contains(r#""mode":"commit""#));
    assert!(body.contains(&format!(r#""nonce":"{}""#, b64url_encode(n.as_bytes()))));
    assert!(body.contains(r#""basis":{"public":""#));
    assert!(body.contains(r#""capacity":"own""#));
    assert!(
        body.contains(
            r#""intent":{"action":{"namespace":"door","name":"open","major":1,"schema":""#
        )
    );
    assert!(body.contains(r#""resources":[{"namespace":"door","path":["1"],"incarnation":0}]"#));
    assert!(body.contains(r#""validity":{"from":0,"until":"#));
    assert!(!body.contains("ais"));
    let approved: Intent<Door, Open> = Intent::approved(intent_hash(), None);
    let without_envelope = ExerciseRequest {
        envelope: approved.envelope(),
        ..request
    };
    assert_eq!(adp_body(&without_envelope), None);
}

// K08: the proof is typed by the resource and the action of its intent
#[test]
fn an_envelope_of_another_action_or_resource_is_not_this_intent() {
    use access_sdk::authorize::IntentError;
    let mut e = envelope();
    e.action.name = "close".to_owned();
    assert_eq!(
        Intent::<Door, Open>::of(e).unwrap_err(),
        IntentError::Action
    );
    let mut e = envelope();
    e.resources[0].namespace = "window".to_owned();
    assert_eq!(
        Intent::<Door, Open>::of(e).unwrap_err(),
        IntentError::Resource
    );
    let _ = Nonce::new(vec![0; 15]).unwrap_err();
    let _ = Nonce::new(vec![0; 65]).unwrap_err();
    let _ = Ask {
        intent: &intent(),
        nonce: &nonce(),
        actor: &Actor::Anonymous,
        basis: &basis(),
        capacity: Capacity::Own,
        continued: None,
        content_position: None,
    };
    let _ = Response::new(200, Vec::new());
}
