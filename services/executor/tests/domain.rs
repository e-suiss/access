//! The executor's pure core: the history fold, the next command at each re-check point, the
//! delayed-commit window, the drivers and the Web Bot Auth signature.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::collections::BTreeMap;

use access_executor::domain::Kind;
use access_executor::domain::history::{Confirmed, Event, Job, Outcome, Reading, Request, Started};
use access_executor::domain::machine::{Follow, Next, next, settle};
use access_executor::domain::step::{Call, Reversibility, StepSpec, idempotency_key, step_ref};
use access_executor::domain::webbot::{self, Params};
use access_executor::drivers;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::json::b64url_encode;
use access_kernel::model::{ActionRef, ResourceRef, Window};
use suiss_crypto::signer::{Signer as _, SoftSigner};

const NOW: u64 = 1_800_000_000_000;

fn envelope() -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: ActionRef {
            namespace: String::from("mail"),
            name: String::from("send"),
            major: 1,
            schema: Digest([7; 32]),
        },
        resources: vec![ResourceRef {
            namespace: String::from("mail"),
            path: vec![String::from("outbox")],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: NOW - 1_000,
            until: NOW + 3_600_000,
        },
    }
}

fn spec(name: &str, reversibility: Reversibility, idempotent: bool) -> StepSpec {
    StepSpec {
        name: String::from(name),
        action: String::from("mail/send"),
        resource: String::from("mail:outbox"),
        reversibility,
        idempotent,
        call: Call::Http {
            method: String::from("POST"),
            url: String::from("https://api.mail.example/v1/send"),
            body: Some(serde_json::json!({ "to": "a@example.org" })),
        },
    }
}

fn started(kind: Kind, steps: Vec<StepSpec>) -> Event {
    Event::Started(Box::new(Started {
        job: [1; 16],
        kind,
        domain: [2; 32],
        exercise: [3; 32],
        intent: envelope().to_bytes().unwrap(),
        ais: vec![0xd2],
        realm: String::from("acme"),
        connection: String::from("c"),
        steps,
        commit_window_ms: access_executor::domain::COMMIT_WINDOW_MS,
        at: NOW,
    }))
}

fn job(events: &[Event]) -> Job {
    Job::replay(events).unwrap()
}

fn done(step: u32) -> [Event; 4] {
    [
        Event::Outbox {
            step,
            key: [0; 32],
            request: [0; 32],
            at: NOW,
        },
        Event::Answered {
            step,
            status: 200,
            body: [9; 32],
            reading: Reading::Confirmed,
            at: NOW,
        },
        Event::Outcome {
            step,
            outcome: Outcome::Done,
            evidence: vec![access_executor::domain::history::Evidence::UpstreamConfirmation],
            at: NOW,
        },
        Event::Attested {
            step,
            claim: vec![1; 16],
            refused: None,
            at: NOW,
        },
    ]
}

fn released() -> Event {
    Event::Released {
        step: 0,
        use_until: NOW + 600_000,
        at: NOW,
    }
}

// E62 (1)
#[test]
fn a_history_replays_to_the_same_job_after_a_round_trip_through_text() {
    let mut events = vec![started(
        Kind::Cloud,
        vec![spec("send", Reversibility::Reversible, true)],
    )];
    events.push(released());
    events.extend(done(0));
    let text: Vec<String> = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect();
    let again: Vec<Event> = text
        .iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect();
    assert_eq!(again, events);
    assert_eq!(job(&again), job(&events));
    assert_eq!(next(&job(&events), NOW, true), Next::Done);
    assert!(Job::replay(&events[1..]).is_err());
}

// E62 (2), OP-154 m.3 (u)
#[test]
fn the_idempotency_key_is_the_exercise_and_step_digest_and_goes_upstream() {
    let s = spec("send", Reversibility::Reversible, true);
    let exercise = Digest([3; 32]);
    let step = step_ref(&exercise, 0, &s);
    let key = idempotency_key(&exercise, &step);
    assert_ne!(step, step_ref(&exercise, 1, &s));
    assert_ne!(key, idempotency_key(&Digest([4; 32]), &step));
    let j = job(&[started(Kind::Cloud, vec![s.clone()])]);
    assert_eq!(j.steps[0].key, key);
    let req = drivers::request(&s, &key);
    assert!(
        req.headers
            .contains(&(String::from("Idempotency-Key"), b64url_encode(&key.0)))
    );
    assert!(!req.headers.iter().any(|(k, _)| k == "Authorization"));
    let mcp = StepSpec {
        call: Call::Mcp {
            server: String::from("https://mcp.mail.example/mcp"),
            tool: String::from("send_mail"),
            arguments: serde_json::json!({ "to": "a@example.org" }),
        },
        ..s
    };
    let req = drivers::request(&mcp, &key);
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["method"], "tools/call");
    assert_eq!(
        body["params"]["_meta"][drivers::MCP_IDEMPOTENCY],
        b64url_encode(&key.0)
    );
}

// TI-6, E62 (3), Ek B 4497
#[test]
fn a_request_whose_answer_was_lost_is_sent_again_once_and_only_if_the_upstream_dedupes() {
    let outbox = Event::Outbox {
        step: 0,
        key: [0; 32],
        request: [0; 32],
        at: NOW,
    };
    let mut events = vec![
        started(
            Kind::Cloud,
            vec![spec("send", Reversibility::Reversible, true)],
        ),
        released(),
    ];
    assert_eq!(next(&job(&events), NOW, true), Next::Outbox(0));
    events.push(outbox.clone());
    events.push(Event::Recovered { at: NOW });
    events.push(Event::Continuations { ais: vec![vec![1]] });
    assert_eq!(next(&job(&events), NOW, true), Next::Recheck);
    events.push(Event::Decided {
        checkpoint: 0,
        allowed: true,
        code: String::from("allow"),
        at: NOW,
    });
    assert_eq!(next(&job(&events), NOW, true), Next::Resend(0));
    assert!(matches!(
        next(&job(&events), NOW, false),
        Next::Settle(0, Outcome::Unknown, _, Some(Follow::Pause("unknown")))
    ));
    events.push(Event::Resent { step: 0, at: NOW });
    assert!(matches!(
        next(&job(&events), NOW, true),
        Next::Settle(0, Outcome::Unknown, _, _)
    ));
    let plain = vec![
        started(
            Kind::Cloud,
            vec![spec("send", Reversibility::Reversible, false)],
        ),
        released(),
        outbox,
    ];
    assert!(matches!(
        next(&job(&plain), NOW, true),
        Next::Settle(0, Outcome::Unknown, _, _)
    ));
}

// U5, Ek B 4277
#[test]
fn a_stop_settles_what_may_have_left_and_is_then_confirmed() {
    let stop = Event::Requested {
        control: Request::Stop,
        reason: String::from("person"),
        at: NOW,
    };
    let mut events = vec![
        started(
            Kind::Cloud,
            vec![
                spec("one", Reversibility::Reversible, false),
                spec("two", Reversibility::Reversible, false),
            ],
        ),
        released(),
        Event::Outbox {
            step: 0,
            key: [0; 32],
            request: [0; 32],
            at: NOW,
        },
        stop,
    ];
    assert_eq!(
        next(&job(&events), NOW, true),
        Next::Settle(0, Outcome::Unknown, Vec::new(), None)
    );
    events.push(Event::Outcome {
        step: 0,
        outcome: Outcome::Unknown,
        evidence: Vec::new(),
        at: NOW,
    });
    assert_eq!(next(&job(&events), NOW, true), Next::Attest(0));
    events.push(Event::Attested {
        step: 0,
        claim: vec![1],
        refused: None,
        at: NOW,
    });
    assert_eq!(next(&job(&events), NOW, true), Next::ConfirmStop);
    events.push(Event::Confirmed {
        state: Confirmed::Stopped,
        claim: vec![2],
        at: NOW,
    });
    assert_eq!(next(&job(&events), NOW, true), Next::Done);
}

// U5, E63 (2), §7.9.7.2, Ek B 4277, 4498
#[test]
fn every_re_check_point_asks_access_before_the_next_effect() {
    let base = vec![
        started(
            Kind::Cloud,
            vec![
                spec("one", Reversibility::Reversible, false),
                spec("two", Reversibility::Reversible, false),
            ],
        ),
        released(),
    ];
    let mut after_one = base.clone();
    after_one.extend(done(0));
    assert_eq!(
        next(&job(&after_one), NOW, true),
        Next::Pause("continuation")
    );
    after_one.push(Event::Continuations { ais: vec![vec![1]] });
    assert_eq!(next(&job(&after_one), NOW, true), Next::Recheck);
    let mut denied = after_one.clone();
    denied.push(Event::Decided {
        checkpoint: 0,
        allowed: false,
        code: String::from("deny"),
        at: NOW,
    });
    assert_eq!(next(&job(&denied), NOW, true), Next::Stop("decision"));
    for trigger in [
        Event::Semantic { step: 0, at: NOW },
        Event::Recovered { at: NOW },
    ] {
        let mut e = base.clone();
        e.push(Event::Continuations { ais: vec![vec![1]] });
        e.push(trigger);
        assert_eq!(next(&job(&e), NOW, true), Next::Recheck);
    }
    let mut paused = base.clone();
    paused.push(Event::Requested {
        control: Request::Pause,
        reason: String::from("person"),
        at: NOW,
    });
    assert_eq!(next(&job(&paused), NOW, true), Next::ConfirmPause);
    paused.push(Event::Confirmed {
        state: Confirmed::Paused,
        claim: vec![1],
        at: NOW,
    });
    assert_eq!(next(&job(&paused), NOW, true), Next::Idle);
    paused.push(Event::Continuations { ais: vec![vec![1]] });
    paused.push(Event::Resumed { at: NOW });
    assert_eq!(next(&job(&paused), NOW, true), Next::Recheck);
}

// E47 (4), E51, Ek B 4328
#[test]
fn silence_is_not_approval_and_a_block_is_a_handoff() {
    let mut events = vec![
        started(
            Kind::Cloud,
            vec![spec("one", Reversibility::Reversible, false)],
        ),
        Event::Continuations { ais: vec![vec![1]] },
        Event::Semantic { step: 0, at: NOW },
        Event::Decided {
            checkpoint: 0,
            allowed: false,
            code: String::from("require_action"),
            at: NOW,
        },
    ];
    assert_eq!(next(&job(&events), NOW, true), Next::AwaitApproval(0));
    events.push(Event::Handoff {
        step: 0,
        reason: String::from("approval"),
        until: NOW + 10,
        at: NOW,
    });
    assert_eq!(next(&job(&events), NOW, true), Next::Wait(NOW + 10));
    assert_eq!(next(&job(&events), NOW + 10, true), Next::Stop("silence"));
    assert_eq!(
        settle(Reading::Blocked),
        (Outcome::NotDone, Vec::new(), Some(Follow::Handoff))
    );
    let s = spec("one", Reversibility::Reversible, false);
    assert_eq!(drivers::read(&s, 403, b""), Reading::Blocked);
    assert_eq!(drivers::read(&s, 429, b""), Reading::Blocked);
    assert_eq!(drivers::read(&s, 409, b""), Reading::Conflict);
    assert_eq!(drivers::read(&s, 503, b""), Reading::Unclear);
    assert_eq!(drivers::read(&s, 201, b"{}"), Reading::Confirmed);
}

// E47 (2), (3), Ek B 4493
#[test]
fn an_irreversible_step_waits_out_its_window_and_can_be_cancelled_inside_it() {
    let mut events = vec![
        started(
            Kind::Cloud,
            vec![spec("send", Reversibility::Irreversible, false)],
        ),
        released(),
    ];
    let until = NOW + access_executor::domain::COMMIT_WINDOW_MS;
    assert_eq!(next(&job(&events), NOW, true), Next::OpenWindow(0, until));
    events.push(Event::WindowOpened { step: 0, until });
    assert_eq!(next(&job(&events), NOW + 1, true), Next::Wait(until));
    assert_eq!(next(&job(&events), until, true), Next::Outbox(0));
    let mut cancelled = events.clone();
    cancelled.push(Event::Cancelled { step: 0, at: NOW });
    assert_eq!(
        next(&job(&cancelled), NOW + 1, true),
        Next::Settle(
            0,
            Outcome::NotDone,
            Vec::new(),
            Some(Follow::Stop("cancel"))
        )
    );
    let Event::Started(mut off) = started(
        Kind::Cloud,
        vec![spec("send", Reversibility::Irreversible, false)],
    ) else {
        panic!()
    };
    off.commit_window_ms = 0;
    assert_eq!(
        next(&job(&[Event::Started(off), released()]), NOW, true),
        Next::Outbox(0)
    );
}

// INV-19, Ek B 4280
#[test]
fn a_step_outside_the_envelope_or_past_the_horizon_never_runs() {
    let mut outside = spec("other", Reversibility::Reversible, false);
    outside.resource = String::from("mail:drafts");
    let j = job(&[started(Kind::Cloud, vec![outside]), released()]);
    assert_eq!(
        next(&j, NOW, true),
        Next::Settle(
            0,
            Outcome::NotDone,
            Vec::new(),
            Some(Follow::Stop("envelope"))
        )
    );
    let late = job(&[
        started(
            Kind::Cloud,
            vec![spec("one", Reversibility::Reversible, false)],
        ),
        released(),
    ]);
    assert_eq!(
        next(&late, NOW + 3_600_001, true),
        Next::Settle(
            0,
            Outcome::NotDone,
            Vec::new(),
            Some(Follow::Stop("horizon"))
        )
    );
}

// E57 (1), B21, Ek B 4490
#[test]
fn every_executor_kind_follows_the_same_rules() {
    for at in [NOW, NOW + 20_000] {
        let runs: Vec<Next> = [Kind::Cloud, Kind::Customer, Kind::Local]
            .into_iter()
            .map(|k| {
                next(
                    &job(&[
                        started(k, vec![spec("send", Reversibility::Irreversible, true)]),
                        Event::WindowOpened {
                            step: 0,
                            until: NOW + 15_000,
                        },
                        released(),
                    ]),
                    at,
                    true,
                )
            })
            .collect();
        assert!(runs.windows(2).all(|w| w[0] == w[1]), "{runs:?}");
    }
    assert_eq!(Kind::parse("local"), Some(Kind::Local));
    assert_eq!(Kind::parse("enterprise"), None);
}

// AG-40 (5), Ek B 4486
#[test]
fn without_the_released_token_nothing_leaves() {
    let j = job(&[started(
        Kind::Cloud,
        vec![spec("send", Reversibility::Reversible, false)],
    )]);
    assert_eq!(next(&j, NOW, false), Next::Release(0));
    let lost = job(&[
        started(
            Kind::Cloud,
            vec![spec("send", Reversibility::Reversible, false)],
        ),
        released(),
    ]);
    assert_eq!(
        next(&lost, NOW, false),
        Next::Settle(
            0,
            Outcome::NotDone,
            Vec::new(),
            Some(Follow::Stop("release"))
        )
    );
}

// E51, Ek B 4327
#[test]
fn a_web_bot_auth_signature_covers_authority_and_signature_agent_and_verifies() {
    let (signer, _) = SoftSigner::generate_ed25519().unwrap();
    let p = Params {
        authority: String::from("API.mail.example"),
        agent: String::from("https://access.example/.well-known/http-message-signatures-directory"),
        thumbprint: access_kernel::verify::key_scope::thumbprint(&signer.public_key()),
        created: 1_800_000_000,
        nonce: [5; 16],
    };
    let base = p.base();
    assert!(base.starts_with(
        "\"@authority\": api.mail.example\n\"signature-agent\": \"https://access.example/"
    ));
    assert!(base.contains(";tag=\"web-bot-auth\""));
    let sig = signer.sign(base.as_bytes()).unwrap();
    let access_kernel::verify::cose::PublicKey::Ed25519(pk) = signer.public_key() else {
        panic!()
    };
    access_kernel::verify::ed25519(
        &access_kernel::verify::PureBackend,
        &pk,
        base.as_bytes(),
        &sig,
    )
    .unwrap();
    let headers = p.headers(&sig);
    assert_eq!(headers[0].1, format!("\"{}\"", p.agent));
    assert!(headers[1].1.starts_with(
        "sig1=(\"@authority\" \"signature-agent\");created=1800000000;expires=1800000060;"
    ));
    assert_eq!(
        webbot::base64(b"any carnal pleas"),
        "YW55IGNhcm5hbCBwbGVhcw=="
    );
    assert_eq!(
        webbot::authority("https://a.example:8443/x?y"),
        Some("a.example:8443")
    );
    assert_eq!(webbot::authority("http://a.example/"), None);
}
