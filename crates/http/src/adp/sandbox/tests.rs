#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{ActionRef, Window};
use suiss_crypto::dcbor::Value;

use super::*;

const PROD: Digest = Digest([1; 32]);
const PROD_2: Digest = Digest([2; 32]);
const SANDBOX: Digest = Digest([3; 32]);
const UNKNOWN: Digest = Digest([4; 32]);

struct Fixed;

impl Regimes for Fixed {
    fn regime(&self, domain: Digest) -> impl Future<Output = Result<Regime, CoreError>> + Send {
        std::future::ready(match domain {
            SANDBOX => Ok(Regime::Sandbox),
            UNKNOWN => Err(CoreError::Unavailable("regime")),
            _ => Ok(Regime::Production),
        })
    }
}

/// Counts the requests that reach it, and answers each with a marker refusal.
#[derive(Default)]
struct Reached(AtomicU64);

impl Pdp for Reached {
    fn evaluate(&self, _: Incoming) -> impl Future<Output = Result<Response, CoreError>> + Send {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Err(CoreError::Protocol("reached")))
    }
}

fn foreign_acceptance(domain: Digest) -> Value {
    Value::Map(vec![
        (Value::text("use"), Value::text("foreign-authority")),
        (
            Value::text("issuer"),
            Value::Map(vec![(
                Value::text("foreign"),
                Value::Map(vec![(Value::text("domain"), domain.to_value())]),
            )]),
        ),
    ])
}

fn incoming(home: Digest, payload: Option<Payload>) -> Incoming {
    Incoming {
        request: Request {
            domain: home,
            mode: Mode::Commit,
            nonce: vec![1; 16],
            intent: IntentEnvelope {
                provenance: BTreeMap::new(),
                action: ActionRef {
                    namespace: String::from("access"),
                    name: String::from("acceptance_establish"),
                    major: 1,
                    schema: Digest([0; 32]),
                },
                resources: Vec::new(),
                params: BTreeMap::new(),
                opaque: BTreeMap::new(),
                recipient: None,
                purpose: None,
                context: ContextRefs::default(),
                validity: Window { from: 0, until: 1 },
            },
            payload,
            basis: ExerciseBasis::Public(Id([0; 16])),
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        },
        ais: None,
        pep: String::from("pep"),
        requester: None,
        explain: false,
        status: None,
        context: None,
    }
}

async fn code(line: &SandboxLine<Reached, Fixed>, inc: Incoming) -> &'static str {
    match line.evaluate(inc).await {
        Err(CoreError::Protocol(c) | CoreError::Unavailable(c)) => c,
        Err(e) => panic!("{e}"),
        Ok(_) => panic!("answered"),
    }
}

// OP-151 m.3 (m), X21
#[tokio::test]
async fn no_authority_crosses_the_sandbox_line() {
    let line = SandboxLine {
        inner: Reached::default(),
        regimes: Fixed,
    };
    let establish = |d| Some(Payload::AcceptanceEstablish(foreign_acceptance(d)));
    assert_eq!(
        code(&line, incoming(PROD, establish(SANDBOX))).await,
        SANDBOX_LINE
    );
    assert_eq!(
        code(&line, incoming(SANDBOX, establish(PROD))).await,
        SANDBOX_LINE
    );
    let amend = Some(Payload::AcceptanceAmend {
        acceptance: Id([5; 16]),
        content: foreign_acceptance(SANDBOX),
    });
    assert_eq!(code(&line, incoming(PROD, amend)).await, SANDBOX_LINE);
    assert_eq!(line.inner.0.load(Ordering::SeqCst), 0);

    assert_eq!(
        code(&line, incoming(PROD, establish(PROD_2))).await,
        "reached"
    );
    assert_eq!(code(&line, incoming(PROD, None)).await, "reached");
    assert_eq!(line.inner.0.load(Ordering::SeqCst), 2);
}

// MD-8
#[tokio::test]
async fn an_unknown_side_is_unavailable() {
    let line = SandboxLine {
        inner: Reached::default(),
        regimes: Fixed,
    };
    let inc = incoming(
        PROD,
        Some(Payload::AcceptanceEstablish(foreign_acceptance(UNKNOWN))),
    );
    assert_eq!(code(&line, inc).await, "regime");
    assert_eq!(line.inner.0.load(Ordering::SeqCst), 0);
}

// OP-151 m.3 (m)
#[test]
fn only_other_domains_are_foreign() {
    let own = incoming(
        PROD,
        Some(Payload::AcceptanceEstablish(foreign_acceptance(PROD))),
    );
    assert_eq!(foreign_domains(&own.request), Vec::<Digest>::new());
    let local = incoming(
        PROD,
        Some(Payload::AcceptanceEstablish(Value::Map(vec![(
            Value::text("issuer"),
            Id([1; 16]).to_value(),
        )]))),
    );
    assert_eq!(foreign_domains(&local.request), Vec::<Digest>::new());
}
