#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use access_kernel::intent::ContextRefs;
use access_kernel::model::{ActionRef, Window};

use super::*;
use crate::domain::engine::Engine;

const PEP: &str = "cGVwLXRodW1icHJpbnQtb2YtdGhlLXByb3h5LTMyYnk";
const HOST: &str = "tools.example.com";
const DOMAIN: Digest = Digest([4; 32]);

#[derive(Default)]
struct Fake {
    pins: Mutex<Vec<PinnedTool>>,
    answer: Mutex<Option<(u16, String)>>,
    audits: Mutex<Vec<(String, String, String, String)>>,
    asked: AtomicUsize,
    down: AtomicBool,
}

fn registration() -> Registration {
    Registration {
        name: String::from("tools"),
        engine: Engine::Envoy,
        host: String::from(HOST),
        upstream: None,
        client_id: String::from("tools-proxy"),
        pep: String::from(PEP),
        action: ActionRef {
            namespace: String::from("apps"),
            name: String::from("call"),
            major: 1,
            schema: Digest([9; 32]),
        },
        namespace: String::from("apps"),
        routes: vec![String::from("/")],
    }
}

impl McpPorts for Fake {
    type Realm = ();

    async fn registered(
        &self,
        pep: &str,
        host: &str,
    ) -> Result<Option<((), Registration)>, Unavailable> {
        Ok((pep == PEP && host == HOST).then(|| ((), registration())))
    }

    async fn governing(&self, (): &()) -> Result<Option<Digest>, Unavailable> {
        Ok(Some(DOMAIN))
    }

    async fn pins(&self, (): &(), proxy: &str) -> Result<Vec<PinnedTool>, Unavailable> {
        assert_eq!(proxy, "tools");
        Ok(self.pins.lock().unwrap().clone())
    }

    async fn evaluate(&self, pep: &str, body: Vec<u8>) -> Result<Evaluated, Unavailable> {
        assert_eq!(pep, PEP);
        assert_eq!(body, b"{\"evaluation\":1}");
        if self.down.load(Ordering::SeqCst) {
            return Err(Unavailable);
        }
        self.asked.fetch_add(1, Ordering::SeqCst);
        let (status, body) = self.answer.lock().unwrap().clone().unwrap();
        Ok(Evaluated {
            status,
            content_type: Some(String::from("application/json")),
            key_excerpt: None,
            body: body.into_bytes(),
        })
    }

    async fn instance(&self, domain: Digest, _: Digest) -> Result<Option<Id>, Unavailable> {
        assert_eq!(domain, DOMAIN);
        Ok(Some(Id([0x0c; 16])))
    }

    async fn audit(&self, (): &(), row: &Audit<'_>) -> Result<(), Unavailable> {
        self.audits.lock().unwrap().push((
            String::from(row.event),
            String::from(row.actor),
            String::from(row.target),
            String::from(row.correlation),
        ));
        Ok(())
    }
}

fn intent(tool: &str) -> IntentEnvelope {
    let r = registration();
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: r.action.clone(),
        resources: vec![tool_resource(&r, tool)],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window { from: 1, until: 2 },
    }
}

fn pinned(fake: &Fake, name: &str, pin: [u8; 32]) {
    fake.pins.lock().unwrap().push(PinnedTool {
        name: String::from(name),
        pin,
    });
}

fn call<'a>(tool: &'a str, pin: &'a [u8; 32], intent: &'a IntentEnvelope) -> ToolCall<'a> {
    ToolCall {
        pep: Some(PEP),
        host: HOST,
        tool,
        pin,
        domain: DOMAIN,
        mode: Mode::Commit,
        nonce: &[7; 16],
        intent,
        statement: true,
        evaluation: b"{\"evaluation\":1}",
    }
}

// AG-42, OP-156 m.3 (n)
#[tokio::test]
async fn ag_42_a_tool_whose_definition_changed_is_blocked_before_any_decision() {
    let g = Gateway::new(Fake::default());
    pinned(g.ports(), "search", [1; 32]);
    *g.ports().answer.lock().unwrap() = Some((
        200,
        String::from(r#"{"decision":true,"context":{"outcome":"allow"}}"#),
    ));
    let i = intent("search");
    let r = g.call(&call("search", &[2; 32], &i)).await;
    assert_eq!(r, Err(McpRefusal::Blocked(Standing::Changed)));
    let i = intent("delete");
    let r = g.call(&call("delete", &[1; 32], &i)).await;
    assert_eq!(r, Err(McpRefusal::Blocked(Standing::New)));
    assert_eq!(g.ports().asked.load(Ordering::SeqCst), 0);
    let audits = g.ports().audits.lock().unwrap().clone();
    assert_eq!(audits.len(), 2);
    assert_eq!(audits[0].0, "mcp_gateway.tool_blocked");
    assert_eq!(audits[0].1, format!("pep:{PEP}"));
    assert_eq!(audits[0].2, "tools:search");
    assert!(audits[0].3.starts_with("changed:"), "{}", audits[0].3);
    assert!(audits[1].3.starts_with("new:"), "{}", audits[1].3);

    let listed = g
        .tools(
            Some(PEP),
            HOST,
            &[
                Observed {
                    name: String::from("search"),
                    pin: [1; 32],
                },
                Observed {
                    name: String::from("delete"),
                    pin: [1; 32],
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(listed, ["search"]);
}

// AG-42, E17
#[tokio::test]
async fn ag_42_each_decided_call_is_audited_once_with_its_instance_as_actor() {
    let g = Gateway::new(Fake::default());
    pinned(g.ports(), "search", [1; 32]);
    *g.ports().answer.lock().unwrap() = Some((
        200,
        String::from(r#"{"decision":true,"context":{"outcome":"allow"}}"#),
    ));
    let i = intent("search");
    let r = g.call(&call("search", &[1; 32], &i)).await.unwrap();
    assert_eq!(r.status, 200);
    *g.ports().answer.lock().unwrap() = Some((
        200,
        String::from(r#"{"decision":false,"context":{"outcome":"deny"}}"#),
    ));
    g.call(&call("search", &[1; 32], &i)).await.unwrap();
    let audits = g.ports().audits.lock().unwrap().clone();
    assert_eq!(audits.len(), 2);
    assert!(audits.iter().all(|a| a.0 == "mcp_gateway.call"));
    assert_eq!(
        audits[0].1,
        format!("instance:{}", b64url_encode(&[0x0c; 16]))
    );
    assert!(audits[0].3.ends_with(":allow"));
    assert_eq!(audits[1].1, "-");
    assert!(audits[1].3.ends_with(":deny"));
    let exercise = access_kernel::meta::exercise_id(&DOMAIN, &[7; 16]).unwrap();
    assert!(audits[0].3.starts_with(&b64url_encode(&exercise.0)));
}

// AG-42, E17, B22
#[tokio::test]
async fn ag_42_a_call_that_is_not_the_agents_own_commit_on_this_tool_is_refused() {
    let g = Gateway::new(Fake::default());
    pinned(g.ports(), "search", [1; 32]);
    let i = intent("search");
    let other = intent("other");
    let mut c = call("search", &[1; 32], &i);
    c.statement = false;
    assert_eq!(g.call(&c).await, Err(McpRefusal::Malformed("statement")));
    let mut c = call("search", &[1; 32], &i);
    c.mode = Mode::Check;
    assert_eq!(g.call(&c).await, Err(McpRefusal::Malformed("statement")));
    let c = call("search", &[1; 32], &other);
    assert_eq!(g.call(&c).await, Err(McpRefusal::Malformed("intent")));
    let mut c = call("search", &[1; 32], &i);
    c.domain = Digest([5; 32]);
    assert_eq!(g.call(&c).await, Err(McpRefusal::Malformed("domain")));
    let mut c = call("search", &[1; 32], &i);
    c.pep = Some("other");
    assert_eq!(g.call(&c).await, Err(McpRefusal::Unregistered));
    c.pep = None;
    assert_eq!(g.call(&c).await, Err(McpRefusal::Unregistered));
    assert_eq!(g.ports().asked.load(Ordering::SeqCst), 0);
    assert!(g.ports().audits.lock().unwrap().is_empty());
}

// MD-8, TI-9
#[tokio::test]
async fn an_unreachable_decision_point_refuses_and_records_nothing() {
    let g = Gateway::new(Fake::default());
    pinned(g.ports(), "search", [1; 32]);
    g.ports().down.store(true, Ordering::SeqCst);
    let i = intent("search");
    assert_eq!(
        g.call(&call("search", &[1; 32], &i)).await,
        Err(McpRefusal::Unavailable)
    );
    assert!(g.ports().audits.lock().unwrap().is_empty());
}
