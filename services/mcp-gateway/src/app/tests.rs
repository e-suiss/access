#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use access_kernel::model::ActionRef;
use access_sdk::transport::Response;

use super::*;

const HOST: &str = "tools.example.com";

#[derive(Default)]
struct FakeAccess {
    pinned: StdMutex<Vec<String>>,
    calls: StdMutex<Vec<String>>,
    answer: StdMutex<Option<(u16, String)>>,
}

impl Access for FakeAccess {
    async fn tools(&self, body: Vec<u8>) -> Answer {
        let v = json::parse(&body, 1 << 20).unwrap();
        assert_eq!(v.get("host").and_then(Json::as_str), Some(HOST));
        let pinned = self.pinned.lock().unwrap().clone();
        let names: Vec<String> = pinned.iter().map(|n| format!("\"{n}\"")).collect();
        Answer::Response(Response::new(
            200,
            format!("{{\"pinned\":[{}]}}", names.join(",")).into_bytes(),
        ))
    }

    async fn calls(&self, body: Vec<u8>) -> Answer {
        self.calls
            .lock()
            .unwrap()
            .push(String::from_utf8(body).unwrap());
        let (status, body) = self.answer.lock().unwrap().clone().unwrap();
        Answer::Response(Response::new(status, body.into_bytes()))
    }

    async fn metadata(&self, _: String) -> Answer {
        Answer::Unanswered(Fault::Unreachable)
    }
}

#[derive(Default)]
struct FakeServer {
    seen: StdMutex<Vec<String>>,
    called: AtomicUsize,
    description: StdMutex<String>,
}

impl Upstream for FakeServer {
    async fn send(&self, body: Vec<u8>) -> Answer {
        let text = String::from_utf8(body).unwrap();
        let v = json::parse(text.as_bytes(), 1 << 20).unwrap();
        self.seen.lock().unwrap().push(text);
        if v.get("method").and_then(Json::as_str) == Some("tools/call") {
            self.called.fetch_add(1, Ordering::SeqCst);
            return Answer::Response(Response::new(
                200,
                br#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#.to_vec(),
            ));
        }
        let d = self.description.lock().unwrap().clone();
        Answer::Response(Response::new(
            200,
            format!(
                r#"{{"jsonrpc":"2.0","id":"x","result":{{"tools":[{{"name":"search","description":"{d}"}},{{"name":"delete","description":"Delete"}}]}}}}"#
            )
            .into_bytes(),
        ))
    }
}

struct Now;

impl Clock for Now {
    fn now(&self) -> Option<u64> {
        Some(1_000_000)
    }
}

fn gateway() -> Gateway<FakeAccess, FakeServer, Now> {
    let server = FakeServer::default();
    *server.description.lock().unwrap() = String::from("Find pages");
    Gateway::new(
        (FakeAccess::default(), server, Now),
        Config {
            host: String::from(HOST),
            origins: Vec::new(),
            pep: String::from("gateway-pep"),
            domain: Digest([4; 32]),
            profile: Profile {
                proxy: String::from("tools"),
                namespace: String::from("work"),
                action: ActionRef {
                    namespace: String::from("work"),
                    name: String::from("call"),
                    major: 1,
                    schema: Digest([9; 32]),
                },
            },
        },
    )
}

fn rpc(method: &str, params: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}{params}}}}}"#
    )
    .into_bytes()
}

fn headers() -> Vec<(&'static str, &'static str)> {
    vec![("host", HOST), ("content-type", "application/json")]
}

// AG-42, OP-156 m.3 (n)
#[tokio::test]
async fn ag_42_a_list_shows_only_pinned_tools() {
    let g = gateway();
    g.access.pinned.lock().unwrap().push(String::from("search"));
    let r = g.handle(&headers(), &rpc("tools/list", "")).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("\"search\""), "{}", r.body);
    assert!(!r.body.contains("delete"), "{}", r.body);
}

// E17, AG-42
#[tokio::test]
async fn ag_42_a_call_without_the_agents_statement_never_reaches_the_server() {
    let g = gateway();
    let r = g
        .handle(
            &headers(),
            &rpc("tools/call", r#","name":"search","arguments":{"q":"x"}"#),
        )
        .await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert!(r.body.contains("statement"), "{}", r.body);
    assert!(g.access.calls.lock().unwrap().is_empty());
    assert_eq!(g.upstream.called.load(Ordering::SeqCst), 0);
}

// AG-42
#[tokio::test]
async fn ag_42_only_tools_initialize_and_ping_are_served() {
    let g = gateway();
    let r = g
        .handle(
            &headers(),
            &rpc("resources/read", r#","uri":"file:///etc""#),
        )
        .await;
    assert!(r.body.contains("-32601"), "{}", r.body);
    let r = g.handle(&headers(), &rpc("ping", "")).await;
    assert_eq!(r.status, 200);
    assert!(g.upstream.seen.lock().unwrap().is_empty());
    let r = g
        .handle(&[("host", "evil.example.com")], &rpc("ping", ""))
        .await;
    assert_eq!(r.status, 403, "{}", r.body);
}
