//! The MCP resource server profile without I/O (§11.2, §11.5, RS-M1 to RS-M19, AG-9 to AG-15,
//! AGI-5, AGI-6, OP-154 m.3 (v)): metadata, challenges, wire checks, `requestState`,
//! `cacheScope`, the stream governor and the request path over the fixture domain. The same
//! rules run against a real server in `bins/access-server` (OP-153 m.3 (gg)).

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::useless_format,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::intent_digest;
use access_kernel::json::{self, Json, b64url_encode};
use access_kernel::model::{ResourceRef, Window};
use access_sdk::auth::{Random, RandomUnavailable};
use access_sdk::authorize::{AskDecision, ExerciseRequest};
use access_sdk::mcp::cache::{CacheKey, CacheScope, ListCache, Slot, Visibility, scope_of};
use access_sdk::mcp::challenge::{Challenge, scope_param, www_authenticate};
use access_sdk::mcp::client::{
    canonical_resource, check_metadata, metadata_urls, parse_challenge, token_resource,
};
use access_sdk::mcp::listen::{Closed, Listen, ListenError, Next};
use access_sdk::mcp::prm::{Binding, Localized, PrmError, ProtectedResource};
use access_sdk::mcp::server::{Env, Handled, McpServer, Request, Response, Stream};
use access_sdk::mcp::state::{Binding as StateBinding, STATE_TTL_MS, StateError, StateKey};
use access_sdk::mcp::tool::{ToolDef, Tools, intent};
use access_sdk::mcp::wire::{self, HEADER_MISMATCH, Headers, Origins, Rejection, local_bind};
use access_sdk::resource::{Profile, ResourceServer, TokenCapacity};
use access_sdk::transport::{Answer, FixedClock};
use suiss_crypto::secret::Secret;
use support::{
    HOLDER_SEED, NOW, OTHER_SEED, PEP, RS, TokenSpec, action, allow_body, basis, config, domain,
    ok, pep, proof_with, receipt_for, sign1,
};

const URI: &str = "https://rs.example/";
const HOST: &str = "rs.example";

fn prm() -> ProtectedResource {
    ProtectedResource::new(
        RS,
        vec![String::from("https://as.example")],
        vec![String::from("door:open")],
        Binding::Dpop(vec![String::from("EdDSA"), String::from("ES256")]),
    )
    .unwrap()
}

fn door() -> ResourceRef {
    ResourceRef {
        namespace: String::from("door"),
        path: vec![String::from("1")],
        incarnation: 0,
    }
}

fn tool(name: &str, public: Option<access_kernel::model::Id>) -> ToolDef {
    ToolDef {
        name: String::from(name),
        action: action(),
        resource: door(),
        scopes: vec![String::from("door:open"), String::from("offline_access")],
        public,
        secret: BTreeSet::from([String::from("pin")]),
        listing: Json::Object(vec![(String::from("name"), Json::Str(String::from(name)))]),
    }
}

fn other_tool() -> ToolDef {
    let mut t = tool("lock", None);
    t.action.name = String::from("lock");
    t
}

fn origins() -> Origins {
    Origins {
        origins: vec![String::from("https://app.example")],
        hosts: vec![String::from(HOST)],
    }
}

struct Seq(Cell<u8>);

impl Random for Seq {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        let n = self.0.get().wrapping_add(1);
        self.0.set(n);
        out.fill(n);
        Ok(())
    }
}

/// A decision point that answers from a script and counts.
#[derive(Default)]
struct Scripted {
    answers: RefCell<Vec<Answer>>,
    asked: RefCell<Vec<(Mode, Vec<u8>)>>,
}

impl AskDecision for Scripted {
    fn ask(&self, request: &ExerciseRequest<'_>) -> Answer {
        self.asked
            .borrow_mut()
            .push((request.mode, request.nonce.to_vec()));
        let mut a = self.answers.borrow_mut();
        if a.is_empty() {
            Answer::Unanswered(access_sdk::transport::Fault::Unreachable)
        } else {
            a.remove(0)
        }
    }
}

struct World {
    prm: ProtectedResource,
    metadata: String,
    origins: Origins,
    rs: ResourceServer,
    pep: access_sdk::authorize::Pep,
    tools: Tools,
    state: StateKey,
    cache: ListCache,
}

impl World {
    fn new() -> Self {
        let prm = prm();
        Self {
            metadata: prm.json(),
            prm,
            origins: origins(),
            rs: ResourceServer::new(config(Profile::Fast)).unwrap(),
            pep: pep(),
            tools: Tools::new(vec![tool("open", None), other_tool()]).unwrap(),
            state: StateKey::new(Secret::new([0x42; 32])),
            cache: ListCache::new(16),
        }
    }

    fn server(&self) -> McpServer<'_> {
        McpServer {
            prm: &self.prm,
            metadata: &self.metadata,
            origins: &self.origins,
            rs: &self.rs,
            pep: &self.pep,
            tools: &self.tools,
            subscriptions: self.tools.get("open"),
            state: &self.state,
            cache: &self.cache,
            approval_surface: "https://as.example/approve",
            list_ttl_ms: 60_000,
            discover: None,
            name: "door-server",
        }
    }
}

fn rpc(method: &str, params: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":7,"method":"{method}","params":{params}}}"#).into_bytes()
}

fn meta_only() -> String {
    access_sdk::mcp::client::meta(None, None, None)
}

fn send(
    w: &World,
    headers: &[(&str, &str)],
    body: &[u8],
    memory: &support::Memory,
    decisions: &Scripted,
) -> Handled {
    let clock = FixedClock(NOW);
    let random = Seq(Cell::new(0));
    let ports = memory.ports();
    let env = Env {
        clock: &clock,
        ports: &ports,
        decisions,
        random: &random,
    };
    w.server().handle(
        &Request {
            method: "POST",
            path: "/",
            uri: URI,
            headers: Headers(headers),
            body,
            certificate: None,
        },
        &env,
    )
}

fn respond(h: Handled) -> Response {
    match h {
        Handled::Respond(r) => r,
        other => panic!("{other:?}"),
    }
}

fn header<'a>(r: &'a Response, name: &str) -> Vec<&'a str> {
    r.headers
        .iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .collect()
}

fn body(r: &Response) -> Json {
    json::parse(r.body.as_bytes(), 1 << 20).unwrap()
}

fn auth(token: &str, jti: &str) -> (String, String) {
    (
        format!("DPoP {token}"),
        proof_with(HOLDER_SEED, token, jti, "POST", URI, None),
    )
}

// RS-M1, RS-M2, AG-9, AG-10, §11.5.2
#[test]
fn metadata_is_served_at_the_path_aware_well_known_uri() {
    let cases = [
        (
            "https://mcp.example.com",
            "https://mcp.example.com/.well-known/oauth-protected-resource",
        ),
        (
            "https://mcp.example.com/mcp",
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        ),
        (
            "https://example.com/public/mcp/",
            "https://example.com/.well-known/oauth-protected-resource/public/mcp",
        ),
    ];
    for (resource, url) in cases {
        let p = ProtectedResource::new(
            resource,
            vec![String::from("https://as.example")],
            Vec::new(),
            Binding::Mtls,
        )
        .unwrap();
        assert_eq!(p.metadata_url(), url);
    }
    let p = prm()
        .named(Localized {
            language: Some(String::from("tr-TR")),
            text: String::from("Kapı"),
        })
        .unwrap();
    let v = json::parse(p.json().as_bytes(), 4096).unwrap();
    assert_eq!(v.get("resource").and_then(Json::as_str), Some(RS));
    assert_eq!(
        v.get("dpop_bound_access_tokens_required"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        v.get("bearer_methods_supported"),
        Some(&Json::Array(vec![Json::Str(String::from("header"))]))
    );
    assert!(v.get("resource_name#tr-TR").is_some());
    // OP-154 m.3 (v)
    assert!(v.get("signed_metadata").is_none());
    assert_eq!(
        ProtectedResource::new(RS, Vec::new(), Vec::new(), Binding::Mtls).unwrap_err(),
        PrmError::AuthorizationServers
    );
    // §11.5.1
    assert_eq!(
        ProtectedResource::new(
            RS,
            vec![String::from("https://as.example")],
            vec![String::from("offline_access")],
            Binding::Mtls
        )
        .unwrap_err(),
        PrmError::Scope
    );
    assert_eq!(
        ProtectedResource::new(
            RS,
            vec![String::from("https://as.example")],
            Vec::new(),
            Binding::Dpop(vec![String::from("none")])
        )
        .unwrap_err(),
        PrmError::Binding
    );
    assert!(
        ProtectedResource::new(
            "http://mcp.example",
            vec![String::from("https://as.example")],
            Vec::new(),
            Binding::Mtls
        )
        .is_err()
    );
}

// RS-M3, §11.5.6, §9.9.5
#[test]
fn challenges_name_the_metadata_and_tell_scope_from_a_required_action() {
    let p = prm();
    let missing = www_authenticate(&Challenge::Missing, &p);
    assert_eq!(missing.len(), 2);
    assert!(missing[0].starts_with("Bearer "));
    assert!(missing[0].contains(
        r#"resource_metadata="https://rs.example/.well-known/oauth-protected-resource""#
    ));
    assert!(!missing[0].contains("error="));
    assert!(missing[1].starts_with(r#"DPoP algs="EdDSA ES256""#));
    let scopes = vec![
        String::from("door:open"),
        String::from("offline_access"),
        String::from("door:read"),
        String::from("door:open"),
    ];
    assert_eq!(scope_param(&scopes).as_deref(), Some("door:open door:read"));
    let c = Challenge::InsufficientScope(scopes);
    assert_eq!(c.status(), 403);
    let v = www_authenticate(&c, &p);
    assert!(v[0].contains(r#"error="insufficient_scope""#));
    assert!(v[0].contains(r#"scope="door:open door:read""#));
    assert!(!v[0].contains("offline_access"));
    let required = www_authenticate(&Challenge::Authorization, &p);
    assert_eq!(Challenge::Authorization.status(), 403);
    assert!(required[0].contains(r#"error="insufficient_authorization""#));
    assert!(!required[0].contains("insufficient_scope"));
}

// RS-M15, §11.5.6
#[test]
fn rebinding_origins_hosts_and_line_breaks_are_refused() {
    let o = origins();
    assert!(o.check(&Headers(&[("host", HOST)])).is_ok());
    assert!(
        o.check(&Headers(&[
            ("host", HOST),
            ("origin", "https://app.example")
        ]))
        .is_ok()
    );
    assert_eq!(
        o.check(&Headers(&[
            ("host", HOST),
            ("origin", "https://evil.example")
        ])),
        Err(Rejection::Origin)
    );
    assert_eq!(
        o.check(&Headers(&[("host", HOST), ("origin", "null")])),
        Err(Rejection::Origin)
    );
    assert_eq!(
        o.check(&Headers(&[("host", "attacker.example")])),
        Err(Rejection::Host)
    );
    assert_eq!(o.check(&Headers(&[])), Err(Rejection::Host));
    assert_eq!(
        wire::hygiene(&Headers(&[("x-a", "a\r\nset-cookie: x")])),
        Err(Rejection::HeaderCrlf)
    );
    assert!(local_bind(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
    assert!(local_bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).is_err());
    assert!(local_bind(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))).is_err());
    assert!(local_bind(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_err());
}

// RS-M14, §11.5.6
#[test]
fn a_header_that_disagrees_with_the_body_is_minus_32020() {
    let params = format!(
        r#"{{"name":"open","arguments":{{"door":"front","n":3,"pin":"1234"}},"_meta":{}}}"#,
        meta_only()
    );
    let r = wire::parse(&rpc("tools/call", &params)).unwrap();
    let secret = |a: &str| a == "pin";
    assert!(
        wire::consistent(
            &Headers(&[("Mcp-Method", "tools/call"), ("Mcp-Name", "open")]),
            &r,
            secret
        )
        .is_ok()
    );
    assert!(
        wire::consistent(
            &Headers(&[("mcp-param-door", "front"), ("mcp-param-n", "3")]),
            &r,
            secret
        )
        .is_ok()
    );
    let sentinel = format!("=?base64?{}?=", b64url_encode(b"front"));
    assert!(wire::consistent(&Headers(&[("mcp-param-door", &sentinel)]), &r, secret).is_ok());
    for bad in [
        [("Mcp-Method", "tools/list")],
        [("Mcp-Name", "lock")],
        [("mcp-param-door", "back")],
        [("mcp-param-missing", "x")],
    ] {
        let e = wire::consistent(&Headers(&bad), &r, secret).unwrap_err();
        assert_eq!(e, Rejection::HeaderMismatch);
        assert_eq!((e.status(), e.rpc_code()), (400, HEADER_MISMATCH));
    }
    assert_eq!(
        wire::consistent(&Headers(&[("mcp-param-pin", "1234")]), &r, secret),
        Err(Rejection::HeaderSecret)
    );
}

// AG-11, RS-M19, §11.5.3
#[test]
fn self_reported_client_and_server_info_are_dropped_at_parse() {
    let with = format!(
        r#"{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{{"name":"admin-console"}},"io.modelcontextprotocol/clientCapabilities":{{"trusted":true}}}},"serverInfo":{{"name":"x"}}}}"#
    );
    let without = format!(r#"{{"_meta":{}}}"#, meta_only());
    let a = wire::parse(&rpc("tools/list", &with)).unwrap();
    let b = wire::parse(&rpc("tools/list", &without)).unwrap();
    assert_eq!(a, b);
    assert_eq!(
        wire::parse(&rpc("tools/list", "{}")).unwrap_err(),
        Rejection::ProtocolVersion
    );
}

fn state_binding<'a>(
    instance: &'a [u8; 32],
    capacity: &'a TokenCapacity,
    intent: &'a Digest,
) -> StateBinding<'a> {
    StateBinding {
        instance,
        capacity,
        audience: RS,
        intent,
    }
}

// AG-13, AGI-6, RS-M13
#[test]
fn a_request_state_opens_once_for_its_own_binding_within_120_seconds() {
    let key = StateKey::new(Secret::new([1; 32]));
    let m = support::Memory::healthy();
    let me = [1; 32];
    let own = TokenCapacity::Own {
        subject: String::from("p-1"),
    };
    let intent_a = Digest([2; 32]);
    let b = state_binding(&me, &own, &intent_a);
    let state = key.seal(&b, Some(&[9; 16]), NOW).unwrap();
    let opened = key.open(&state, &b, NOW + 1_000, &m).unwrap();
    assert_eq!(opened.nonce.as_deref(), Some(&[9; 16][..]));
    // AGI-6
    assert_eq!(
        key.open(&state, &b, NOW + 2_000, &m),
        Err(StateError::Replayed)
    );
    let other_instance = [3; 32];
    let other_cap = TokenCapacity::Own {
        subject: String::from("p-2"),
    };
    let other_intent = Digest([4; 32]);
    for rebound in [
        state_binding(&other_instance, &own, &intent_a),
        state_binding(&me, &other_cap, &intent_a),
        state_binding(&me, &own, &other_intent),
        StateBinding {
            audience: "https://other.example",
            ..b
        },
    ] {
        let s = key.seal(&b, None, NOW).unwrap();
        assert_eq!(key.open(&s, &rebound, NOW, &m), Err(StateError::Invalid));
    }
    let late = key.seal(&b, None, NOW).unwrap();
    assert_eq!(
        key.open(&late, &b, NOW + STATE_TTL_MS + 1, &m),
        Err(StateError::Expired)
    );
    let foreign = StateKey::new(Secret::new([2; 32]))
        .seal(&b, None, NOW)
        .unwrap();
    assert_eq!(key.open(&foreign, &b, NOW, &m), Err(StateError::Invalid));
    assert_eq!(
        key.open("not-a-state", &b, NOW, &m),
        Err(StateError::Invalid)
    );
    m.replay_down.set(true);
    let s = key.seal(&b, None, NOW).unwrap();
    assert_eq!(key.open(&s, &b, NOW, &m), Err(StateError::Store));
}

// AG-12, AGI-5, RS-M16
#[test]
fn a_list_is_public_only_when_every_candidate_is_public() {
    assert_eq!(
        scope_of([Visibility::Public, Visibility::Public]),
        CacheScope::Public
    );
    assert_eq!(
        scope_of([Visibility::Public, Visibility::Viewer]),
        CacheScope::Private
    );
    assert_eq!(
        scope_of([Visibility::Public, Visibility::Unknown]),
        CacheScope::Private
    );
    let key = |instance: u8, subject: &str, pos: u64| CacheKey {
        instance: [instance; 32],
        capacity: TokenCapacity::Own {
            subject: String::from(subject),
        },
        audience: String::from(RS),
        applied_pos: pos,
        projection: Digest([9; 32]),
    };
    let a = key(1, "p-1", 5);
    for other in [key(2, "p-1", 5), key(1, "p-2", 5), key(1, "p-1", 6)] {
        assert_ne!(a.digest(), other.digest());
    }
    let cache = ListCache::new(4);
    cache.put(
        &Slot::Private(a.clone()),
        CacheScope::Private,
        String::from("[1]"),
        (NOW, NOW + 10),
    );
    assert!(cache.get(&Slot::Private(key(2, "p-1", 5)), NOW).is_none());
    assert_eq!(
        cache.get(&Slot::Private(a.clone()), NOW),
        Some((CacheScope::Private, String::from("[1]")))
    );
    assert!(cache.get(&Slot::Private(a), NOW + 10).is_none());
    let public = Slot::Public(String::from(RS));
    cache.put(
        &public,
        CacheScope::Private,
        String::from("[2]"),
        (NOW, NOW + 10),
    );
    assert!(cache.get(&public, NOW).is_none());
}

// AG-15, A-8, U64
#[test]
fn a_stream_closes_at_the_earlier_of_token_expiry_and_horizon() {
    let e = Digest([5; 32]);
    let mut l = Listen::open(e, NOW, NOW + 600_000, NOW + 900_000).unwrap();
    assert_eq!(l.close_at(), NOW + 600_000);
    assert_eq!(l.next(NOW), Next::Open);
    assert_eq!(l.deliver(NOW + 1, "a"), Some("a"));
    assert_eq!(l.next(NOW + 300_000), Next::Checkpoint(e));
    assert_eq!(l.deliver(NOW + 300_001, "b"), None);
    l.continued(true);
    assert_eq!(l.deliver(NOW + 300_002, "c"), Some("c"));
    assert_eq!(l.present_token("new"), Err(ListenError::Refresh));
    assert_eq!(l.deliver(NOW + 600_000, "late"), None);
    assert_eq!(l.next(NOW + 600_001), Next::Closed(Closed::TokenExpired));
    let mut h = Listen::open(e, NOW, NOW + 900_000, NOW + 100_000).unwrap();
    h.signal();
    assert_eq!(h.next(NOW + 1), Next::Checkpoint(e));
    h.continued(false);
    assert_eq!(h.deliver(NOW + 2, "x"), None);
    assert_eq!(h.next(NOW + 3), Next::Closed(Closed::Denied));
    assert!(Listen::open(e, NOW, NOW, NOW + 1).is_err());
}

// §11.4.3, RFC 9728 §7.3, §11.5.2
#[test]
fn the_client_checks_the_resource_and_finds_metadata_in_order() {
    assert_eq!(
        canonical_resource("HTTPS://MCP.Example.com:443/mcp/").unwrap(),
        "https://mcp.example.com/mcp"
    );
    assert!(canonical_resource("https://mcp.example.com/mcp?x=1").is_err());
    assert!(canonical_resource("http://mcp.example.com").is_err());
    let c = parse_challenge(
        r#"Bearer error="insufficient_scope", scope="a b", resource_metadata="https://m.example/x""#,
    )
    .unwrap();
    assert_eq!(c.scope.as_deref(), Some("a b"));
    assert_eq!(
        metadata_urls("https://mcp.example.com/mcp", Some(&c)),
        vec![
            String::from("https://m.example/x"),
            String::from("https://mcp.example.com/.well-known/oauth-protected-resource/mcp"),
            String::from("https://mcp.example.com/.well-known/oauth-protected-resource"),
        ]
    );
    let p = prm();
    assert!(check_metadata(p.json().as_bytes(), RS).is_ok());
    assert!(check_metadata(p.json().as_bytes(), "https://other.example").is_err());
    assert_eq!(
        token_resource(
            "https://MCP.example.com/mcp",
            &[String::from("a"), String::from("offline_access")]
        )
        .unwrap(),
        "resource=https%3A%2F%2Fmcp.example.com%2Fmcp&scope=a"
    );
}

// AG-2, §9.4.1
#[test]
fn a_call_is_the_intent_of_its_tool_with_its_arguments() {
    let t = tool("open", None);
    let w = Window { from: 1, until: 2 };
    let args = json::parse(
        br#"{"door":"front","n":3,"ok":true,"opts":{"a":1},"none":null}"#,
        1024,
    )
    .unwrap();
    let e = intent(&t, Some(&args), w).unwrap();
    assert_eq!(e.action, action());
    assert_eq!(e.params.len(), 3);
    assert_eq!(e.opaque.len(), 1);
    let reordered =
        json::parse(br#"{"opts":{"a":1},"ok":true,"n":3,"door":"front"}"#, 1024).unwrap();
    assert_eq!(
        intent_digest(&e).unwrap(),
        intent_digest(&intent(&t, Some(&reordered), w).unwrap()).unwrap()
    );
    let changed = json::parse(br#"{"door":"back","n":3,"ok":true,"opts":{"a":1}}"#, 1024).unwrap();
    assert_ne!(
        intent_digest(&e).unwrap(),
        intent_digest(&intent(&t, Some(&changed), w).unwrap()).unwrap()
    );
    assert!(Tools::new(vec![tool("a", None), tool("a", None)]).is_err());
}

// §11.5.6, RS-M3, RS-M6, RS-M9, §11.5.3
#[test]
fn the_endpoint_is_post_only_and_asks_for_a_token_first() {
    let w = World::new();
    let m = support::Memory::healthy();
    let d = Scripted::default();
    let clock = FixedClock(NOW);
    let random = Seq(Cell::new(0));
    let ports = m.ports();
    let env = Env {
        clock: &clock,
        ports: &ports,
        decisions: &d,
        random: &random,
    };
    for method in ["GET", "DELETE"] {
        let r = respond(w.server().handle(
            &Request {
                method,
                path: "/",
                uri: URI,
                headers: Headers(&[("host", HOST)]),
                body: b"",
                certificate: None,
            },
            &env,
        ));
        assert_eq!(r.status, 405);
        assert_eq!(header(&r, "allow"), ["POST"]);
    }
    let r = respond(w.server().handle(
        &Request {
            method: "GET",
            path: "/.well-known/oauth-protected-resource",
            uri: URI,
            headers: Headers(&[("host", HOST)]),
            body: b"",
            certificate: None,
        },
        &env,
    ));
    assert_eq!(r.status, 200);
    assert_eq!(header(&r, "cache-control"), ["max-age=300"]);
    let list = rpc("tools/list", &format!(r#"{{"_meta":{}}}"#, meta_only()));
    let r = respond(send(&w, &[("host", HOST)], &list, &m, &d));
    assert_eq!(r.status, 401);
    assert_eq!(header(&r, "www-authenticate").len(), 2);
    let r = respond(send(
        &w,
        &[("host", HOST), ("authorization", "Bearer abc")],
        &list,
        &m,
        &d,
    ));
    assert_eq!(r.status, 401);
    assert!(header(&r, "www-authenticate")[0].contains("invalid_token"));
    // RS-M5
    let mut spec = TokenSpec::bounds_token();
    spec.audience = String::from("https://other.example");
    spec.contract_audience = String::from(r#""https://other.example""#);
    let token = spec.signed();
    let (a, p) = auth(&token, "j-aud");
    let r = respond(send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &list,
        &m,
        &d,
    ));
    assert_eq!(r.status, 401);
    assert!(header(&r, "www-authenticate")[0].contains("invalid_token"));
    assert!(d.asked.borrow().is_empty());
}

// AG-12, U63, AGI-5, RS-M17, A-10, §11.5.6
#[test]
fn a_list_follows_the_viewer_and_never_authorizes_a_call() {
    let w = World::new();
    let m = support::Memory::healthy();
    let d = Scripted::default();
    let token = TokenSpec::bounds_token().signed();
    let list = rpc("tools/list", &format!(r#"{{"_meta":{}}}"#, meta_only()));
    let (a, p) = auth(&token, "j-1");
    let r = respond(send(
        &w,
        &[
            ("host", HOST),
            ("authorization", &a),
            ("dpop", &p),
            ("mcp-session-id", "s-1"),
        ],
        &list,
        &m,
        &d,
    ));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(header(&r, "mcp-session-id"), Vec::<&str>::new());
    let v = body(&r);
    let result = v.get("result").unwrap();
    assert_eq!(
        result.get("cacheScope").and_then(Json::as_str),
        Some("private")
    );
    let Some(Json::Array(tools)) = result.get("tools") else {
        panic!("tools")
    };
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].get("name").and_then(Json::as_str), Some("open"));
    let call = rpc(
        "tools/call",
        &format!(r#"{{"name":"lock","_meta":{}}}"#, meta_only()),
    );
    let (a, p) = auth(&token, "j-2");
    let r = respond(send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &call,
        &m,
        &d,
    ));
    assert_eq!(r.status, 403);
    assert!(header(&r, "www-authenticate")[0].contains("insufficient_scope"));
    let mut spec = TokenSpec::bounds_token();
    spec.action_type = String::from("door:lock:1");
    spec.jkt = support::kid(OTHER_SEED);
    let other = spec.signed();
    let p = proof_with(OTHER_SEED, &other, "j-3", "POST", URI, None);
    let a = format!("DPoP {other}");
    let r = respond(send(
        &w,
        &[
            ("host", HOST),
            ("authorization", &a),
            ("dpop", &p),
            ("mcp-session-id", "s-1"),
        ],
        &list,
        &m,
        &d,
    ));
    let v = body(&r);
    let result = v.get("result").unwrap();
    assert_eq!(
        result.get("cacheScope").and_then(Json::as_str),
        Some("private")
    );
    let Some(Json::Array(tools)) = result.get("tools") else {
        panic!("tools")
    };
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].get("name").and_then(Json::as_str), Some("lock"));
}

// AG-12, AGI-5, AG-14
#[test]
fn a_list_of_public_grant_tools_is_public() {
    let mut w = World::new();
    w.tools = Tools::new(vec![tool("open", Some(access_kernel::model::Id([7; 16])))]).unwrap();
    let m = support::Memory::healthy();
    let d = Scripted::default();
    d.answers.borrow_mut().push(ok(
        br#"{"decision":true,"context":{"outcome":"allow"}}"#.to_vec()
    ));
    let token = TokenSpec::bounds_token().signed();
    let (a, p) = auth(&token, "j-1");
    let list = rpc("tools/list", &format!(r#"{{"_meta":{}}}"#, meta_only()));
    let r = respond(send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &list,
        &m,
        &d,
    ));
    let v = body(&r);
    assert_eq!(
        v.get("result")
            .and_then(|r| r.get("cacheScope"))
            .and_then(Json::as_str),
        Some("public")
    );
    assert_eq!(d.asked.borrow()[0].0, Mode::Check);
    let (a, p) = auth(&token, "j-2");
    let w2 = World {
        cache: ListCache::new(16),
        ..w
    };
    let r = respond(send(
        &w2,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &list,
        &m,
        &d,
    ));
    let v = body(&r);
    assert_eq!(
        v.get("result")
            .and_then(|r| r.get("cacheScope"))
            .and_then(Json::as_str),
        Some("private")
    );
}

fn statement_for(intent: Digest, nonce: &[u8], mode: Mode, exercise: Option<Digest>) -> Vec<u8> {
    let s = Statement {
        domain: domain(),
        nonce: nonce.to_vec(),
        intent,
        mode,
        pep: String::from(PEP),
        capacity: Capacity::Own,
        basis: basis(),
        iat: NOW - 1_000,
        exercise,
    };
    sign1(HOLDER_SEED, CONTENT_TYPE, &s.to_bytes().unwrap())
}

fn require_action() -> Answer {
    ok(br#"{"decision":false,"context":{"outcome":"require_action"}}"#.to_vec())
}

// AG-2, AG-13, AGI-6, EI-18, §11.5.5, §9.9.5, P54
#[test]
fn a_call_with_a_statement_is_one_decision_and_a_retry_is_another() {
    let w = World::new();
    let m = support::Memory::healthy();
    let d = Scripted::default();
    let token = TokenSpec::bounds_token().signed();
    let window = Window {
        from: NOW - 1_000,
        until: NOW + 60_000,
    };
    let digest = intent_digest(&intent(&tool("open", None), None, window).unwrap()).unwrap();
    let nonce = [0xab; 16];
    let ais = statement_for(digest, &nonce, Mode::Commit, None);
    let meta = access_sdk::mcp::client::meta(Some(&ais), Some(window), None);
    let call = rpc(
        "tools/call",
        &format!(r#"{{"name":"open","_meta":{meta}}}"#),
    );
    d.answers.borrow_mut().push(require_action());
    let (a, p) = auth(&token, "j-1");
    let r = respond(send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &call,
        &m,
        &d,
    ));
    assert_eq!(r.status, 200, "{}", r.body);
    let v = body(&r);
    let result = v.get("result").unwrap();
    assert_eq!(
        result.get("resultType").and_then(Json::as_str),
        Some("input_required")
    );
    let el = result
        .get("inputRequests")
        .and_then(|i| i.get("access.approval"))
        .and_then(|e| e.get("params"))
        .unwrap();
    // EI-18
    assert_eq!(el.get("mode").and_then(Json::as_str), Some("url"));
    assert_eq!(
        el.get("url").and_then(Json::as_str),
        Some("https://as.example/approve")
    );
    assert!(el.get("requestedSchema").is_none());
    let state = String::from(result.get("requestState").and_then(Json::as_str).unwrap());

    let receipt = receipt_for(&nonce, PEP, &digest);
    d.answers.borrow_mut().push(ok(allow_body(&receipt, "")));
    let retry = rpc(
        "tools/call",
        &format!(
            r#"{{"name":"open","requestState":"{state}","inputResponses":{{"access.approval":{{"action":"accept"}}}},"_meta":{meta}}}"#
        ),
    );
    let (a, p) = auth(&token, "j-2");
    let h = send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &retry,
        &m,
        &d,
    );
    let Handled::Call(c) = h else { panic!("{h:?}") };
    assert_eq!(d.asked.borrow().len(), 2);
    let ran = Cell::new(false);
    let r = c.run(|_, _, _| {
        ran.set(true);
        Json::Object(vec![(String::from("content"), Json::Array(Vec::new()))])
    });
    assert!(ran.get());
    assert_eq!(r.status, 200);

    // AGI-6, AG-13
    let (a, p) = auth(&token, "j-3");
    let r = respond(send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &retry,
        &m,
        &d,
    ));
    assert!(r.body.contains("request-state-replayed"), "{}", r.body);
    assert_eq!(d.asked.borrow().len(), 2);

    d.answers.borrow_mut().push(require_action());
    let (a, p) = auth(&token, "j-4");
    let r = respond(send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &call,
        &m,
        &d,
    ));
    let fresh = String::from(
        body(&r)
            .get("result")
            .and_then(|r| r.get("requestState"))
            .and_then(Json::as_str)
            .unwrap(),
    );
    let rebound = rpc(
        "tools/call",
        &format!(
            r#"{{"name":"open","arguments":{{"door":"back"}},"requestState":"{fresh}","_meta":{meta}}}"#
        ),
    );
    let before = d.asked.borrow().len();
    let (a, p) = auth(&token, "j-5");
    let r = respond(send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &rebound,
        &m,
        &d,
    ));
    assert!(r.body.contains("request-state"), "{}", r.body);
    assert_eq!(d.asked.borrow().len(), before);
}

// AG-2, INV-19, §11.5.4
#[test]
fn a_call_without_a_statement_needs_a_token_for_this_intent() {
    let w = World::new();
    let m = support::Memory::healthy();
    let d = Scripted::default();
    let token = TokenSpec::bounds_token().signed();
    let call = rpc(
        "tools/call",
        &format!(r#"{{"name":"open","_meta":{}}}"#, meta_only()),
    );
    let (a, p) = auth(&token, "j-1");
    let h = send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &call,
        &m,
        &d,
    );
    assert!(matches!(h, Handled::Call(_)), "{h:?}");
    let exact = TokenSpec::intent_token().signed();
    let (a, p) = auth(&exact, "j-2");
    let r = respond(send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &call,
        &m,
        &d,
    ));
    assert_eq!(r.status, 403);
    assert!(d.asked.borrow().is_empty());
}

// AG-15, U64, A-8
#[test]
fn a_stream_opens_on_a_decision_and_continues_once_with_its_statement() {
    let w = World::new();
    let m = support::Memory::healthy();
    let d = Scripted::default();
    let token = TokenSpec::bounds_token().signed();
    let window = Window {
        from: NOW - 1_000,
        until: NOW + 120_000,
    };
    let digest = intent_digest(&intent(&tool("open", None), None, window).unwrap()).unwrap();
    let nonce = [0xab; 16];
    let exercise = access_kernel::meta::exercise_id(&domain(), &nonce).unwrap();
    let ais = statement_for(digest, &nonce, Mode::Commit, None);
    let cont_nonce = [0xcd; 16];
    let cont = statement_for(digest, &cont_nonce, Mode::Continue, Some(exercise));
    let meta = access_sdk::mcp::client::meta(Some(&ais), Some(window), Some(&cont));
    let listen = rpc("subscriptions/listen", &format!(r#"{{"_meta":{meta}}}"#));
    d.answers
        .borrow_mut()
        .push(ok(allow_body(&receipt_for(&nonce, PEP, &digest), "")));
    let (a, p) = auth(&token, "j-1");
    let h = send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &listen,
        &m,
        &d,
    );
    let Handled::Listen(mut s) = h else {
        panic!("{h:?}")
    };
    assert!(Stream::headers().contains(&(String::from("x-accel-buffering"), String::from("no"))));
    assert_eq!(s.listen.close_at(), NOW + 120_000);
    let half = NOW + 60_000;
    assert!(matches!(s.listen.next(half), Next::Checkpoint(_)));
    let mut r = receipt_for(&cont_nonce, PEP, &digest);
    r.exercise = exercise;
    d.answers.borrow_mut().push(ok(allow_body(&r, "")));
    assert!(w.server().checkpoint(&mut s, &FixedClock(half), &d));
    assert_eq!(d.asked.borrow()[1].0, Mode::Continue);
    assert_eq!(s.listen.deliver(half + 1, 1), Some(1));
    assert_eq!(s.listen.deliver(NOW + 120_000, 2), None);
    assert!(matches!(
        s.listen.next(NOW + 120_001),
        Next::Closed(Closed::Horizon)
    ));
}

// AG-15, A-8
#[test]
fn a_checkpoint_without_a_statement_closes_the_stream() {
    let w = World::new();
    let m = support::Memory::healthy();
    let d = Scripted::default();
    let token = TokenSpec::bounds_token().signed();
    let listen = rpc(
        "subscriptions/listen",
        &format!(r#"{{"_meta":{}}}"#, meta_only()),
    );
    let (a, p) = auth(&token, "j-1");
    let h = send(
        &w,
        &[("host", HOST), ("authorization", &a), ("dpop", &p)],
        &listen,
        &m,
        &d,
    );
    let Handled::Listen(mut s) = h else {
        panic!("{h:?}")
    };
    s.listen.signal();
    assert!(!w.server().checkpoint(&mut s, &FixedClock(NOW + 1), &d));
    assert!(d.asked.borrow().is_empty());
    assert_eq!(s.listen.deliver(NOW + 2, ()), None);
    assert_eq!(s.listen.next(NOW + 3), Next::Closed(Closed::Denied));
}
