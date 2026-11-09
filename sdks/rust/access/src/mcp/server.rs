//! One MCP endpoint as a resource server and PEP (§11.5, §11.5.6, RS-M1 to RS-M19, AG-9 to
//! AG-15). [`McpServer::handle`] answers the metadata route and `POST` on the MCP path:
//!
//! 1. Header hygiene, `Origin` and `Host`, then the JSON-RPC body and its mirrored headers.
//! 2. The token on every request (RS-M9, RS-M12): DPoP- or mTLS-bound, for this audience only,
//!    never passed on (RS-M8, RS-M10). Nothing from an earlier request is used (RS-M19).
//! 3. `tools/list`: the viewer-scoped disclosure with its `cacheScope` (AG-12).
//!    `server/discover`: authenticated unless a Public Grant opens it (AG-14).
//! 4. `tools/call`: one decision for one exact intent (AG-2, INV-19). With the actor's statement
//!    in `_meta` it is an ADP `commit` the server forwards as PEP; without it the token itself
//!    must be an exact-intent token for this intent or a bounds token covering it. A required
//!    action answers MRTR `input_required` whose only elicitation is the Approval Surface
//!    address, with a `requestState` bound to the request (AG-13, EI-18); the retry is decided
//!    anew.
//! 5. `subscriptions/listen`: a long-running exercise governed by [`Listen`] (AG-15).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use access_kernel::ais::Statement;
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::json::{Json, b64url_encode};
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{ActionRef, Id, ResourceRef, TrustedTime, Window};
use access_kernel::verify::cose::parse_sign1;

use super::PROTOCOL_VERSION;
use super::cache::{CacheKey, CacheScope, ListCache, Slot, Visibility, scope_of};
use super::challenge::{Challenge, www_authenticate};
use super::json::{render, text, value};
use super::listen::{Listen, SSE_HEADERS};
use super::prm::{Binding as TokenBinding, ProtectedResource, split};
use super::state::{Binding, StateKey};
use super::tool::{ToolDef, Tools, intent};
use super::wire::{self, Headers, Origins, Rejection, Rpc};
use crate::auth::Random;
use crate::authorize::{
    Action, Actor, Ask, AskDecision, Authorized, Denied as Refused, Evidence, ExerciseRequest,
    Intent, Nonce, Pep, Refusal, Resource,
};
use crate::resource::{
    Authority, Introspector, KeySource, NonceSource, Ports, Presented, ReplayStore, ResourceServer,
    Revocations, StatusSource,
};
use crate::transport::{Answer, Clock};

/// Default validity of an intent the server builds itself (no statement): one minute.
pub const DEFAULT_VALIDITY_MS: u64 = 60_000;

/// JSON-RPC code of a call Access refused.
pub const ACCESS_DENIED: i64 = -32001;

/// JSON-RPC code of a call no decision could be obtained for.
pub const ACCESS_UNAVAILABLE: i64 = -32002;

/// JSON-RPC code of an unknown method.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// JSON-RPC code of bad parameters, a refused `requestState` included.
pub const INVALID_PARAMS: i64 = -32602;

/// The elicitation key of the Approval Surface address in an `input_required` answer.
pub const APPROVAL_INPUT: &str = "access.approval";

/// The resource marker of a tool call's proof: the tool table, not the type, names the
/// resource.
#[derive(Debug)]
pub struct ToolResource;

impl Resource for ToolResource {
    const NAMESPACE: &'static str = "mcp";
}

/// The action marker of a tool call's proof.
#[derive(Debug)]
pub struct ToolCall;

impl Action for ToolCall {
    const NAMESPACE: &'static str = "mcp";
    const NAME: &'static str = "call";
}

/// One HTTP request as received.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The method.
    pub method: &'a str,
    /// The path, without query.
    pub path: &'a str,
    /// The absolute request URI as this server sees it (the DPoP `htu`).
    pub uri: &'a str,
    /// The headers.
    pub headers: Headers<'a>,
    /// The body.
    pub body: &'a [u8],
    /// The SHA-256 thumbprint of the client certificate, for an mTLS request.
    pub certificate: Option<[u8; 32]>,
}

/// One HTTP answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The status.
    pub status: u16,
    /// The headers; `Mcp-Session-Id` is never among them.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: String,
}

impl Response {
    fn json(status: u16, body: String) -> Self {
        Self {
            status,
            headers: alloc::vec![(
                String::from("content-type"),
                String::from("application/json")
            )],
            body,
        }
    }

    fn with(mut self, name: &str, value: String) -> Self {
        self.headers.push((String::from(name), value));
        self
    }
}

/// An authorized tool call: the host runs the tool through [`Call::run`], which consumes the
/// proof (§9.5.2 k.6).
pub struct Call {
    /// The JSON-RPC id.
    pub id: Json,
    /// The tool.
    pub tool: ToolDef,
    /// The arguments, as sent.
    pub arguments: Json,
    authorized: Authorized<ToolResource, ToolCall>,
    digest: Digest,
}

impl core::fmt::Debug for Call {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Call")
            .field("tool", &self.tool.name)
            .field("authorized", &self.authorized)
            .finish_non_exhaustive()
    }
}

impl Call {
    /// The `ExerciseID` the call runs under.
    #[must_use]
    pub const fn exercise(&self) -> &Digest {
        self.authorized.exercise()
    }

    /// Runs the tool once and answers its `CallToolResult`.
    #[must_use]
    pub fn run(self, effect: impl FnOnce(&ToolDef, &Json, Evidence<'_>) -> Json) -> Response {
        let Self {
            id,
            tool,
            arguments,
            authorized,
            digest,
        } = self;
        match authorized.apply(&digest, |evidence| effect(&tool, &arguments, evidence)) {
            Ok(result) => result_response(&id, &result),
            Err(_) => error_response(403, &id, ACCESS_DENIED, "intent-body"),
        }
    }
}

/// An open `subscriptions/listen` stream: the host sends [`SSE_HEADERS`] and drives
/// [`Stream::listen`], asking [`McpServer::checkpoint`] when it says so.
pub struct Stream {
    /// The JSON-RPC id.
    pub id: Json,
    /// The governor.
    pub listen: Listen,
    intent: Intent<ToolResource, ToolCall>,
    continue_ais: Option<Vec<u8>>,
}

impl core::fmt::Debug for Stream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stream")
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

impl Stream {
    /// The response headers of the stream.
    #[must_use]
    pub fn headers() -> Vec<(String, String)> {
        SSE_HEADERS
            .iter()
            .map(|(k, v)| (String::from(*k), String::from(*v)))
            .collect()
    }
}

/// What the host does with a request.
#[derive(Debug)]
pub enum Handled {
    /// Send this answer.
    Respond(Response),
    /// Run this authorized call.
    Call(Call),
    /// Open this stream.
    Listen(Stream),
}

/// A capability probe a Public Grant opens (AG-14): an anonymous check of `action` on
/// `resource` under `grant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discoverable {
    /// The action the probe is a check of.
    pub action: ActionRef,
    /// The resource.
    pub resource: ResourceRef,
    /// The Public Grant.
    pub grant: Id,
}

/// One MCP endpoint.
#[derive(Debug)]
pub struct McpServer<'a> {
    /// The published metadata; its `resource` is the audience.
    pub prm: &'a ProtectedResource,
    /// The rendered metadata body (signed or not), served as is.
    pub metadata: &'a str,
    /// Allowed origins and hosts.
    pub origins: &'a Origins,
    /// The token verifier.
    pub rs: &'a ResourceServer,
    /// The PEP.
    pub pep: &'a Pep,
    /// The tools.
    pub tools: &'a Tools,
    /// The action and resource a stream exercises, when the server offers streams.
    pub subscriptions: Option<&'a ToolDef>,
    /// The `requestState` key.
    pub state: &'a StateKey,
    /// The list cache.
    pub cache: &'a ListCache,
    /// The Approval Surface address an elicitation carries.
    pub approval_surface: &'a str,
    /// `ttlMs` of list results.
    pub list_ttl_ms: u64,
    /// The Public Grant that opens `server/discover`, when there is one.
    pub discover: Option<&'a Discoverable>,
    /// The server's self-reported name.
    pub name: &'a str,
}

/// The ports of one request.
#[derive(Clone, Copy)]
pub struct Env<'a, K, P, N, S, I, V, D, G> {
    /// Trusted time.
    pub clock: &'a dyn Clock,
    /// The token ports.
    pub ports: &'a Ports<'a, K, P, N, S, I, V>,
    /// The decision point.
    pub decisions: &'a D,
    /// The random source.
    pub random: &'a G,
}

fn error_body(id: &Json, code: i64, message: &str) -> String {
    let mut out = String::from("{\"jsonrpc\":\"2.0\",\"id\":");
    value(&mut out, id);
    let _ = write!(out, ",\"error\":{{\"code\":{code},\"message\":");
    text(&mut out, message);
    out.push_str("}}");
    out
}

fn error_response(status: u16, id: &Json, code: i64, message: &str) -> Response {
    Response::json(status, error_body(id, code, message))
}

fn result_response(id: &Json, result: &Json) -> Response {
    let mut out = String::from("{\"jsonrpc\":\"2.0\",\"id\":");
    value(&mut out, id);
    out.push_str(",\"result\":");
    value(&mut out, result);
    out.push('}');
    Response::json(200, out)
}

fn rejected(r: Rejection) -> Response {
    let mut resp = error_response(
        r.status(),
        &Json::Null,
        r.rpc_code(),
        &alloc::format!("{r}"),
    );
    if r == Rejection::MethodNotAllowed {
        resp = resp.with("allow", String::from("POST"));
    }
    resp
}

fn statement(ais: &[u8]) -> Option<Statement> {
    let payload = parse_sign1(ais).ok()?.payload?;
    Statement::from_bytes(&payload).ok()
}

/// What the request presented, or why it presented nothing usable.
enum Credential<'a> {
    None,
    Token(&'a str),
    Malformed,
}

impl McpServer<'_> {
    fn mcp_path(&self) -> &str {
        let (_, path) = split(self.prm.resource());
        if path.is_empty() { "/" } else { path }
    }

    fn challenged(&self, c: &Challenge) -> Response {
        let mut r = error_response(c.status(), &Json::Null, -32600, "unauthorized");
        for v in www_authenticate(c, self.prm) {
            r = r.with("www-authenticate", v);
        }
        r
    }

    fn credential<'r>(&self, headers: &Headers<'r>) -> Credential<'r> {
        if headers.count("authorization") > 1 {
            return Credential::Malformed;
        }
        let Some(value) = headers.get("authorization") else {
            return Credential::None;
        };
        let scheme = match self.prm.binding() {
            TokenBinding::Dpop(_) => "DPoP ",
            TokenBinding::Mtls => "Bearer ",
        };
        match value.get(..scheme.len()) {
            Some(s) if s.eq_ignore_ascii_case(scheme) => value
                .get(scheme.len()..)
                .map(str::trim)
                .filter(|t| !t.is_empty() && !t.contains(' '))
                .map_or(Credential::Malformed, Credential::Token),
            _ => Credential::Malformed,
        }
    }

    /// Answers one request.
    #[must_use]
    pub fn handle<K, P, N, S, I, V, D, G>(
        &self,
        req: &Request<'_>,
        env: &Env<'_, K, P, N, S, I, V, D, G>,
    ) -> Handled
    where
        K: KeySource,
        P: ReplayStore,
        N: NonceSource,
        S: StatusSource,
        I: Introspector,
        V: Revocations,
        D: AskDecision,
        G: Random,
    {
        if let Err(r) = wire::hygiene(&req.headers) {
            return Handled::Respond(rejected(r));
        }
        // RS-M1, §11.5.6
        if req.path == self.prm.well_known_path() {
            if !req.method.eq_ignore_ascii_case("GET") {
                return Handled::Respond(
                    rejected(Rejection::MethodNotAllowed).with("allow", String::from("GET")),
                );
            }
            return Handled::Respond(
                Response::json(200, String::from(self.metadata))
                    .with("cache-control", String::from(super::prm::CACHE_CONTROL)),
            );
        }
        if req.path != self.mcp_path() {
            return Handled::Respond(error_response(404, &Json::Null, -32600, "not-found"));
        }
        // §11.5.3
        if !req.method.eq_ignore_ascii_case("POST") {
            return Handled::Respond(rejected(Rejection::MethodNotAllowed));
        }
        // RS-M15
        if let Err(r) = self.origins.check(&req.headers) {
            return Handled::Respond(rejected(r));
        }
        let rpc = match wire::parse(req.body) {
            Ok(rpc) => rpc,
            Err(r) => return Handled::Respond(rejected(r)),
        };
        let tool_name = (rpc.method == "tools/call")
            .then(|| rpc.params.get("name").and_then(Json::as_str))
            .flatten();
        // RS-M14
        if let Err(r) = wire::consistent(&req.headers, &rpc, |a| self.tools.secret(tool_name, a)) {
            return Handled::Respond(rejected(r));
        }
        if rpc.method.starts_with("notifications/") && rpc.id == Json::Null {
            return Handled::Respond(Response {
                status: 202,
                headers: Vec::new(),
                body: String::new(),
            });
        }
        let credential = self.credential(&req.headers);
        if rpc.method == "server/discover" {
            return Handled::Respond(self.discover(req, &rpc, &credential, env));
        }
        let token = match credential {
            Credential::Token(t) => t,
            // RS-M3, §11.5.6
            Credential::None => return Handled::Respond(self.challenged(&Challenge::Missing)),
            Credential::Malformed => {
                return Handled::Respond(self.challenged(&Challenge::InvalidToken));
            }
        };
        let presented = Presented {
            token,
            method: "POST",
            uri: req.uri,
            proof: req.headers.get("dpop"),
            certificate: req.certificate,
            content_position: None,
            satisfied: &[],
        };
        match rpc.method.as_str() {
            "tools/list" => Handled::Respond(self.list(&rpc, &presented, env)),
            "tools/call" => self.call(&rpc, &presented, env),
            "subscriptions/listen" => self.open_stream(&rpc, &presented, env),
            _ => Handled::Respond(error_response(
                200,
                &rpc.id,
                METHOD_NOT_FOUND,
                "method-not-found",
            )),
        }
    }

    fn authenticated<K, P, N, S, I, V, D, G>(
        &self,
        presented: &Presented<'_>,
        env: &Env<'_, K, P, N, S, I, V, D, G>,
    ) -> Result<Authority, Response>
    where
        K: KeySource,
        P: ReplayStore,
        N: NonceSource,
        S: StatusSource,
        I: Introspector,
        V: Revocations,
    {
        self.rs
            .authenticate(presented, &env.clock, env.ports)
            .map_err(|d| self.challenged(&Challenge::of(&d, &[])))
    }

    /// An anonymous check of `action` on `resource` under the Public Grant `grant` (AG-12,
    /// AG-14, INV-11): `Some(true)` allowed, `Some(false)` refused, `None` unknown.
    fn public_check<D: AskDecision, G: Random>(
        &self,
        (action, resource, grant): (&ActionRef, &ResourceRef, Id),
        now: TrustedTime,
        decisions: &D,
        random: &G,
    ) -> Option<bool> {
        let envelope = IntentEnvelope {
            action: action.clone(),
            resources: alloc::vec![resource.clone()],
            params: alloc::collections::BTreeMap::new(),
            opaque: alloc::collections::BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window {
                from: now,
                until: now.checked_add(DEFAULT_VALIDITY_MS)?,
            },
        };
        let digest = intent_digest(&envelope).ok()?;
        let mut nonce = [0u8; 16];
        random.fill(&mut nonce).ok()?;
        let request = ExerciseRequest {
            domain: &self.pep.domain,
            mode: Mode::Check,
            nonce: &nonce,
            intent: &digest,
            envelope: Some(&envelope),
            actor: &Actor::Anonymous,
            basis: &ExerciseBasis::Public(grant),
            capacity: Capacity::Own,
            pep: &self.pep.audience,
            exercise: None,
        };
        let Answer::Response(r) = decisions.ask(&request) else {
            return None;
        };
        if r.status != 200 {
            return None;
        }
        match access_kernel::json::parse(&r.body, crate::authorize::MAX_BODY)
            .ok()?
            .get("decision")
        {
            Some(Json::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    fn discover<K, P, N, S, I, V, D, G>(
        &self,
        req: &Request<'_>,
        rpc: &Rpc,
        credential: &Credential<'_>,
        env: &Env<'_, K, P, N, S, I, V, D, G>,
    ) -> Response
    where
        K: KeySource,
        P: ReplayStore,
        N: NonceSource,
        S: StatusSource,
        I: Introspector,
        V: Revocations,
        D: AskDecision,
        G: Random,
    {
        let Some(now) = env.clock.now() else {
            return error_response(503, &rpc.id, ACCESS_UNAVAILABLE, "clock");
        };
        // AG-14
        let scope = match credential {
            Credential::None => {
                let open = self.discover.and_then(|d| {
                    self.public_check(
                        (&d.action, &d.resource, d.grant),
                        now,
                        env.decisions,
                        env.random,
                    )
                });
                if open != Some(true) {
                    return self.challenged(&Challenge::Missing);
                }
                CacheScope::Public
            }
            Credential::Malformed => return self.challenged(&Challenge::InvalidToken),
            Credential::Token(token) => {
                let presented = Presented {
                    token,
                    method: "POST",
                    uri: req.uri,
                    proof: req.headers.get("dpop"),
                    certificate: req.certificate,
                    content_position: None,
                    satisfied: &[],
                };
                if let Err(r) = self.authenticated(&presented, env) {
                    return r;
                }
                CacheScope::Private
            }
        };
        let mut out = String::from("{\"protocolVersions\":[");
        text(&mut out, PROTOCOL_VERSION);
        out.push_str("],\"capabilities\":{\"tools\":{}");
        if self.subscriptions.is_some() {
            out.push_str(",\"subscriptions\":{}");
        }
        out.push_str("},\"serverInfo\":{\"name\":");
        text(&mut out, self.name);
        let _ = write!(out, "}},\"ttlMs\":{},\"cacheScope\":", self.list_ttl_ms);
        text(&mut out, scope.as_str());
        out.push('}');
        let mut body = String::from("{\"jsonrpc\":\"2.0\",\"id\":");
        value(&mut body, &rpc.id);
        body.push_str(",\"result\":");
        body.push_str(&out);
        body.push('}');
        Response::json(200, body)
    }

    fn list<K, P, N, S, I, V, D, G>(
        &self,
        rpc: &Rpc,
        presented: &Presented<'_>,
        env: &Env<'_, K, P, N, S, I, V, D, G>,
    ) -> Response
    where
        K: KeySource,
        P: ReplayStore,
        N: NonceSource,
        S: StatusSource,
        I: Introspector,
        V: Revocations,
        D: AskDecision,
        G: Random,
    {
        let authority = match self.authenticated(presented, env) {
            Ok(a) => a,
            Err(r) => return r,
        };
        let Some(now) = env.clock.now() else {
            return error_response(503, &rpc.id, ACCESS_UNAVAILABLE, "clock");
        };
        // AG-12
        let private = Slot::Private(CacheKey {
            instance: authority.holder,
            capacity: authority.capacity.clone(),
            audience: String::from(self.rs.audience()),
            applied_pos: authority.as_of,
            projection: authority.exercise,
        });
        let (scope, items) = if let Some((scope, items)) = self.cache.get(&private, now) {
            (scope, items)
        } else {
            let mut seen = Vec::new();
            let mut items = String::from("[");
            for tool in self.tools.all() {
                let viewer = authority.actions.iter().any(|a| a.is(&tool.action));
                let (visible, how) = match tool.public {
                    Some(grant) => match self.public_check(
                        (&tool.action, &tool.resource, grant),
                        now,
                        env.decisions,
                        env.random,
                    ) {
                        Some(true) => (true, Visibility::Public),
                        Some(false) => (viewer, Visibility::Viewer),
                        None => (viewer, Visibility::Unknown),
                    },
                    None => (viewer, Visibility::Viewer),
                };
                seen.push(how);
                if visible {
                    if items.len() > 1 {
                        items.push(',');
                    }
                    value(&mut items, &tool.listing);
                }
            }
            items.push(']');
            let scope = scope_of(seen);
            let until = now.saturating_add(self.list_ttl_ms);
            let slot = match scope {
                CacheScope::Public => Slot::Public(String::from(self.rs.audience())),
                CacheScope::Private => private,
            };
            self.cache.put(&slot, scope, items.clone(), (now, until));
            (scope, items)
        };
        let mut body = String::from("{\"jsonrpc\":\"2.0\",\"id\":");
        value(&mut body, &rpc.id);
        body.push_str(",\"result\":{\"tools\":");
        body.push_str(&items);
        let _ = write!(body, ",\"ttlMs\":{},\"cacheScope\":", self.list_ttl_ms);
        text(&mut body, scope.as_str());
        body.push_str("}}");
        Response::json(200, body)
    }

    /// The intent of a call of `tool` in `rpc`: over the statement's validity window when the
    /// actor sent one, else over [`DEFAULT_VALIDITY_MS`] from now.
    fn call_intent(
        tool: &ToolDef,
        rpc: &Rpc,
        now: TrustedTime,
    ) -> Option<Intent<ToolResource, ToolCall>> {
        let validity = match rpc.access.validity {
            Some(w) => w,
            None => Window {
                from: now,
                until: now.checked_add(DEFAULT_VALIDITY_MS)?,
            },
        };
        let envelope = intent(tool, rpc.params.get("arguments"), validity).ok()?;
        Intent::named(envelope).ok()
    }

    /// The decision for `intent` asked with the actor's statement `ais` (§9.5), the nonce the
    /// state named enforced.
    fn decided<D: AskDecision>(
        &self,
        intent: &Intent<ToolResource, ToolCall>,
        ais: &[u8],
        continued: Option<&Digest>,
        expected_nonce: Option<&[u8]>,
        (clock, decisions): (&dyn Clock, &D),
    ) -> Result<(Authorized<ToolResource, ToolCall>, Vec<u8>), Refused> {
        let s = statement(ais).ok_or(Refused::Actor("payload"))?;
        // AG-13, P54
        if expected_nonce.is_some_and(|n| n != s.nonce.as_slice()) {
            return Err(Refused::Actor("nonce"));
        }
        let nonce = Nonce::new(s.nonce.clone()).map_err(|_| Refused::Actor("nonce"))?;
        let actor = Actor::Statement(ais.to_vec());
        let ask = Ask {
            intent,
            nonce: &nonce,
            actor: &actor,
            basis: &s.basis,
            capacity: s.capacity,
            continued,
            content_position: None,
        };
        self.pep
            .authorize(&ask, &clock, decisions)
            .map(|a| (a, s.nonce))
    }

    fn refusal(&self, id: &Json, d: Refused) -> Response {
        match d {
            Refused::Refused(Refusal::RequireAction) => self.challenged(&Challenge::Authorization),
            Refused::Refused(_) => error_response(403, id, ACCESS_DENIED, "denied"),
            Refused::Clock | Refused::Unavailable(_) | Refused::Status(_) | Refused::Malformed => {
                error_response(503, id, ACCESS_UNAVAILABLE, d.code())
            }
            _ => error_response(403, id, ACCESS_DENIED, d.code()),
        }
    }

    /// The MRTR answer to a required action (§11.5.5, §9.9.5, EI-18): the only input asked
    /// for is the Approval Surface address as a URL elicitation, and the `requestState` is
    /// bound to this request and carries the nonce.
    fn input_required(&self, id: &Json, state: &str, exercise: &Digest) -> Response {
        let mut out = String::from("{\"jsonrpc\":\"2.0\",\"id\":");
        value(&mut out, id);
        out.push_str(",\"result\":{\"resultType\":\"input_required\",\"inputRequests\":{");
        text(&mut out, APPROVAL_INPUT);
        out.push_str(":{\"method\":\"elicitation/create\",\"params\":{\"mode\":\"url\",\"url\":");
        text(&mut out, self.approval_surface);
        out.push_str(",\"elicitationId\":");
        text(&mut out, &b64url_encode(&exercise.0));
        out.push_str(",\"message\":");
        text(&mut out, APPROVAL_INPUT);
        out.push_str("}}},\"requestState\":");
        text(&mut out, state);
        out.push_str("}}");
        Response::json(200, out)
    }

    #[allow(clippy::too_many_lines, reason = "one tool call, in spec order")]
    fn call<K, P, N, S, I, V, D, G>(
        &self,
        rpc: &Rpc,
        presented: &Presented<'_>,
        env: &Env<'_, K, P, N, S, I, V, D, G>,
    ) -> Handled
    where
        K: KeySource,
        P: ReplayStore,
        N: NonceSource,
        S: StatusSource,
        I: Introspector,
        V: Revocations,
        D: AskDecision,
        G: Random,
    {
        let Some(now) = env.clock.now() else {
            return Handled::Respond(error_response(503, &rpc.id, ACCESS_UNAVAILABLE, "clock"));
        };
        let Some(tool) = rpc
            .params
            .get("name")
            .and_then(Json::as_str)
            .and_then(|n| self.tools.get(n))
        else {
            return Handled::Respond(error_response(200, &rpc.id, INVALID_PARAMS, "unknown-tool"));
        };
        let Some(intent) = Self::call_intent(tool, rpc, now) else {
            return Handled::Respond(error_response(200, &rpc.id, INVALID_PARAMS, "arguments"));
        };
        // RS-M9, RS-M12
        let (authority, token_authorized) = match &rpc.access.ais {
            Some(_) => match self.authenticated(presented, env) {
                Ok(a) => (a, None),
                Err(r) => return Handled::Respond(r),
            },
            None => match self.rs.verify(presented, &intent, &env.clock, env.ports) {
                Ok(v) => (v.authority, Some(v.authorized)),
                Err(d) => {
                    return Handled::Respond(self.challenged(&Challenge::of(&d, &tool.scopes)));
                }
            },
        };
        let audience = String::from(self.rs.audience());
        let binding = Binding {
            instance: &authority.holder,
            capacity: &authority.capacity,
            audience: &audience,
            intent: intent.digest(),
        };
        // AG-13, AGI-6
        let expected_nonce = match &rpc.request_state {
            None => None,
            Some(s) => match self.state.open(s, &binding, now, env.ports.replay) {
                Ok(opened) => opened.nonce,
                Err(e) => {
                    return Handled::Respond(error_response(
                        200,
                        &rpc.id,
                        INVALID_PARAMS,
                        &alloc::format!("{e}"),
                    ));
                }
            },
        };
        let authorized = match (&rpc.access.ais, token_authorized) {
            (Some(ais), _) => {
                match self.decided(
                    &intent,
                    ais,
                    None,
                    expected_nonce.as_deref(),
                    (env.clock, env.decisions),
                ) {
                    Ok((a, _)) => a,
                    Err(Refused::Refused(Refusal::RequireAction)) => {
                        let Some(s) = statement(ais) else {
                            return Handled::Respond(self.refusal(&rpc.id, Refused::Malformed));
                        };
                        let Ok(exercise) =
                            access_kernel::meta::exercise_id(&self.pep.domain, &s.nonce)
                        else {
                            return Handled::Respond(self.refusal(&rpc.id, Refused::Exercise));
                        };
                        return Handled::Respond(
                            match self.state.seal(&binding, Some(&s.nonce), now) {
                                Ok(state) => self.input_required(&rpc.id, &state, &exercise),
                                Err(_) => {
                                    self.refusal(&rpc.id, Refused::Refused(Refusal::RequireAction))
                                }
                            },
                        );
                    }
                    Err(d) => return Handled::Respond(self.refusal(&rpc.id, d)),
                }
            }
            (None, Some(a)) => {
                if expected_nonce.is_some() {
                    return Handled::Respond(error_response(
                        200,
                        &rpc.id,
                        INVALID_PARAMS,
                        "request-state",
                    ));
                }
                a
            }
            (None, None) => return Handled::Respond(self.refusal(&rpc.id, Refused::NoReceipt)),
        };
        Handled::Call(Call {
            id: rpc.id.clone(),
            tool: tool.clone(),
            arguments: rpc.params.get("arguments").cloned().unwrap_or(Json::Null),
            digest: *intent.digest(),
            authorized,
        })
    }

    fn open_stream<K, P, N, S, I, V, D, G>(
        &self,
        rpc: &Rpc,
        presented: &Presented<'_>,
        env: &Env<'_, K, P, N, S, I, V, D, G>,
    ) -> Handled
    where
        K: KeySource,
        P: ReplayStore,
        N: NonceSource,
        S: StatusSource,
        I: Introspector,
        V: Revocations,
        D: AskDecision,
        G: Random,
    {
        let Some(now) = env.clock.now() else {
            return Handled::Respond(error_response(503, &rpc.id, ACCESS_UNAVAILABLE, "clock"));
        };
        let Some(tool) = self.subscriptions else {
            return Handled::Respond(error_response(
                200,
                &rpc.id,
                METHOD_NOT_FOUND,
                "method-not-found",
            ));
        };
        let Some(intent) = Self::call_intent(tool, rpc, now) else {
            return Handled::Respond(error_response(200, &rpc.id, INVALID_PARAMS, "arguments"));
        };
        // AG-15
        let (authority, authorized) = match &rpc.access.ais {
            Some(ais) => {
                let authority = match self.authenticated(presented, env) {
                    Ok(a) => a,
                    Err(r) => return Handled::Respond(r),
                };
                match self.decided(&intent, ais, None, None, (env.clock, env.decisions)) {
                    Ok((a, _)) => (authority, a),
                    Err(d) => return Handled::Respond(self.refusal(&rpc.id, d)),
                }
            }
            None => match self.rs.verify(presented, &intent, &env.clock, env.ports) {
                Ok(v) => (v.authority, v.authorized),
                Err(d) => {
                    return Handled::Respond(self.challenged(&Challenge::of(&d, &tool.scopes)));
                }
            },
        };
        // AG-15
        let validity_end = intent
            .envelope()
            .map_or(authority.contract.horizon, |e| e.validity.until);
        let horizon = authority.contract.horizon.min(validity_end);
        match Listen::open(*authorized.exercise(), now, authority.expires_at, horizon) {
            Ok(listen) => Handled::Listen(Stream {
                id: rpc.id.clone(),
                listen,
                intent,
                continue_ais: rpc.access.continue_ais.clone(),
            }),
            Err(_) => Handled::Respond(self.challenged(&Challenge::InvalidToken)),
        }
    }

    /// The checkpoint of `stream` (A-8, AG-15 step 3): a `continue` of its Exercise with the
    /// actor's pre-signed statement, used once. No statement, a refusal or no answer closes
    /// the stream; an ALLOW keeps it open until the same close time.
    pub fn checkpoint<D: AskDecision>(
        &self,
        stream: &mut Stream,
        clock: &dyn Clock,
        decisions: &D,
    ) -> bool {
        let exercise = *stream.listen.exercise();
        let allowed = stream.continue_ais.take().is_some_and(|ais| {
            self.decided(
                &stream.intent,
                &ais,
                Some(&exercise),
                None,
                (clock, decisions),
            )
            .is_ok()
        });
        stream.listen.continued(allowed);
        allowed
    }
}

/// One SSE `data:` frame of a JSON-RPC notification, for a stream event that
/// [`Listen::deliver`] released.
#[must_use]
pub fn sse_event(notification: &Json) -> String {
    let mut out = String::from("data: ");
    out.push_str(&render(notification));
    out.push_str("\n\n");
    out
}
