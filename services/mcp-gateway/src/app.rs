//! One MCP request from the agent to its answer (AG-42, B22, IDP-30, OP-156 m.3 (n)):
//!
//! 1. Header hygiene, `Origin` and `Host`, then the JSON-RPC body (§11.5.6).
//! 2. `tools/list`: the server's tools, each with its pin, checked with Access; only the ones
//!    that stand pinned are shown.
//! 3. `tools/call`: the agent's own `commit` statement for the tool's intent, sent to Access with
//!    the tool and its pin as read from the server now. Only a verified ALLOW for this intent,
//!    this PEP and this Exercise reaches the server (§9.5); anything else, the server never
//!    sees. The statement is never forwarded and no token passes through (L24).
//! 4. Anything else but `initialize`, `ping` and notifications is not served.
//!
//! The gateway is a PEP, never an actor: it has no key that signs a statement (E17).

use std::sync::Mutex;

use access_kernel::ais::Statement;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::json::{self, Json, b64url_encode};
use access_kernel::verify::cose::parse_sign1;
use access_kernel::verify::key_scope::DomainMetadata;
use access_sdk::authorize::{
    Actor, Ask, AskDecision, Denied, ExerciseRequest, Intent, Nonce, Pep, Refusal, adp_body,
};
use access_sdk::mcp::render_json;
use access_sdk::mcp::wire::{self, Headers, Origins, Rpc};
use access_sdk::mcp::{META_PROTOCOL, PROTOCOL_VERSION};
use access_sdk::transport::{Answer, Fault};

use crate::domain::{Listed, Profile, listed, tool_def, tool_name_ok};
use crate::ports::{Access, Clock, Upstream};

/// Largest answer read from Access or the server.
pub const MAX_ANSWER: usize = 4 * 1024 * 1024;

/// Most `tools/list` pages read from the server for one request.
pub const MAX_PAGES: usize = 16;

/// JSON-RPC code of a call Access did not allow.
pub const ACCESS_DENIED: i64 = -32001;

/// JSON-RPC code of a call no decision or server answer could be obtained for.
pub const ACCESS_UNAVAILABLE: i64 = -32002;

/// JSON-RPC code of an unknown method.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// JSON-RPC code of bad parameters.
pub const INVALID_PARAMS: i64 = -32602;

/// The gateway's configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// The MCP server's host as agents reach it, the host the proxy is registered for.
    pub host: String,
    /// Allowed `Origin` values; empty refuses any request that sends one.
    pub origins: Vec<String>,
    /// The PEP name Access derives from this gateway's client certificate.
    pub pep: String,
    /// The domain the realm governs, the only one decided in.
    pub domain: Digest,
    /// The proxy registration this gateway is.
    pub profile: Profile,
}

/// One HTTP answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The status.
    pub status: u16,
    /// The JSON body; empty for `202`.
    pub body: String,
}

struct Prefetched(Answer);

impl AskDecision for Prefetched {
    fn ask(&self, _: &ExerciseRequest<'_>) -> Answer {
        self.0.clone()
    }
}

struct At(u64);

impl access_sdk::transport::Clock for At {
    fn now(&self) -> Option<u64> {
        Some(self.0)
    }
}

fn text(s: &str) -> String {
    render_json(&Json::Str(String::from(s)))
}

fn error(status: u16, id: &Json, code: i64, message: &str) -> Reply {
    Reply {
        status,
        body: format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{code},\"message\":{}}}}}",
            render_json(id),
            text(message)
        ),
    }
}

fn result(id: &Json, result: &str) -> Reply {
    Reply {
        status: 200,
        body: format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{result}}}",
            render_json(id)
        ),
    }
}

fn meta() -> Json {
    Json::Object(vec![(
        String::from(META_PROTOCOL),
        Json::Str(String::from(PROTOCOL_VERSION)),
    )])
}

fn request(id: &Json, method: &str, mut params: Vec<(String, Json)>) -> Vec<u8> {
    params.retain(|(k, _)| k != "_meta");
    params.push((String::from("_meta"), meta()));
    render_json(&Json::Object(vec![
        (String::from("jsonrpc"), Json::Str(String::from("2.0"))),
        (String::from("id"), id.clone()),
        (String::from("method"), Json::Str(String::from(method))),
        (String::from("params"), Json::Object(params)),
    ]))
    .into_bytes()
}

fn json_of(a: &Answer) -> Option<(u16, Json)> {
    match a {
        Answer::Response(r) => Some((r.status, json::parse(&r.body, MAX_ANSWER).ok()?)),
        Answer::Unanswered(_) => None,
    }
}

fn statement(ais: &[u8]) -> Option<Statement> {
    let payload = parse_sign1(ais).ok()?.payload?;
    Statement::from_bytes(&payload).ok()
}

/// Why the server's list could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NoList;

/// The gateway over its ports.
pub struct Gateway<A, U, C> {
    access: A,
    upstream: U,
    clock: C,
    config: Config,
    metadata: Mutex<Option<DomainMetadata>>,
}

impl<A: Access, U: Upstream, C: Clock> Gateway<A, U, C> {
    /// A gateway.
    pub fn new((access, upstream, clock): (A, U, C), config: Config) -> Self {
        Self {
            access,
            upstream,
            clock,
            config,
            metadata: Mutex::new(None),
        }
    }

    /// The configuration.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Answers one `POST` of the MCP endpoint.
    pub async fn handle(&self, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        let headers = Headers(headers);
        let origins = Origins {
            origins: self.config.origins.clone(),
            hosts: vec![self.config.host.clone()],
        };
        // §11.5.6
        if let Err(r) = wire::hygiene(&headers).and_then(|()| origins.check(&headers)) {
            return error(r.status(), &Json::Null, r.rpc_code(), &format!("{r}"));
        }
        let rpc = match wire::parse(body) {
            Ok(rpc) => rpc,
            Err(r) => return error(r.status(), &Json::Null, r.rpc_code(), &format!("{r}")),
        };
        if rpc.method.starts_with("notifications/") && rpc.id == Json::Null {
            return Reply {
                status: 202,
                body: String::new(),
            };
        }
        match rpc.method.as_str() {
            "initialize" | "server/discover" => result(
                &rpc.id,
                &format!(
                    "{{\"protocolVersion\":{},\"capabilities\":{{\"tools\":{{\"listChanged\":false}}}},\"serverInfo\":{{\"name\":\"access-mcp-gateway\",\"version\":{}}}}}",
                    text(PROTOCOL_VERSION),
                    text(env!("CARGO_PKG_VERSION"))
                ),
            ),
            "ping" => result(&rpc.id, "{}"),
            "tools/list" => self.list(&rpc).await,
            "tools/call" => self.call(&rpc).await,
            _ => error(200, &rpc.id, METHOD_NOT_FOUND, "method-not-found"),
        }
    }

    /// Every tool the server lists now, with its pin.
    async fn server_tools(&self) -> Result<Vec<Listed>, NoList> {
        let mut out: Vec<Listed> = Vec::new();
        let mut cursor: Option<String> = None;
        for page in 0..MAX_PAGES {
            let mut params = Vec::new();
            if let Some(c) = cursor.take() {
                params.push((String::from("cursor"), Json::Str(c)));
            }
            let id = Json::Str(format!("access-mcp-gateway-{page}"));
            let answer = self.upstream.send(request(&id, "tools/list", params)).await;
            let Some((200, v)) = json_of(&answer) else {
                return Err(NoList);
            };
            let (tools, next) = v.get("result").and_then(listed).ok_or(NoList)?;
            out.extend(tools);
            if out.len() > crate::domain::MAX_TOOLS {
                return Err(NoList);
            }
            match next {
                Some(n) => cursor = Some(n),
                None => return Ok(out),
            }
        }
        Err(NoList)
    }

    /// The names of `tools` that stand pinned, as Access answers (AG-42).
    async fn pinned(&self, tools: &[Listed]) -> Result<Vec<String>, Fault> {
        let body = render_json(&Json::Object(vec![
            (String::from("host"), Json::Str(self.config.host.clone())),
            (
                String::from("tools"),
                Json::Array(
                    tools
                        .iter()
                        .map(|t| {
                            Json::Object(vec![
                                (String::from("name"), Json::Str(t.name.clone())),
                                (String::from("pin"), Json::Str(b64url_encode(&t.pin))),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]));
        let answer = self.access.tools(body.into_bytes()).await;
        let Some((200, v)) = json_of(&answer) else {
            return Err(Fault::Transport);
        };
        match v.get("pinned") {
            Some(Json::Array(names)) => names
                .iter()
                .map(|n| n.as_str().map(String::from).ok_or(Fault::Transport))
                .collect(),
            _ => Err(Fault::Transport),
        }
    }

    async fn list(&self, rpc: &Rpc) -> Reply {
        let Ok(tools) = self.server_tools().await else {
            return error(502, &rpc.id, ACCESS_UNAVAILABLE, "upstream");
        };
        let Ok(pinned) = self.pinned(&tools).await else {
            return error(503, &rpc.id, ACCESS_UNAVAILABLE, "unavailable");
        };
        let shown: Vec<Json> = tools
            .into_iter()
            .filter(|t| pinned.contains(&t.name))
            .map(|t| t.listing)
            .collect();
        result(
            &rpc.id,
            &format!("{{\"tools\":{}}}", render_json(&Json::Array(shown))),
        )
    }

    async fn domain_metadata(&self) -> Option<DomainMetadata> {
        if let Some(m) = self.metadata.lock().ok().and_then(|m| m.clone()) {
            return Some(m);
        }
        let answer = self
            .access
            .metadata(b64url_encode(&self.config.domain.0))
            .await;
        let m = match answer {
            Answer::Response(r) if r.status == 200 => parse_sign1(&r.body)
                .ok()
                .and_then(|s| s.payload)
                .and_then(|p| DomainMetadata::from_bytes(&p).ok())?,
            _ => return None,
        };
        if let Ok(mut cache) = self.metadata.lock() {
            *cache = Some(m.clone());
        }
        Some(m)
    }

    #[allow(clippy::too_many_lines, reason = "one tool call, in order")]
    async fn call(&self, rpc: &Rpc) -> Reply {
        let id = &rpc.id;
        let Some(name) = rpc.params.get("name").and_then(Json::as_str) else {
            return error(200, id, INVALID_PARAMS, "unknown-tool");
        };
        if !tool_name_ok(name) {
            return error(200, id, INVALID_PARAMS, "unknown-tool");
        }
        // E17, §9.5 k.2
        let (Some(ais), Some(validity)) = (&rpc.access.ais, rpc.access.validity) else {
            return error(403, id, ACCESS_DENIED, "statement");
        };
        let Some(s) = statement(ais) else {
            return error(403, id, ACCESS_DENIED, "statement");
        };
        if s.mode != Mode::Commit || s.domain != self.config.domain || s.pep != self.config.pep {
            return error(403, id, ACCESS_DENIED, "statement");
        }
        let Some(now) = self.clock.now() else {
            return error(503, id, ACCESS_UNAVAILABLE, "clock");
        };
        let Ok(tools) = self.server_tools().await else {
            return error(502, id, ACCESS_UNAVAILABLE, "upstream");
        };
        let Some(tool) = tools.into_iter().find(|t| t.name == name) else {
            return error(200, id, INVALID_PARAMS, "unknown-tool");
        };
        let def = tool_def(&self.config.profile, name, tool.listing.clone());
        let Ok(envelope) =
            access_sdk::mcp::tool::intent(&def, rpc.params.get("arguments"), validity)
        else {
            return error(200, id, INVALID_PARAMS, "arguments");
        };
        let Ok(intent) = Intent::<(), ()>::named(envelope.clone()) else {
            return error(200, id, INVALID_PARAMS, "arguments");
        };
        if s.intent != *intent.digest() {
            return error(403, id, ACCESS_DENIED, "statement");
        }
        let Ok(nonce) = Nonce::new(s.nonce.clone()) else {
            return error(403, id, ACCESS_DENIED, "statement");
        };
        let actor = Actor::Statement(ais.clone());
        let request = ExerciseRequest {
            domain: &s.domain,
            mode: Mode::Commit,
            nonce: &s.nonce,
            intent: intent.digest(),
            envelope: Some(&envelope),
            actor: &actor,
            basis: &s.basis,
            capacity: s.capacity,
            pep: &self.config.pep,
            exercise: None,
        };
        let Some(evaluation) = adp_body(&request) else {
            return error(200, id, INVALID_PARAMS, "arguments");
        };
        let Some(metadata) = self.domain_metadata().await else {
            return error(503, id, ACCESS_UNAVAILABLE, "metadata");
        };
        let body = render_json(&Json::Object(vec![
            (String::from("host"), Json::Str(self.config.host.clone())),
            (String::from("tool"), Json::Str(String::from(name))),
            (String::from("pin"), Json::Str(b64url_encode(&tool.pin))),
            (String::from("evaluation"), Json::Str(evaluation)),
        ]));
        let answer = self.access.calls(body.into_bytes()).await;
        // AG-42
        if let Some((409, v)) = json_of(&answer)
            && v.get("code").and_then(Json::as_str) == Some("mcp-tool-unpinned")
        {
            return error(403, id, ACCESS_DENIED, "tool-unpinned");
        }
        let pep = Pep {
            audience: self.config.pep.clone(),
            domain: s.domain,
            metadata,
        };
        let ask = Ask {
            intent: &intent,
            nonce: &nonce,
            actor: &actor,
            basis: &s.basis,
            capacity: s.capacity,
            continued: None,
            content_position: None,
        };
        // §9.5, L1-ADP-3
        let authorized = match pep.authorize(&ask, &At(now), &Prefetched(answer)) {
            Ok(a) => a,
            Err(Denied::Refused(Refusal::RequireAction)) => {
                return error(403, id, ACCESS_DENIED, "require-action");
            }
            Err(Denied::Refused(_)) => return error(403, id, ACCESS_DENIED, "denied"),
            Err(
                e
                @ (Denied::Clock | Denied::Unavailable(_) | Denied::Status(_) | Denied::Malformed),
            ) => return error(503, id, ACCESS_UNAVAILABLE, e.code()),
            Err(e) => return error(403, id, ACCESS_DENIED, e.code()),
        };
        if authorized.apply(intent.digest(), |_| ()).is_err() {
            return error(403, id, ACCESS_DENIED, "intent-body");
        }
        let params = match &rpc.params {
            Json::Object(m) => m.clone(),
            _ => Vec::new(),
        };
        let answer = self.upstream.send(request_of(id, params)).await;
        match answer {
            Answer::Response(r) if r.status == 200 => match String::from_utf8(r.body) {
                Ok(body) if json::parse(body.as_bytes(), MAX_ANSWER).is_ok() => {
                    Reply { status: 200, body }
                }
                _ => error(502, id, ACCESS_UNAVAILABLE, "upstream"),
            },
            _ => error(502, id, ACCESS_UNAVAILABLE, "upstream"),
        }
    }
}

fn request_of(id: &Json, params: Vec<(String, Json)>) -> Vec<u8> {
    request(id, "tools/call", params)
}

#[cfg(test)]
mod tests;
