//! The gateway's rules, sans-I/O (AG-42, OP-156 m.3 (n)): a tool's pin, the MCP server's tool
//! list, and the tool table a call is decided against.
//!
//! - A pin is the SHA-256 of the RFC 8785 form of the tool's `name`, `description`,
//!   `inputSchema` and `annotations`, as the server lists them. A listing that cannot be read
//!   has no pin and the tool stays blocked.
//! - A call of tool `t` exercises the proxy registration's action on `namespace:[proxy, t]`;
//!   the agent signs its statement over the same intent ([`tool_def`],
//!   [`access_sdk::mcp::tool::intent`]).

use std::collections::BTreeSet;

use access_kernel::json::Json;
use access_kernel::model::{ActionRef, ResourceRef};
use access_sdk::agent::a2a::jcs;
use access_sdk::mcp::tool::ToolDef;

/// The members of a tool definition a pin covers.
pub const PINNED_MEMBERS: [&str; 4] = ["name", "description", "inputSchema", "annotations"];

/// Most tools the gateway reads from one server.
pub const MAX_TOOLS: usize = 1024;

/// Longest MCP tool name.
pub const MAX_TOOL_NAME: usize = 128;

/// Whether `name` is an MCP tool name: 1 to 128 of `A-Z a-z 0-9 _ - .`.
#[must_use]
pub fn tool_name_ok(name: &str) -> bool {
    (1..=MAX_TOOL_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

/// The canonical definition of `listing`: the RFC 8785 form of its pinned members only.
#[must_use]
pub fn canonical(listing: &Json) -> Option<String> {
    let Json::Object(members) = listing else {
        return None;
    };
    let name = listing.get("name").and_then(Json::as_str)?;
    if !tool_name_ok(name) {
        return None;
    }
    let kept: Vec<(String, Json)> = members
        .iter()
        .filter(|(k, _)| PINNED_MEMBERS.contains(&k.as_str()))
        .cloned()
        .collect();
    let mut out = String::new();
    jcs(&mut out, &Json::Object(kept));
    Some(out)
}

/// The pin of `listing` (OP-156 m.3 (n)).
#[must_use]
pub fn pin(listing: &Json) -> Option<[u8; 32]> {
    canonical(listing).map(|c| suiss_crypto::digest::sha256(c.as_bytes()))
}

/// One tool as the server lists it now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    /// The name.
    pub name: String,
    /// The listing object, as the server sent it.
    pub listing: Json,
    /// Its pin.
    pub pin: [u8; 32],
}

/// The tools of one `tools/list` result page: each readable tool with its pin, and the next
/// cursor. A tool without a name or pin is left out, so it can never be called.
#[must_use]
pub fn listed(result: &Json) -> Option<(Vec<Listed>, Option<String>)> {
    let Some(Json::Array(tools)) = result.get("tools") else {
        return None;
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for t in tools {
        let (Some(name), Some(pin)) = (t.get("name").and_then(Json::as_str), pin(t)) else {
            continue;
        };
        if !seen.insert(String::from(name)) {
            out.retain(|l: &Listed| l.name != name);
            continue;
        }
        out.push(Listed {
            name: String::from(name),
            listing: t.clone(),
            pin,
        });
    }
    let next = match result.get("nextCursor") {
        None | Some(Json::Null) => None,
        Some(Json::Str(s)) => Some(s.clone()),
        Some(_) => return None,
    };
    Some((out, next))
}

/// What the gateway decides in: the proxy registration it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The proxy's registered name.
    pub proxy: String,
    /// The resource namespace of the registration.
    pub namespace: String,
    /// The action of the registration: every tool call exercises it.
    pub action: ActionRef,
}

/// The resource a call of `tool` acts on: `namespace:[proxy, tool]`.
#[must_use]
pub fn tool_resource(p: &Profile, tool: &str) -> ResourceRef {
    ResourceRef {
        namespace: p.namespace.clone(),
        path: vec![p.proxy.clone(), String::from(tool)],
        incarnation: 0,
    }
}

/// The SDK tool `name` under `p`: what the agent signs over and the gateway asks about.
#[must_use]
pub fn tool_def(p: &Profile, name: &str, listing: Json) -> ToolDef {
    ToolDef {
        name: String::from(name),
        action: p.action.clone(),
        resource: tool_resource(p, name),
        scopes: Vec::new(),
        public: None,
        secret: BTreeSet::new(),
        listing,
    }
}

#[cfg(test)]
mod tests;
