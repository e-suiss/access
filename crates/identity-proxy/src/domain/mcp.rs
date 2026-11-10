//! A proxy in MCP mode (OP-156 m.3 (n), AG-42, B22): the tool list an administrator pinned,
//! the `idp.proxy.mcp_pin` change that pins it, and what a call of one tool exercises.
//! Sans-I/O.
//!
//! A pin is the SHA-256 of a tool's canonical definition: the RFC 8785 form of its `name`,
//! `description`, `inputSchema` and `annotations`, computed by the gateway from what the MCP
//! server lists. Pinning is strict: a tool whose definition changed, and a tool never pinned,
//! is blocked until an administrator pins the list again.

use access_internal_api::idp::IdpAction;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::{ActionRef, ResourceRef};
use serde_json::{Map, Value as Json, json};
use suiss_crypto::dcbor::Value;

use super::registration::{Registration, name_ok};

/// Most tools one list pins.
pub const MAX_TOOLS: usize = 256;

/// Longest MCP tool name.
pub const MAX_TOOL_NAME: usize = 128;

/// Why a body is not an `idp.proxy.mcp_pin` change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("mcp pin body")]
pub struct PinError;

/// One pinned tool.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PinnedTool {
    /// The MCP tool name.
    pub name: String,
    /// The SHA-256 of its canonical definition.
    pub pin: [u8; 32],
}

/// `idp.proxy.mcp_pin` (CT2): the whole tool list of proxy `proxy`, replacing the one before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpPinChange {
    /// The proxy.
    pub proxy: String,
    /// The tools, by name.
    pub tools: Vec<PinnedTool>,
}

/// Whether `name` is an MCP tool name: 1 to 128 of `A-Z a-z 0-9 _ - .`.
#[must_use]
pub fn tool_name_ok(name: &str) -> bool {
    (1..=MAX_TOOL_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

fn pin_of(s: &str) -> Result<[u8; 32], PinError> {
    let b = b64url_decode(s).map_err(|_| PinError)?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| PinError)
}

fn tools_of(v: &Json) -> Result<Vec<PinnedTool>, PinError> {
    let Json::Array(items) = v else {
        return Err(PinError);
    };
    if items.len() > MAX_TOOLS {
        return Err(PinError);
    }
    let mut tools = items
        .iter()
        .map(|i| {
            let m = i.as_object().ok_or(PinError)?;
            if m.len() != 2 {
                return Err(PinError);
            }
            let name = m.get("name").and_then(Json::as_str).ok_or(PinError)?;
            let pin = m.get("pin").and_then(Json::as_str).ok_or(PinError)?;
            if !tool_name_ok(name) || pin.len() != 43 {
                return Err(PinError);
            }
            Ok(PinnedTool {
                name: String::from(name),
                pin: pin_of(pin)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    tools.sort();
    if tools
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.name == b.name))
    {
        return Err(PinError);
    }
    Ok(tools)
}

impl McpPinChange {
    /// `pinMcpTools` of proxy `proxy`: `{"tools": [{"name": …, "pin": base64url}]}`, at most
    /// [`MAX_TOOLS`], each name once; an empty list blocks every tool.
    ///
    /// # Errors
    /// [`PinError`].
    pub fn parse(proxy: &str, body: &Json) -> Result<Self, PinError> {
        let m = body.as_object().ok_or(PinError)?;
        if !name_ok(proxy) || m.keys().any(|k| k != "tools") {
            return Err(PinError);
        }
        Ok(Self {
            proxy: String::from(proxy),
            tools: tools_of(m.get("tools").ok_or(PinError)?)?,
        })
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        IdpAction::ProxyMcpPin
    }

    /// Whether it is inside the rules.
    ///
    /// # Errors
    /// [`PinError`].
    pub fn check(&self) -> Result<(), PinError> {
        let sorted = self.tools.windows(2).all(|w| match w {
            [a, b] => a.name < b.name,
            _ => true,
        });
        let ok = name_ok(&self.proxy)
            && self.tools.len() <= MAX_TOOLS
            && sorted
            && self.tools.iter().all(|t| tool_name_ok(&t.name));
        ok.then_some(()).ok_or(PinError)
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        let m = |e: Vec<(&str, Value)>| {
            Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
        };
        m(vec![
            ("mcp_pin", Value::text(&self.proxy)),
            (
                "tools",
                Value::Array(
                    self.tools
                        .iter()
                        .map(|t| {
                            m(vec![
                                ("name", Value::text(&t.name)),
                                ("pin", Value::Bytes(t.pin.to_vec())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    /// Its resource path below the realm's slug.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        vec![
            String::from("proxy"),
            self.proxy.clone(),
            String::from("mcp-pins"),
        ]
    }
}

/// The tools as stored and read back.
#[must_use]
pub fn to_json(tools: &[PinnedTool]) -> Json {
    Json::Array(
        tools
            .iter()
            .map(|t| json!({ "name": t.name, "pin": b64url_encode(&t.pin) }))
            .collect(),
    )
}

/// The tools a stored body names.
///
/// # Errors
/// [`PinError`].
pub fn from_json(v: &Json) -> Result<Vec<PinnedTool>, PinError> {
    tools_of(v)
}

/// Where a tool stands against the pinned list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Pinned with this definition.
    Pinned,
    /// Pinned with another definition: its description, schema or annotations changed.
    Changed,
    /// Never pinned.
    New,
}

impl Standing {
    /// The word for it.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Changed => "changed",
            Self::New => "new",
        }
    }
}

/// Where tool `name` with definition digest `pin` stands against `pinned`.
#[must_use]
pub fn standing(pinned: &[PinnedTool], name: &str, pin: &[u8; 32]) -> Standing {
    match pinned.iter().find(|t| t.name == name) {
        Some(t) if t.pin == *pin => Standing::Pinned,
        Some(_) => Standing::Changed,
        None => Standing::New,
    }
}

/// The action a call of any tool of `r` exercises: the registration's.
#[must_use]
pub fn call_action(r: &Registration) -> &ActionRef {
    &r.action
}

/// The resource a call of tool `tool` through `r` acts on: `namespace:[proxy, tool]`.
#[must_use]
pub fn tool_resource(r: &Registration, tool: &str) -> ResourceRef {
    ResourceRef {
        namespace: r.namespace.clone(),
        path: vec![r.name.clone(), String::from(tool)],
        incarnation: 0,
    }
}

/// The pinned list as administrators read it on the proxy.
#[must_use]
pub fn listed(tools: &[PinnedTool], version: u64) -> Json {
    let mut m = Map::new();
    m.insert(String::from("version"), json!(version));
    m.insert(String::from("tools"), to_json(tools));
    Json::Object(m)
}

#[cfg(test)]
mod tests;
