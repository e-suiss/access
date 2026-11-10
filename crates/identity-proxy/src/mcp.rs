//! A proxy in MCP mode on Access's side (OP-156 m.3 (n), AG-42, B22, IDP-30): the MCP gateway
//! is a registered proxy that asks about each tool before it shows or calls it.
//!
//! 1. The gateway is a PEP its transport names, registered for the MCP server's host; anything
//!    else is `401`.
//! 2. A list check answers which of the tools the server lists now stand pinned
//!    ([`Gateway::tools`]); the others are not shown.
//! 3. A call is one ADP `commit` of the agent's own statement, its actor the agent's Instance and
//!    the gateway only its PEP ([`Gateway::call`]). A tool that is not pinned with this
//!    definition is blocked before any decision and audited as `mcp_gateway.tool_blocked`.
//! 4. Every decided call writes one `mcp_gateway.call` audit row: the decision, the tool and its
//!    pin, never the arguments.
//!
//! A dependency that does not answer refuses (MD-8, TI-9).

use std::future::Future;

use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::b64url_encode;
use access_kernel::model::Id;

use crate::domain::mcp::{PinnedTool, Standing, standing, tool_name_ok, tool_resource};
use crate::domain::registration::Registration;
use crate::ports::Unavailable;

/// Most tools one list check reads.
pub const MAX_LISTED: usize = 1024;

/// One identity audit row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Audit<'a> {
    /// The event.
    pub event: &'static str,
    /// Who acted.
    pub actor: &'a str,
    /// What on.
    pub target: &'a str,
    /// The decision, pin and outcome.
    pub correlation: &'a str,
}

/// The decision point's answer, as it came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluated {
    /// The status.
    pub status: u16,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// `Access-Key-Excerpt`.
    pub key_excerpt: Option<String>,
    /// The body.
    pub body: Vec<u8>,
}

/// What MCP mode needs from the rest of the server (OP-63).
pub trait McpPorts: Send + Sync {
    /// A realm as the ports name it.
    type Realm: Send + Sync;

    /// The live registration of the proxy `pep` names for `host`.
    fn registered(
        &self,
        pep: &str,
        host: &str,
    ) -> impl Future<Output = Result<Option<(Self::Realm, Registration)>, Unavailable>> + Send;

    /// The realm's governing domain, while the realm is active.
    fn governing(
        &self,
        realm: &Self::Realm,
    ) -> impl Future<Output = Result<Option<Digest>, Unavailable>> + Send;

    /// The newest pinned list of `proxy`; empty when none was pinned.
    fn pins(
        &self,
        realm: &Self::Realm,
        proxy: &str,
    ) -> impl Future<Output = Result<Vec<PinnedTool>, Unavailable>> + Send;

    /// One ADP evaluation of `body` asked by the PEP `pep`.
    fn evaluate(
        &self,
        pep: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<Evaluated, Unavailable>> + Send;

    /// The Instance that acted in the allowed Exercise `exercise` of `domain`.
    fn instance(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> impl Future<Output = Result<Option<Id>, Unavailable>> + Send;

    /// Writes one audit row in `realm`.
    fn audit(
        &self,
        realm: &Self::Realm,
        row: &Audit<'_>,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
}

/// Why MCP mode did not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum McpRefusal {
    /// No transport identity, or no live registration for the host: `401`.
    #[error("proxy-unregistered")]
    Unregistered,
    /// The request is not one call of one tool of this proxy: `400`.
    #[error("invalid-mcp-call: {0}")]
    Malformed(&'static str),
    /// The tool is not pinned with this definition: `409`.
    #[error("mcp-tool-unpinned: {}", .0.word())]
    Blocked(Standing),
    /// A dependency did not answer: `503`.
    #[error("unavailable")]
    Unavailable,
}

impl From<Unavailable> for McpRefusal {
    fn from(_: Unavailable) -> Self {
        Self::Unavailable
    }
}

/// One tool as the MCP server lists it now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    /// The name.
    pub name: String,
    /// The SHA-256 of its canonical definition.
    pub pin: [u8; 32],
}

/// One call as the gateway asks about it, the evaluation already read.
#[derive(Clone, Copy, Debug)]
pub struct ToolCall<'a> {
    /// The gateway's transport identity.
    pub pep: Option<&'a str>,
    /// The MCP server's host the gateway is registered for.
    pub host: &'a str,
    /// The tool.
    pub tool: &'a str,
    /// The SHA-256 of the tool's canonical definition the gateway sees now.
    pub pin: &'a [u8; 32],
    /// The evaluation's domain.
    pub domain: Digest,
    /// The evaluation's mode.
    pub mode: Mode,
    /// The evaluation's nonce.
    pub nonce: &'a [u8],
    /// The evaluation's intent.
    pub intent: &'a IntentEnvelope,
    /// Whether the evaluation carries the actor's statement.
    pub statement: bool,
    /// The evaluation as sent.
    pub evaluation: &'a [u8],
}

/// MCP mode over `P`.
pub struct Gateway<P> {
    ports: P,
}

fn outcome(e: &Evaluated) -> (&'static str, bool) {
    if e.status != 200 {
        return ("error", false);
    }
    let v: serde_json::Value = serde_json::from_slice(&e.body).unwrap_or_default();
    match v.get("decision").and_then(serde_json::Value::as_bool) {
        Some(true) => ("allow", true),
        Some(false) => match v
            .get("context")
            .and_then(|c| c.get("outcome"))
            .and_then(serde_json::Value::as_str)
        {
            Some("require_action") => ("require_action", false),
            _ => ("deny", false),
        },
        None => ("error", false),
    }
}

impl<P: McpPorts> Gateway<P> {
    /// MCP mode over `ports`.
    pub const fn new(ports: P) -> Self {
        Self { ports }
    }

    /// The ports.
    pub const fn ports(&self) -> &P {
        &self.ports
    }

    async fn registered(
        &self,
        pep: Option<&str>,
        host: &str,
    ) -> Result<(P::Realm, Registration), McpRefusal> {
        let pep = pep.ok_or(McpRefusal::Unregistered)?;
        self.ports
            .registered(pep, &host.to_ascii_lowercase())
            .await?
            .ok_or(McpRefusal::Unregistered)
    }

    /// Which of `observed` stand pinned, by name (AG-42); a change is logged for the
    /// administrator as `mcp_gateway.tool.changed`.
    ///
    /// # Errors
    /// [`McpRefusal`].
    pub async fn tools(
        &self,
        pep: Option<&str>,
        host: &str,
        observed: &[Observed],
    ) -> Result<Vec<String>, McpRefusal> {
        let (realm, r) = self.registered(pep, host).await?;
        if observed.len() > MAX_LISTED || observed.iter().any(|o| !tool_name_ok(&o.name)) {
            return Err(McpRefusal::Malformed("tools"));
        }
        let pinned = self.ports.pins(&realm, &r.name).await?;
        let mut out = Vec::new();
        let mut unpinned = 0_usize;
        for o in observed {
            if standing(&pinned, &o.name, &o.pin) == Standing::Pinned {
                out.push(o.name.clone());
            } else {
                unpinned = unpinned.saturating_add(1);
            }
        }
        if unpinned > 0 {
            // OP-67
            tracing::warn!(
                event = "mcp_gateway.tool.changed",
                server = %r.name,
                tools = unpinned,
                "MCP tools changed or new; blocked until pinned"
            );
        }
        Ok(out)
    }

    /// The decision on one tool call (AG-42, OP-156 m.3 (n)): refused before any decision when
    /// it is not a `commit` of the actor's own statement on this tool, or the tool does not
    /// stand pinned; otherwise the ADP's answer as it came back, audited once.
    ///
    /// # Errors
    /// [`McpRefusal`].
    pub async fn call(&self, c: &ToolCall<'_>) -> Result<Evaluated, McpRefusal> {
        let (realm, r) = self.registered(c.pep, c.host).await?;
        let pep = c.pep.ok_or(McpRefusal::Unregistered)?;
        if !tool_name_ok(c.tool) {
            return Err(McpRefusal::Malformed("tool"));
        }
        // E17, §9.5 k.2
        if c.mode != Mode::Commit || !c.statement {
            return Err(McpRefusal::Malformed("statement"));
        }
        if c.intent.action != r.action || c.intent.resources != [tool_resource(&r, c.tool)] {
            return Err(McpRefusal::Malformed("intent"));
        }
        if self.ports.governing(&realm).await? != Some(c.domain) {
            return Err(McpRefusal::Malformed("domain"));
        }
        let target = format!("{}:{}", r.name, c.tool);
        let pinned = self.ports.pins(&realm, &r.name).await?;
        let s = standing(&pinned, c.tool, c.pin);
        // AG-42
        if s != Standing::Pinned {
            let actor = format!("pep:{pep}");
            let correlation = format!("{}:{}", s.word(), b64url_encode(c.pin));
            self.ports
                .audit(
                    &realm,
                    &Audit {
                        event: "mcp_gateway.tool_blocked",
                        actor: &actor,
                        target: &target,
                        correlation: &correlation,
                    },
                )
                .await?;
            // OP-67
            tracing::warn!(
                event = "mcp_gateway.tool.changed",
                server = %r.name,
                tools = 1_usize,
                "MCP tool call blocked until pinned"
            );
            return Err(McpRefusal::Blocked(s));
        }
        let exercise = access_kernel::meta::exercise_id(&c.domain, c.nonce)
            .map_err(|_| McpRefusal::Malformed("nonce"))?;
        let evaluated = self.ports.evaluate(pep, c.evaluation.to_vec()).await?;
        let (word, allowed) = outcome(&evaluated);
        // AG-42, E17
        let actor = if allowed {
            match self.ports.instance(c.domain, exercise).await? {
                Some(i) => format!("instance:{}", b64url_encode(&i.0)),
                None => return Err(McpRefusal::Unavailable),
            }
        } else {
            String::from("-")
        };
        let correlation = format!(
            "{}:{}:{word}",
            b64url_encode(&exercise.0),
            b64url_encode(c.pin)
        );
        self.ports
            .audit(
                &realm,
                &Audit {
                    event: "mcp_gateway.call",
                    actor: &actor,
                    target: &target,
                    correlation: &correlation,
                },
            )
            .await?;
        Ok(evaluated)
    }
}

#[cfg(test)]
mod tests;
