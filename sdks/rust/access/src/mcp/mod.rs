//! An MCP server as an OAuth resource server and the domain's PEP (§11.2, §11.5, AG-1, AG-2,
//! AG-9 to AG-16, OP-154 m.3 (v)). The MCP client is an agent Instance, a tool is an
//! `ActionRef`, a `tools/call` is one decision for one exact intent, a list is a viewer-scoped
//! disclosure, the access token is an Access projection, an elicitation is never an approval
//! and a handle or `requestState` is a name, never a capability.
//!
//! The module is sans I/O like the rest of the SDK: [`server::McpServer::handle`] takes one
//! HTTP request as received and answers with what to send, or with a value the host acts on:
//! an [`server::Handled::Call`] holding the `Authorized` proof of one tool call, or a
//! [`listen::Listen`] governing one `subscriptions/listen` stream. Tokens are verified with
//! [`crate::resource::ResourceServer`]; decisions are asked with [`crate::authorize::Pep`].
//!
//! Every check fails closed. There is no gateway mode: a server that is not integrated puts
//! the Access Proxy in front of it (AG-42), this module is for the server itself.

pub mod cache;
pub mod challenge;
pub mod client;
pub(crate) mod json;
pub mod listen;
pub mod prm;
pub mod server;
pub mod state;
pub mod tool;
pub mod wire;

/// The MCP protocol revision this profile implements (§11.1, stateless core).
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// `_meta` member carrying the actor Instance's Actor Intent Statement for a `tools/call`,
/// base64url `COSE_Sign1` exactly as signed (§11.2: the server forwards the agent's AIS).
pub const META_AIS: &str = "io.suiss.access/ais";

/// `_meta` member carrying the intent validity window `{"from": ms, "until": ms}` the
/// statement was signed over.
pub const META_VALIDITY: &str = "io.suiss.access/validity";

/// `_meta` member carrying the actor's pre-signed `continue` statement for the checkpoint of a
/// `subscriptions/listen` stream (A-8, AG-15).
pub const META_CONTINUE: &str = "io.suiss.access/continue";

/// `_meta` member naming the protocol revision (SEP-2575).
pub const META_PROTOCOL: &str = "io.modelcontextprotocol/protocolVersion";
