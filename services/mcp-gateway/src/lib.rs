//! The MCP gateway (OP-156 m.3 (n), AG-42, B22, IDP-30): Access Proxy's MCP mode, an
//! MCP-aware enforcement point in front of an MCP server that is not integrated with Access.
//!
//! - Every `tools/call` is decided by Access through the SDK on the agent's own signed
//!   statement, and forwarded only on a verified ALLOW ([`app`]).
//! - Each tool is pinned by the SHA-256 of its canonical definition; a changed or new tool is
//!   neither shown nor called until an administrator pins it with `idp.proxy.mcp_pin`
//!   ([`domain`]).
//! - Access records every decided call as `mcp_gateway.call`, without its arguments.
//!
//! It uses public crates only (OP-62) and holds no authority: it is a PEP, never an actor.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod https;
pub mod ports;
