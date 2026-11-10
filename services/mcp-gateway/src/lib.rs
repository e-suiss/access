//! The MCP gateway (OP-156 m.3 (n), AG-42, B22): Access Proxy's MCP mode. Every `tools/call` is
//! decided by Access through the SDK and forwarded only on ALLOW; each server's tool list is
//! pinned by the SHA-256 of every tool's canonical definition. It uses public crates only
//! (OP-62) and holds no authority.
