# access-mcp-gateway

The MCP gateway sits between an agent and its MCP servers. Before every tool call it asks Access for a decision and forwards the call only when Access allows it. Each server's tool list is pinned; a tool that changes or appears is blocked until an administrator pins it again. Every call is recorded without its arguments.

It uses public crates only and holds no authority.

## License

Apache-2.0.
