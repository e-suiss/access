# access-mcp-gateway

The MCP gateway puts Access in front of an MCP server that knows nothing about Access. Agents talk
to the gateway as if it were the server. The gateway asks Access before every tool call, forwards
the call only when Access allows it, and shows only the tools an administrator pinned.

It is the Access Proxy's MCP mode: it runs behind the proxy's engine, is registered as a proxy
with `idp.proxy.register`, uses only the public crates (`esuiss-access-kernel`,
`esuiss-access-sdk`, `esuiss-crypto`) and holds no authority. It is an enforcement point, never an
actor.

## Tool pinning

Each tool is pinned by the SHA-256 of its canonical definition: the RFC 8785 form of its `name`,
`description`, `inputSchema` and `annotations`. An administrator pins a proxy's tool list with
`idp.proxy.mcp_pin` (`POST /admin/v1/realms/{slug}/proxies/{proxy}/mcp-pins`).

Pinning is strict. When a server changes a tool's description, schema or annotations, or adds a
tool, the gateway hides it from `tools/list` and refuses to call it until it is pinned again. A
poisoned description never reaches the agent, and a call against it never reaches the server.
A listing the gateway cannot read (no valid name, a number with a fraction, a name listed twice)
has no pin and stays blocked.

## Every call is a decision

A `tools/call` must carry the agent Instance's own signed statement in `_meta`
(`io.suiss.access/ais`, with `io.suiss.access/validity`), over the intent of the call: the proxy
registration's action on `namespace:[proxy, tool]`, with the arguments as parameters. The agent
builds the same intent with `access_mcp_gateway::domain::tool_def` and
`access_sdk::mcp::tool::intent`, with the gateway's PEP name in the statement.

The gateway reads the server's current definition of the tool, sends the evaluation with the
tool and its pin to Access, and verifies the answer with the SDK against the domain's metadata.
Only a verified ALLOW for this intent, this PEP and this Exercise is forwarded. A DENY, a required
action, an unpinned tool or an unreachable Access is answered to the agent, and the server sees
nothing. The agent's statement is not forwarded and no agent credential is passed on.

Access records each decided call once as `mcp_gateway.call`: the Exercise, the tool and its pin,
with the agent's Instance as actor. The arguments are never recorded.

## What it serves

`initialize`, `ping`, notifications, `tools/list` and `tools/call`. Resources, prompts and every
other method are not served.

## Running it

`access-mcp-gateway` reads its configuration from the environment; see `src/main.rs` for the
variables: the listen address and MCP path behind the engine, the MCP server's host and allowed
origins, Access's origin with the trust roots, client certificate and key, the MCP server's
endpoint and its trust roots, the realm's governing domain, and the proxy registration's name,
namespace and action. It keeps no state.

## License

Apache-2.0.
