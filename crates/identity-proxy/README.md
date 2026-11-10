# access-identity-proxy

Forward-auth for the Access identity plane: a tenant's own Nginx, Traefik, Caddy or Envoy puts
an internal application behind Access without changing the application. The proxy asks Access
about every request; Access decides; the application receives who the request is for in a signed,
short-lived token.

## The proxy is a PEP

A proxy is registered with `idp.proxy.register` (CT2) for one application host. The registration
names:

- the engine (`nginx`, `traefik`, `caddy` or `envoy`);
- the proxy's transport identity: the base64url SHA-256 of the client certificate it presents on
  the mTLS listener;
- the realm client the browser signs in with, which lists
  `https://{host}/access-proxy/v1/callback` as a redirect URI;
- the action every request asks, the resource namespace, and up to 64 path patterns.

A check from a proxy that is not registered for the host gets `401`. Nothing in the forwarded
request can name a proxy.

## The protocols

| Engine | Asks | Reads |
|---|---|---|
| Nginx `auth_request` | `GET /proxy/v1/check/nginx` with `X-Original-Method`, `X-Original-URI`, `X-Forwarded-Host` | `2xx` allow, `403` deny; a sign-in is `401` with `Location` and `Set-Cookie` for `error_page` |
| Traefik `forwardAuth` | `/proxy/v1/check/traefik` with `X-Forwarded-Method`, `X-Forwarded-Uri`, `X-Forwarded-Host` | `2xx` allow; anything else goes to the browser as it is |
| Caddy `forward_auth` | `/proxy/v1/check/caddy`, the same headers | as Traefik |
| Envoy `ext_authz` (HTTP service) | `/proxy/v1/check/envoy{original path}`, the original method | `200` allow; `x-envoy-auth-headers-to-remove` names the identity headers to drop |

There is no gRPC mode.

An allowed answer carries `Access-Identity`, and `X-Access-User`/`X-Access-Email` only when
`idp.proxy.plain_headers` is on. Configure the engine to copy exactly those headers from the
answer: Traefik's `authResponseHeaders` and Caddy's `copy_headers` remove a header the answer does
not carry, Nginx's `proxy_set_header` with an empty variable removes it, and Envoy removes what
`x-envoy-auth-headers-to-remove` lists. Whatever the client sent under those names never reaches
the application.

## Signing in

Without a `__Host-access-proxy` cookie the browser goes to the realm's hosted sign-in with OIDC
authorization code and PKCE; Access keeps the PKCE verifier and binds the `state` to a
`__Host-access-proxy-state` cookie on the application host. The callback comes back through the
proxy like any other request: Access redeems the code once, opens the proxy session on the OAuth
grant, and sets the cookie. The session ends with the login session, a revoked grant, a raised
subject epoch or the proxy's retirement.

## Every request is a decision

Each request is the domain's eligibility check of the session's Party for the registration's
action on the resource its path pattern names (`[proxy name, pattern segments…]`). A decision is
reused for at most min(the Grant's validity, the login session, 30 s), keyed by session,
application, method and path pattern. The cache is emptied for a domain as soon as its head moves
(the doorbell, or the one-second head watcher). When Access cannot decide, the answer is `503`:
the request is refused, never allowed from a stale decision.

## The application token

`Access-Identity` is a compact JWS: `typ: access-app+jwt`, ES256 under the realm JOSE key, `aud`
the application's origin, `sub` pairwise for the registration's client, `decision` the id of the
decision that let the request through, 60 seconds. Applications verify it with
`esuiss-access-sdk`'s `resource::app_token::verify_app_token` against the realm JWKS.

## Plain headers

Turning on `X-Access-User` (CT2) runs a setup check first: if Access can open a connection to the
registered upstream, anyone could, so the change is refused and audited. A proxy without an
upstream cannot pass the check.

## MCP mode

The MCP gateway is a proxy registered the same way for an MCP server's host. Before it shows or
calls a tool it asks Access:

- `POST /proxy/v1/mcp/tools` with each tool the server lists and its pin answers which ones
  stand pinned. A pin is the base64url SHA-256 of the RFC 8785 form of the tool's `name`,
  `description`, `inputSchema` and `annotations`.
- `POST /proxy/v1/mcp/calls` carries one `tools/call`: the tool, its pin, and the AuthZEN
  evaluation of the agent's own `commit` statement with the gateway as PEP. The intent must be
  the registration's action on `namespace:[proxy, tool]` in the realm's governing domain.

`idp.proxy.mcp_pin` (CT2) pins a proxy's whole tool list. Pinning is strict: a tool whose
definition changed, or that was never pinned, is blocked before any decision (`409
mcp-tool-unpinned`) and audited as `mcp_gateway.tool_blocked`. Every decided call writes one
`mcp_gateway.call` audit row: the Exercise, the tool and its pin, and the agent's Instance as
actor. The arguments are never recorded.
