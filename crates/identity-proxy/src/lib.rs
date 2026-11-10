//! Forward-auth of the identity plane (IDP-30 (1), (3), B22, OP-156 m.3 (l)).
//!
//! - A tenant's own Nginx, Traefik, Caddy or Envoy is a PEP: it asks
//!   `/proxy/v1/check/{engine}` about each request, and Access answers in that engine's protocol
//!   ([`domain::engine`], [`domain::answer`]). The Access Proxy service asks the same way and
//!   gets the same answers (B22).
//! - The proxy is registered by `idp.proxy.register` (CT2) with its transport identity, host,
//!   OIDC client and the action each request asks ([`domain::registration`]).
//! - The browser's session on the application host is the `__Host-access-proxy` cookie, set
//!   through the realm's hosted sign-in with OIDC code + PKCE ([`app`]).
//! - Each request is the domain's eligibility check of the session's Party, cached for at most
//!   min(ValidityContract horizon, 30 s) and emptied by the doorbell ([`domain::cache`]).
//! - The application receives an ES256 `access-app+jwt` of 60 s in `Access-Identity`, and the
//!   plain `X-Access-User`/`X-Access-Email` only under `idp.proxy.plain_headers` (CT2).
//!
//! Nothing here answers for Access when it cannot be reached: the request is refused (MD-8,
//! TI-9).

pub mod app;
pub mod domain;
pub mod ports;
