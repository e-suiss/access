//! Access Proxy (OP-156 m.3 (m), IDP-30, B22): the `access-proxy` tool renders one TOML file
//! into Envoy, Caddy and Traefik configuration whose forward-auth check is Access's
//! `/proxy/v1/check/{engine}`. The proxy engine is never written here; the service uses public
//! crates only (OP-62) and holds no authority.

pub mod behaviour;
pub mod config;
pub mod contract;
pub mod render;
pub mod yaml;
