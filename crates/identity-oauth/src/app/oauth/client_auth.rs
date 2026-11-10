//! Workload client authentication and a workload's first presentation (OP-154 m.3 (d), (r),
//! §11.12.1, AG-30, L25, U20).
//!
//! A workload client authenticates with a JWT-SVID (`client_assertion_type` `jwt-spiffe`):
//! the realm's one registration whose selector matches the SVID's SPIFFE ID names it, its trust
//! domain must hold the domain root's actor-binding Acceptance, and the SVID must verify
//! against that trust domain's current bundle and be used once. The verified workload and the
//! DPoP key the request proves become the realm issuer's `identity_binding_workload` Claim
//! about the registration's agent Party; the key's own `instance_create` then stands on that
//! Claim alone, and the Instance still needs a Grant to act.

mod mtls;
mod presentation;
pub(crate) mod saml_bearer;
mod secret;
mod spiffe;

use crate::app::oauth::{ClientRequest, TokenHttp};
use crate::domain::metadata::Endpoint;
use crate::domain::request::Params;

impl<'a> TokenHttp<'a> {
    /// What a token request presents to authenticate its client, the connection's X.509-SVID
    /// chain included (OP-154 m.3 (r)).
    pub(crate) fn client_request(&self, params: &'a Params) -> ClientRequest<'a> {
        ClientRequest {
            authorization: self.authorization,
            params,
            endpoint: Endpoint::Token.path(),
            chain: self.client_chain,
        }
    }
}
