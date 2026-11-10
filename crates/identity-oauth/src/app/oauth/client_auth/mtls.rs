//! Mutual TLS client authentication (RFC 8705 §2; §10.4.3, §12.2.1, TN-32, OP-155 m.3 (k)).
//! The certificate is the one the TLS connection to access-server presented: a forwarded
//! certificate header is never read. `tls_client_auth` takes a certificate the realm's trusted
//! CAs issued and that is known not revoked, naming the registered subject; the self-signed
//! method takes one of the certificates the client registered. Its `x5t#S256` then binds the
//! client's tokens (RFC 8705 §3).

use access_crypto::webauthn::sha256;

use crate::app::oauth::{Env, OAuth, Realm};
use crate::domain::client::{Client, ClientAuthError, Presented};
use crate::domain::fapi::{TlsAuth, names_match, self_signed_match};
use crate::ports::Unavailable;

impl<E: Env> OAuth<E> {
    /// The mutual TLS client `client` once the connection's `chain` (leaf first) authenticates
    /// it under `tls`; it presents only its `client_id` besides the certificate.
    pub(crate) async fn mtls_client(
        &self,
        realm: &Realm,
        mut client: Client,
        tls: &TlsAuth,
        presented: &Presented,
        chain: &[Vec<u8>],
        now: u64,
    ) -> Result<Result<Client, ClientAuthError>, Unavailable> {
        if !matches!(presented, Presented::Id(_)) {
            return Ok(Err(ClientAuthError::Method));
        }
        let Some(leaf) = chain.first() else {
            return Ok(Err(ClientAuthError::Rejected));
        };
        let accepted = match tls {
            // MD-8, OP-155 m.3 (m)
            TlsAuth::Pki(name) => {
                match self
                    .env
                    .client_certificates()
                    .verify(realm, chain, now)
                    .await?
                {
                    Ok(names) => names_match(name, &names),
                    Err(r) => {
                        tracing::info!(reason = %r, "client certificate refused");
                        false
                    }
                }
            }
            TlsAuth::SelfSigned { jwks } => self_signed_match(jwks, leaf),
        };
        if !accepted {
            return Ok(Err(ClientAuthError::Rejected));
        }
        client.certificate = Some(sha256(leaf));
        Ok(Ok(client))
    }
}
