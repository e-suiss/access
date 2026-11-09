//! A workload's first presentation (OP-154 m.3 (d), §11.21.1 carleton note, U20): the verified
//! workload and the DPoP key the request proved become the realm issuer's
//! `identity_binding_workload` Claim about the registration's agent Party. It is queued with
//! the token request and issued only if that transaction commits (OP-10); it grants nothing.

use access_identity_account::domain::claims::workload_binding;
use access_kernel::claim::body::Workload;

use crate::app::oauth::{Env, OAuth, Realm};
use crate::domain::client::{Client, ClientAuth};
use crate::domain::dpop::Jkt;
use crate::ports::Unavailable;
use crate::ports::oauth::OAuthTx;

impl<E: Env> OAuth<E> {
    /// OP-154 m.3 (d), U20: queues the `identity_binding_workload` Claim of a verified workload
    /// client for the key `jkt`; nothing for any other client.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub(crate) async fn first_presentation(
        &self,
        realm: &Realm,
        client: &Client,
        jkt: Jkt,
        now: u64,
    ) -> Result<(), Unavailable> {
        let ClientAuth::Workload(w) = &client.auth else {
            return Ok(());
        };
        let Some(v) = &w.verified else {
            return Ok(());
        };
        let order = workload_binding(
            v.agent,
            Workload {
                uri: v.uri.clone(),
                thumbprint: jkt.0,
            },
            &v.evidence,
            now,
        );
        let bytes = order.to_bytes().map_err(|_| Unavailable)?;
        let mut tx = self.begin(realm).await?;
        tx.outbox(&order.kind(), &bytes).await?;
        tx.commit().await
    }
}
