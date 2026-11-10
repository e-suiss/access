//! The RADIUS gateway's call (§10.6.5, IDP-18, OP-155 m.3 (f)): `authenticate`. Every call names
//! the `RadSec` client by its certificate, and only a client registered with this gateway is
//! answered. PAP checks a directory app password (the LDAP credential class) of the account
//! holding the `User-Name`; the primary password never authenticates over RADIUS.

use std::sync::Arc;

use access_identity_account::adapters::pg::{PgAccounts, PgTx};
use access_identity_account::app::hasher::Hasher;
use access_identity_account::app::ldap;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_internal_api::edge::GatewayKind;
use access_internal_api::edge::radius::{Authenticate, Authenticated, Mechanism};
use access_store::Pool;
use access_store::audit::AuditEvent;

use crate::EdgeError;
use crate::domain::{self, Gateway, Refusal};
use crate::ports::Vaults;

/// The RADIUS calls over the realms' account tables.
pub struct Radius<V> {
    vaults: V,
    app: Pool,
    hasher: Arc<Hasher>,
}

impl<V> core::fmt::Debug for Radius<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Radius").finish_non_exhaustive()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

impl<V: Vaults> Radius<V> {
    /// The service; `app` is the `access_app` pool.
    #[must_use]
    pub const fn new(vaults: V, app: Pool, hasher: Arc<Hasher>) -> Self {
        Self {
            vaults,
            app,
            hasher,
        }
    }

    async fn begin(&self, g: &Gateway) -> Result<PgTx, EdgeError> {
        let vault = self
            .vaults
            .vault(g.tenant, g.realm)
            .ok_or_else(|| EdgeError::Unavailable(String::from("vault")))?;
        Ok(PgAccounts::sealed(self.app.clone(), vault)
            .begin(g.tenant, g.realm)
            .await?)
    }

    async fn audit(
        tx: &mut PgTx,
        g: &Gateway,
        event_type: &'static str,
        subject: Option<[u8; 16]>,
    ) -> Result<(), EdgeError> {
        let actor = g.uri.uri();
        let target = subject.map_or_else(|| String::from("unknown"), |s| hex(&s));
        tx.audit(&AuditEvent {
            event_type,
            actor: &actor,
            target: &target,
            correlation: &g.uri.name,
        })
        .await?;
        Ok(())
    }

    /// `authenticate` (OP-155 m.3 (f)): the client must be registered with the gateway; PAP then
    /// needs a directory app password of the account holding the name. An unknown name and a
    /// wrong password answer the same.
    ///
    /// # Errors
    /// [`EdgeError`]; [`Refusal::RadiusClient`] for an unregistered client.
    pub async fn authenticate(
        &self,
        g: &Gateway,
        q: &Authenticate,
    ) -> Result<Authenticated, EdgeError> {
        domain::in_scope(g, &q.realm)?;
        if g.uri.kind != GatewayKind::Radius {
            return Err(Refusal::Method.into());
        }
        let mut tx = self.begin(g).await?;
        if !access_store::edge::radius_client_registered(&mut tx.0, &g.uri.name, &q.client).await? {
            tx.commit().await?;
            return Err(Refusal::RadiusClient.into());
        }
        let (Mechanism::Pap, Some(name), Some(secret)) = (q.mechanism, &q.name, &q.secret) else {
            tx.commit().await?;
            return Ok(Authenticated::default());
        };
        let token = core::str::from_utf8(secret).unwrap_or_default();
        let bound = ldap::verify(&mut tx, &self.hasher, token).await?;
        let holder = match bound {
            Some(_) => tx.subject_by_identifier(name.trim()).await?,
            None => None,
        };
        let subject = bound
            .filter(|b| holder == Some(b.subject))
            .map(|b| b.subject);
        if subject.is_some() {
            Self::audit(&mut tx, g, "login.radius.succeeded", subject).await?;
        } else {
            Self::audit(&mut tx, g, "login.radius.failed", None).await?;
        }
        tx.commit().await?;
        Ok(Authenticated { subject })
    }
}
