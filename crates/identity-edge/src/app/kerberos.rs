//! The Kerberos gateway's call (§10.6.4, IDP-17, OP-155 m.3 (o)): `authenticate`. The gateway
//! accepted a ticket with its keytab and reports who, for which SPN, under which key version and
//! enctype; this holds the facts to the realm's keytab policy, tracks the key version and names
//! the subject. Access is never a KDC and never sees a ticket.

use access_identity_account::adapters::pg::{PgAccounts, PgTx};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_internal_api::edge::GatewayKind;
use access_internal_api::edge::kerberos::{Authenticate, Authenticated};
use access_store::Pool;
use access_store::audit::AuditEvent;

use crate::EdgeError;
use crate::domain::kerberos::{admissible, current, user_of};
use crate::domain::{self, Gateway, Refusal};
use crate::ports::Vaults;

/// The Kerberos calls over the realms' account tables.
pub struct Kerberos<V> {
    vaults: V,
    app: Pool,
}

impl<V> core::fmt::Debug for Kerberos<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kerberos").finish_non_exhaustive()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

impl<V: Vaults> Kerberos<V> {
    /// The service; `app` is the `access_app` pool.
    #[must_use]
    pub const fn new(vaults: V, app: Pool) -> Self {
        Self { vaults, app }
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

    async fn refuse(mut tx: PgTx, g: &Gateway, r: Refusal) -> Result<Authenticated, EdgeError> {
        Self::audit(&mut tx, g, "login.kerberos.failed", None).await?;
        tx.commit().await?;
        Err(r.into())
    }

    /// `authenticate` (OP-155 m.3 (o)): the SPN must be the keytab policy's exactly, the enctype
    /// AES256, and the key version current; the principal `user@REALM` of the SPN's realm names
    /// the active account with user name `user`.
    ///
    /// # Errors
    /// [`EdgeError`]; a policy refusal is [`Refusal::Keytab`], [`Refusal::Spn`],
    /// [`Refusal::Enctype`] or [`Refusal::Kvno`].
    pub async fn authenticate(
        &self,
        g: &Gateway,
        q: &Authenticate,
    ) -> Result<Authenticated, EdgeError> {
        domain::in_scope(g, &q.realm)?;
        if g.uri.kind != GatewayKind::Kerberos {
            return Err(Refusal::Method.into());
        }
        let mut tx = self.begin(g).await?;
        let Some(policy) = access_store::edge::keytab_policy(&mut tx.0, &g.uri.name).await? else {
            return Self::refuse(tx, g, Refusal::Keytab).await;
        };
        if let Err(r) = admissible(&policy, q) {
            return Self::refuse(tx, g, r).await;
        }
        let now = tx.server_time().await?;
        let seen = access_store::edge::seen_kvno(&mut tx.0, &g.uri.name, q.kvno, now).await?;
        if let Err(r) = current(&policy, q.kvno, &seen, now) {
            return Self::refuse(tx, g, r).await;
        }
        let subject = match user_of(&q.principal, &policy.spn) {
            Some(user) => match tx.subject_by_identifier(user).await? {
                Some(id) => tx
                    .subject(id, false)
                    .await?
                    .and_then(|s| AccountStatus::parse(&s.status))
                    .is_some_and(AccountStatus::can_authenticate)
                    .then_some(id),
                None => None,
            },
            None => None,
        };
        if subject.is_some() {
            Self::audit(&mut tx, g, "login.kerberos.succeeded", subject).await?;
        } else {
            Self::audit(&mut tx, g, "login.kerberos.failed", None).await?;
        }
        tx.commit().await?;
        Ok(Authenticated { subject })
    }
}
