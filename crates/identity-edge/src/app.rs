//! The edge calls access-server serves (OP-155 m.3 (c)): `hello`, `subject_lookup`,
//! `issue_claim` and `audit`. Each starts from the gateway the certificate named and stays in
//! its realm (IDP-26, §13.2); nothing here writes authority state (IDI-11).

use access_identity_account::adapters::pg::{PgAccounts, PgTx};
use access_identity_account::app::claims::emit;
use access_identity_account::domain::claims::{AuthFacts, Bind, authentication};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::ports::{AccountDb, AccountTx};
use access_internal_api::edge::{
    Audit, Audited, GatewayUri, Hello, IssueClaim, Issued, Subject, SubjectLookup,
};
use access_kernel::digest::Digest;
use access_store::Pool;
use access_store::audit::AuditEvent;

use crate::EdgeError;
use crate::domain::{self, Gateway, Refusal};
pub use crate::ports::{Registry, Vaults};

pub mod ldap;

/// The edge service over the gateway registry and the realms' account tables.
pub struct Edge<R, V> {
    registry: R,
    vaults: V,
    app: Pool,
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

impl<R: Registry, V: Vaults> Edge<R, V> {
    /// The service; `app` is the `access_app` pool.
    pub const fn new(registry: R, vaults: V, app: Pool) -> Self {
        Self {
            registry,
            vaults,
            app,
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

    /// The live gateway the connection's certificate names (IDP-26).
    ///
    /// # Errors
    /// [`EdgeError::NotRegistered`]; [`EdgeError::Unavailable`].
    pub async fn gateway(&self, uri: &GatewayUri, cert: &[u8; 32]) -> Result<Gateway, EdgeError> {
        self.registry
            .gateway(uri, cert)
            .await?
            .ok_or(EdgeError::NotRegistered)
    }

    /// `hello`: the gateway and its realm.
    #[must_use]
    pub fn hello(g: &Gateway) -> Hello {
        Hello {
            gateway: g.uri.clone(),
            realm: g.slug.clone(),
        }
    }

    /// `subject_lookup`: the active subject holding `identifier` in the gateway's realm. An
    /// unknown and an inactive identifier answer the same.
    ///
    /// # Errors
    /// [`EdgeError`].
    pub async fn subject_lookup(
        &self,
        g: &Gateway,
        q: &SubjectLookup,
    ) -> Result<Subject, EdgeError> {
        domain::in_scope(g, &q.realm)?;
        let mut tx = self.begin(g).await?;
        let subject = active(&mut tx, &q.identifier).await?;
        tx.commit().await?;
        Ok(Subject { subject })
    }

    /// `issue_claim`: queues the realm issuer's `authentication` Claim of an edge
    /// authentication, with its audit row (P-ID-5). The gateway is never the issuer.
    ///
    /// # Errors
    /// [`EdgeError`].
    pub async fn issue_claim(&self, g: &Gateway, q: &IssueClaim) -> Result<Issued, EdgeError> {
        domain::in_scope(g, &q.realm)?;
        let method = domain::method(g.uri.kind, &q.method)?;
        let mut tx = self.begin(g).await?;
        domain::fresh(q.auth_time, tx.server_time().await?)?;
        let live = tx
            .subject(q.subject, false)
            .await?
            .and_then(|s| AccountStatus::parse(&s.status))
            .is_some_and(AccountStatus::can_authenticate);
        if !live {
            return Err(Refusal::Subject.into());
        }
        let order = authentication(AuthFacts {
            subject: q.subject,
            method,
            auth_time: q.auth_time,
            assurance: domain::levels(),
            webauthn: None,
            evidence: q.evidence.map(Digest),
            bind: Bind::None,
        });
        emit(&mut tx, &order).await?;
        let actor = g.uri.uri();
        let target = hex(&q.subject);
        tx.audit(&AuditEvent {
            event_type: "edge.claim_requested",
            actor: &actor,
            target: &target,
            correlation: &g.uri.name,
        })
        .await?;
        tx.commit().await?;
        Ok(Issued { queued: true })
    }

    /// `audit`: one gateway event in the realm's audit log, codes only (OP-47).
    ///
    /// # Errors
    /// [`EdgeError`].
    pub async fn audit(&self, g: &Gateway, q: &Audit) -> Result<Audited, EdgeError> {
        domain::in_scope(g, &q.realm)?;
        let event_type = domain::event_type(&q.event, &q.outcome)?;
        let actor = g.uri.uri();
        let target = q.subject.map_or_else(|| String::from("realm"), |s| hex(&s));
        let mut tx = self.begin(g).await?;
        tx.audit(&AuditEvent {
            event_type: &event_type,
            actor: &actor,
            target: &target,
            correlation: &g.uri.name,
        })
        .await?;
        tx.commit().await?;
        Ok(Audited { recorded: true })
    }
}

async fn active<T: AccountTx>(tx: &mut T, identifier: &str) -> Result<Option<[u8; 16]>, EdgeError> {
    let Some(id) = tx.subject_by_identifier(identifier).await? else {
        return Ok(None);
    };
    let live = tx
        .subject(id, false)
        .await?
        .and_then(|s| AccountStatus::parse(&s.status))
        .is_some_and(AccountStatus::can_authenticate);
    Ok(live.then_some(id))
}
