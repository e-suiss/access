//! The MCP gateway's questions in this process (AG-42, B22, OP-156 m.3 (n)): the proxy
//! registry of forward-auth, the pinned tool lists in the store, the realm's own ADP router with
//! the gateway as its PEP, the authority core's record of who acted, and the identity audit log.

use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_http::adp::adapters::Pep;
use access_identity_oauth::app::oauth::{Env, Realm};
use access_identity_proxy::domain::mcp::{PinnedTool, from_json};
use access_identity_proxy::domain::registration::Registration;
use access_identity_proxy::mcp::{Audit, Evaluated, McpPorts};
use access_identity_proxy::ports::{Ports as _, Unavailable};
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use access_store::identity::TenantTx;
use axum::body::{Body, to_bytes};
use axum::http::{Request, header};
use tower::ServiceExt as _;

use crate::proxy::ServerPorts;

/// Largest ADP answer read.
const MAX_ANSWER: usize = 1 << 22;

/// The MCP gateway's ports over this process.
pub(crate) struct McpServerPorts<E: Env, K, B: Binding, S: Salts, C> {
    pub(crate) proxy: ServerPorts<E, K, B, S, C>,
    pub(crate) adp: axum::Router,
}

fn down<T>(_: T) -> Unavailable {
    Unavailable
}

impl<E, K, B, S, C> McpServerPorts<E, K, B, S, C>
where
    E: Env,
    K: Keys,
    B: Binding + Clone,
    S: Salts + Clone,
    C: Clock + Clone,
{
    async fn tx(&self, realm: &Realm) -> Result<TenantTx, Unavailable> {
        TenantTx::begin(&self.proxy.app, realm.tenant, realm.realm)
            .await
            .map_err(down)
    }
}

impl<E, K, B, S, C> McpPorts for McpServerPorts<E, K, B, S, C>
where
    E: Env,
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    type Realm = Realm;

    async fn registered(
        &self,
        pep: &str,
        host: &str,
    ) -> Result<Option<(Realm, Registration)>, Unavailable> {
        Ok(self
            .proxy
            .registered(pep, host)
            .await?
            .map(|r| (r.realm, r.registration)))
    }

    async fn governing(&self, realm: &Realm) -> Result<Option<Digest>, Unavailable> {
        let mut t = self.tx(realm).await?;
        let g = access_store::idp::governance(&mut t).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(g.map(|g| Digest(*g.domain.as_bytes())))
    }

    async fn pins(&self, realm: &Realm, proxy: &str) -> Result<Vec<PinnedTool>, Unavailable> {
        let mut t = self.tx(realm).await?;
        let row = access_store::mcp_pins::pins(&mut t, proxy)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        let Some(row) = row else {
            return Ok(Vec::new());
        };
        let v: serde_json::Value = serde_json::from_str(&row.tools).map_err(down)?;
        from_json(&v).map_err(down)
    }

    async fn evaluate(&self, pep: &str, body: Vec<u8>) -> Result<Evaluated, Unavailable> {
        let mut req = Request::post("/access/v1/evaluation")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .map_err(down)?;
        req.extensions_mut().insert(Pep(String::from(pep)));
        let (parts, body) = self
            .adp
            .clone()
            .oneshot(req)
            .await
            .map_err(down)?
            .into_parts();
        let text = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        };
        let (status, content_type, key_excerpt) = (
            parts.status.as_u16(),
            text("content-type"),
            text("access-key-excerpt"),
        );
        let body = to_bytes(body, MAX_ANSWER).await.map_err(down)?.to_vec();
        Ok(Evaluated {
            status,
            content_type,
            key_excerpt,
            body,
        })
    }

    async fn instance(&self, domain: Digest, exercise: Digest) -> Result<Option<Id>, Unavailable> {
        Ok(self
            .proxy
            .domains
            .exercise_record(domain, exercise)
            .await
            .map_err(down)?
            .and_then(|r| r.instance))
    }

    async fn audit(&self, realm: &Realm, row: &Audit<'_>) -> Result<(), Unavailable> {
        let mut t = self.tx(realm).await?;
        t.audit(&access_store::audit::AuditEvent {
            event_type: row.event,
            actor: row.actor,
            target: row.target,
            correlation: row.correlation,
        })
        .await
        .map_err(down)?;
        t.commit().await.map_err(down)
    }
}
