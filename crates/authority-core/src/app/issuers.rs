//! The issuers whose assertions the realm's authorization server may take as Claim input
//! (§9.13, §11.11.3 step 1, AG-29, OP-154 m.3 (m), (q)): an issuer the domain accepted for
//! `actor-binding` with a pinned key set. The assertion stays a carrier: it binds an actor, it
//! never grants (L25, MD-18).

use access_authority_sequencer::ports::DomainLog;
use access_kernel::claim::{self, ACTOR_BINDING, Pinned};
use access_kernel::codec::Canonical;
use access_kernel::meta::{self, ContentState, kind};
use access_kernel::model::Id;
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::Authority;
use crate::domain::Snapshot;
use crate::ports::{Binding, Reader, Salts};

fn acceptances_prefix() -> Vec<u8> {
    let mut key = meta::key(kind::ACCEPTANCES, &Id([0; 16]));
    key.truncate(key.len().saturating_sub(17));
    key
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The live `actor-binding` Acceptances at `now` whose pinned key set names `iss`, each with
    /// its issuer Party; an Acceptance for any other use, out of its window or without a pinned
    /// key set is not one.
    ///
    /// # Errors
    /// [`CoreError`] when the state cannot be read.
    pub async fn assertion_issuers(
        &self,
        iss: &str,
        now: u64,
    ) -> Result<Vec<(Id, Pinned)>, CoreError> {
        let mut snap = Snapshot::default();
        let mut out: Vec<(Id, Pinned)> = Vec::new();
        for (_, value, _) in self.scan(&acceptances_prefix()).await? {
            let Some(Value::Array(ids)) = value else {
                continue;
            };
            for v in ids {
                let Ok(a) = Id::from_value(&v) else {
                    continue;
                };
                let Some(content) = self
                    .get(&mut snap, &meta::key(kind::ACCEPTANCE, &a))
                    .await?
                    .and_then(|v| ContentState::from_value(&v).ok())
                    .filter(|c| c.ended.is_none())
                else {
                    continue;
                };
                let Ok(g) = claim::Gate::of(&content.content) else {
                    continue;
                };
                let live = g.validity.from <= now && now < g.validity.until;
                if let (true, true, Some(issuer), Some(p)) =
                    (g.use_ == ACTOR_BINDING, live, g.issuer, g.pinned)
                    && p.iss == iss
                    && !out.iter().any(|(i, q)| *i == issuer && *q == p)
                {
                    out.push((issuer, p));
                }
            }
        }
        Ok(out)
    }
}
