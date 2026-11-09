//! A workload's first presentation on the authority side (OP-154 m.3 (d), §11.21.1 carleton
//! note, AG-30, L25, U20): the realm issuer's `identity_binding_workload` Claim is the actor
//! binding of a self-signed `instance_create`. The key's own `instance_create` stands only
//! while a live Claim, admitted by its issuer's actor-binding Acceptance, binds the key's
//! thumbprint to the Party; the Instance it opens still acts only through a Grant.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::claim::body::{BindingKind, Body, Class};
use access_kernel::claim::{self, ClaimState};
use access_kernel::codec::Canonical as _;
use access_kernel::meta::{self, kind};
use access_kernel::model::{EqValue, Id};

use crate::CoreError;
use crate::app::Authority;
use crate::domain::Snapshot;
use crate::ports::{Binding, Reader, Salts};

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// OP-154 m.3 (d): whether a live, accepted, unsuperseded `identity_binding_workload`
    /// Claim about `party` names the key `kid` with its disclosed body.
    pub(crate) async fn workload_bound(
        &self,
        party: &Id,
        kid: &[u8; 32],
        now: u64,
    ) -> Result<bool, CoreError> {
        let class = Class::IdentityBinding(BindingKind::Workload).name();
        let mut snap = Snapshot::default();
        for (_, value, _) in self.scan(&claim::member_prefix(&class, party)).await? {
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(state) = self
                .get(&mut snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|c| {
                    let s = &c.statement;
                    c.ended.is_none()
                        && s.subject == *party
                        && s.class == class
                        && s.validity.from <= now
                        && now <= s.validity.until
                })
            else {
                continue;
            };
            let Some(EqValue::Bytes(d)) = &state.statement.value else {
                continue;
            };
            let Ok(d) = <[u8; 32]>::try_from(d.as_slice()) else {
                continue;
            };
            let Some(bytes) = self.reader.proof(&d).await? else {
                continue;
            };
            let named = claim::body::check(&state.statement, Some(&bytes))
                .ok()
                .flatten()
                .is_some_and(|b| match b {
                    Body::IdentityBinding(ib) => ib.workload.is_some_and(|w| w.thumbprint == *kid),
                    _ => false,
                });
            if !named {
                continue;
            }
            let gates = self.gates(&mut snap, &state.statement.issuer).await?;
            let accepted = gates
                .iter()
                .any(|g| g.admits_for(claim::ACTOR_BINDING, &state.statement, now));
            if accepted && self.unsuperseded(&mut snap, &id, &state.statement).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// OP-154 m.3 (r), AG-30: whether a live Acceptance of `issuer` lets it sign `class` for
    /// `use_` at `now`: how a SPIFFE or WIMSE trust domain is accepted, by the domain root's
    /// actor-binding Acceptance of its issuer id, never as an `AuthorityDomain`.
    ///
    /// # Errors
    /// [`CoreError`] for a failed read.
    pub async fn issuer_accepted(
        &self,
        issuer: &Id,
        (use_, class): (&str, &str),
        now: u64,
    ) -> Result<bool, CoreError> {
        let mut snap = Snapshot::default();
        Ok(self.gates(&mut snap, issuer).await?.iter().any(|g| {
            g.use_ == use_
                && g.issuer == Some(*issuer)
                && g.classes.iter().any(|c| c == class)
                && g.validity.from <= now
                && now <= g.validity.until
                && g.ingest_until.is_none_or(|u| now <= u)
        }))
    }
}
