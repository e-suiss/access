//! Commit quotas (OP-158 m.3 (v), T27, TN-24, TN-1, B3, B10, B18, B19, D7, SI-20): every
//! widening commit draws from its domain's and its tenant's exact counters (layer B), and a
//! tenant on billing hold commits nothing that widens. Over a quota a commit is a protocol
//! rejection: no record, the nonce is not consumed, no other domain is touched. The narrowing
//! class and the exit class (handover, recovery) never draw and are never refused for quota or
//! billing; export is a read and never reaches here.

use access_kernel::codec::Canonical;
use access_kernel::combinator::Mode;
use access_kernel::meta::{self, ContentState, Payload, kind};
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::Authority;
use crate::domain::Request;
use crate::ports::{Binding, Reader, Salts};
use access_authority_sequencer::ports::DomainLog;

/// A counter's limit: units per second sustained and the burst.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    /// Units per second.
    pub per_second: u32,
    /// Units at once.
    pub burst: u32,
}

/// The commit quotas of a domain and its tenant (PD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quotas {
    /// Widening commits of one tenant across its domains.
    pub tenant: Rate,
    /// Widening commits of one domain.
    pub domain: Rate,
}

/// Widening commits per tenant: 500/s sustained, 2 500 burst (OP-158 m.3 (v), PD).
pub const TENANT: Rate = Rate {
    per_second: 500,
    burst: 2_500,
};

/// Widening commits per domain: 200/s sustained, 1 000 burst, ten times one actor's (§13.7.4,
/// OP-158 m.3 (v), PD).
pub const DOMAIN: Rate = Rate {
    per_second: 200,
    burst: 1_000,
};

impl Default for Quotas {
    fn default() -> Self {
        Self {
            tenant: TENANT,
            domain: DOMAIN,
        }
    }
}

/// Which counter refused a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The tenant is on billing hold (TN-1, B10).
    Suspended,
    /// The tenant's quota.
    Tenant,
    /// The domain's quota.
    Domain,
}

impl Refusal {
    /// The stable reason in the problem details.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Suspended => "billing-hold",
            Self::Tenant => "tenant",
            Self::Domain => "domain",
        }
    }
}

/// Why a commit draws no quota.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Free {
    /// It only narrows: revocation, termination, departure, retirement, renunciation or a
    /// restriction that only adds `forbid` statements (B3, B19, D7).
    Narrowing,
    /// It leaves the provider: handover, forced recovery or a Record Export (B10, B18,
    /// anti-hostage k.2).
    Exit,
    /// It reads and changes no authority state (§9.13.7).
    Read,
}

/// Whether `payload` is free of quota by its kind alone; a `policy_set` is decided on its
/// content by [`Authority::free_of_quota`].
#[must_use]
pub const fn free_by_kind(payload: &Payload) -> Option<Free> {
    match payload {
        Payload::GrantRevoke { .. }
        | Payload::GrantRenounce { .. }
        | Payload::MandateRevoke { .. }
        | Payload::AcceptanceRevoke { .. }
        | Payload::InstanceTerminate { .. }
        | Payload::PartyDepart { .. }
        | Payload::AnchorRetire { .. } => Some(Free::Narrowing),
        Payload::DomainHandover(_) | Payload::DomainRecover(_) => Some(Free::Exit),
        _ => None,
    }
}

/// Whether every statement of a new restriction is a `forbid` (SI-18, OP-157 m.3 (b)).
fn only_forbids(content: &Value) -> bool {
    match content.get("source") {
        Some(Value::Text(source)) => {
            let statements = meta::statements(source);
            !statements.is_empty() && statements.iter().all(|s| meta::is_forbid(s))
        }
        _ => false,
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Why `req` draws no quota, if it does not.
    pub(crate) async fn free_of_quota(&self, req: &Request) -> Result<Option<Free>, CoreError> {
        let action = &req.intent.action;
        if action.namespace == meta::NAMESPACE
            && action.name == crate::domain::export::EXPORT_ACTION
        {
            return Ok(Some(Free::Exit));
        }
        if meta::is_read(&action.namespace, &action.name) {
            return Ok(Some(Free::Read));
        }
        let Some(payload) = &req.payload else {
            return Ok(None);
        };
        if let Some(free) = free_by_kind(payload) {
            return Ok(Some(free));
        }
        let Payload::PolicySet {
            policy,
            content,
            defaults: None,
        } = payload
        else {
            return Ok(None);
        };
        let narrows = match policy {
            None => only_forbids(content),
            Some(p) => self
                .fetch(&[meta::key(kind::POLICY, p)])
                .await?
                .into_iter()
                .find_map(|(_, v, _)| v.and_then(|v| ContentState::from_value(&v).ok()))
                .filter(|old| old.ended.is_none())
                .is_some_and(|old| meta::policy_narrows(&old.content, content)),
        };
        Ok(narrows.then_some(Free::Narrowing))
    }

    /// Draws `req` from the domain's and its tenant's commit quota at `now`, unless it is a
    /// `check` or free of quota (OP-158 m.3 (v)).
    ///
    /// # Errors
    /// [`CoreError::Quota`] when a counter refuses; a counter that cannot be read refuses as
    /// [`CoreError::Store`] (MD-8).
    pub(crate) async fn draw_quota(&self, req: &Request, now: u64) -> Result<(), CoreError> {
        if req.mode == Mode::Check || self.free_of_quota(req).await?.is_some() {
            return Ok(());
        }
        match self.reader.take_quota(now).await? {
            None => Ok(()),
            Some(refusal) => {
                tracing::info!(
                    event = "quota.exceeded",
                    outcome = "refused",
                    dimension = refusal.reason(),
                    kind = "commit",
                    "a widening commit was over its quota; nothing was recorded (T27)"
                );
                Err(CoreError::Quota(refusal))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use access_kernel::model::Id;

    // B3, B19, D7, B18
    #[test]
    fn narrowing_and_exit_kinds_are_free() {
        let id = Id([1; 16]);
        assert_eq!(
            free_by_kind(&Payload::GrantRevoke { grant: id }),
            Some(Free::Narrowing)
        );
        assert_eq!(
            free_by_kind(&Payload::InstanceTerminate { instance: id }),
            Some(Free::Narrowing)
        );
        assert_eq!(
            free_by_kind(&Payload::PolicyRetire { policy: id }),
            None,
            "retiring a restriction widens"
        );
    }

    // SI-18
    #[test]
    fn a_new_restriction_is_free_only_when_it_only_forbids() {
        let source = |s: &str| Value::Map(vec![(Value::text("source"), Value::text(s))]);
        assert!(only_forbids(&source(
            "forbid (principal, action, resource);"
        )));
        assert!(!only_forbids(&source(
            "forbid (principal, action, resource); permit (principal, action, resource);"
        )));
        assert!(!only_forbids(&source("")));
        assert!(!only_forbids(&Value::Map(Vec::new())));
    }
}
