//! The Record Export Package of an `access.audit_export` Exercise (AP-14, PI-4, U53, §17.6.13).
//! An export is never a separate read path: the caller first commits an `access:audit_export`
//! intent through ADP with its AIS, which the audit Grant must cover; the package is then built
//! for that allowed Exercise only, from the request that made it, and names it as
//! `export_exercise`. The package verifies itself before it leaves (INV-27).
//!
//! The intent carries the range and the disclosure as typed parameters: `from` and `to`
//! (`Count`, positions; `to` defaults to the head) and `disclosure` (`Enum`, `"redacted"` by
//! default, `"full"` only for a caller who audits the domain, OP-141 m.38 (d)).

use access_authority_sequencer::ports::DomainLog;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::intent::{ParamValue, intent_digest};
use access_kernel::meta;
use access_kernel::model::Id;

use crate::CoreError;
use crate::app::{Authority, Incoming, who};
use crate::domain::export::{self, Coverage, ExportError, Package};
use crate::ports::{Binding, Reader, Salts};
use crate::rate::Class;

/// The export action.s name in the core namespace (OP-151 m.19 (d)).
pub use crate::domain::export::EXPORT_ACTION;

/// The namespace of the export intent's resource.
pub use crate::domain::export::AUDIT_NAMESPACE as EXPORT_NAMESPACE;

/// A built export and who made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exported {
    /// The package.
    pub package: Package,
    /// The exporting Party.
    pub party: Id,
    /// Its Instance.
    pub instance: Id,
}

fn count(req: &crate::domain::Request, name: &str) -> Result<Option<u64>, CoreError> {
    match req.intent.params.get(name) {
        None => Ok(None),
        Some(ParamValue::Count(n)) => Ok(Some(*n)),
        Some(_) => Err(CoreError::Protocol("export-range")),
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The package of the allowed `access.audit_export` Exercise `inc` names, at trusted time
    /// `now` (AP-14).
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `export` for a request that is not an export intent,
    /// `export-exercise` when its Exercise is not this actor's allowed one, `export-range` and
    /// `export-scope` for a range or disclosure it may not have; [`CoreError::Ais`];
    /// [`CoreError::Limited`]; [`CoreError::Unavailable`] when the package does not verify.
    pub async fn export(&mut self, inc: &Incoming, now: u64) -> Result<Exported, CoreError> {
        let req = &inc.request;
        if req.domain != self.domain {
            return Err(CoreError::Protocol("domain"));
        }
        let on_audit = req
            .intent
            .resources
            .first()
            .is_some_and(|r| r.namespace == EXPORT_NAMESPACE);
        if req.intent.action.namespace != meta::NAMESPACE
            || req.intent.action.name != EXPORT_ACTION
            || req.mode != Mode::Commit
            || !on_audit
        {
            return Err(CoreError::Protocol("export"));
        }
        let digest = intent_digest(&req.intent).map_err(|_| CoreError::Protocol("intent"))?;
        let actor = self
            .actor(inc, &digest, now)
            .await?
            .ok_or(CoreError::Protocol("export-exercise"))?;
        // §13.7.4, OP-141 m.23: an export is counted with explanations
        if !self
            .limiter
            .admit(Class::Explain, who(inc, Some(actor)), now)
        {
            return Err(CoreError::Limited);
        }
        // PI-4: only the actor's own allowed Exercise of this very intent
        let allowed = self.reader.nonce(&req.nonce).await?.is_some_and(|n| {
            n.intent_digest == digest.0
                && n.actor == actor.instance.0.to_vec()
                && n.outcome == "allow"
        });
        if !allowed {
            return Err(CoreError::Protocol("export-exercise"));
        }
        let from = count(req, "from")?.unwrap_or(0);
        let to = count(req, "to")?.unwrap_or_else(|| self.head());
        if to > self.head() {
            return Err(CoreError::Protocol("export-range"));
        }
        let coverage = match req.intent.params.get("disclosure") {
            None => Coverage::Digest,
            Some(ParamValue::Enum(e)) if e == "redacted" => Coverage::Digest,
            Some(ParamValue::Enum(e)) if e == "full" => Coverage::Full,
            Some(_) => return Err(CoreError::Protocol("export-scope")),
        };
        // OP-141 m.38 (d): full records only for who audits the domain
        if coverage == Coverage::Full && !self.audits(&actor.party, now).await? {
            return Err(CoreError::Protocol("export-scope"));
        }
        let exercise: Digest =
            meta::exercise_id(&req.domain, &req.nonce).map_err(|_| CoreError::Protocol("nonce"))?;
        let log = self.reader.log(0, to).await?;
        let package = export::build(self.domain, &log, (from, to), coverage, exercise).map_err(
            |e| match e {
                ExportError::Range => CoreError::Protocol("export-range"),
                _ => CoreError::Unavailable("export"),
            },
        )?;
        // INV-27: what leaves verifies with the open Kernel alone
        export::verify(&package).map_err(|_| CoreError::Unavailable("export-verify"))?;
        Ok(Exported {
            package,
            party: actor.party,
            instance: actor.instance,
        })
    }
}
