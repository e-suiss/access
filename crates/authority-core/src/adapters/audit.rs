//! The authority plane's operational audit stream (OP-39, OP-44, U53, PI-4, §17.6.11): every
//! protocol rejection, every audit-depth explanation and every export is written as one row,
//! never sampled, before the answer leaves. A row that cannot be written turns the answer into
//! `unavailable`; an audit read is never answered unaudited. The checkpointer integrates the
//! stream into its own chain, apart from the identity audit log.

use access_authority_sequencer::ports::Clock;
use access_kernel::json::b64url_encode;
use access_store::authority::domain_tenant;
use access_store::operational::{OperationalEvent, record_operational};
use access_store::scope::DomainId;

use crate::CoreError;
use crate::adapters::Domains;
use crate::app::export::Exported;
use crate::app::{Incoming, Response, Scope};
use crate::ports::{Binding, Keys, Salts};

/// A protocol rejection: no record, nonce not consumed (OP-39).
pub const AUDIT_EVENT_REJECTED: &str = "authority.protocol.rejected";

/// An audit-depth read of the record (OP-44).
pub const AUDIT_EVENT_READ: &str = "audit.read";

/// A Record Export Package handed out (OP-44, PI-4).
pub const AUDIT_EVENT_EXPORT: &str = "audit.export";

/// Whether `e` is a protocol rejection rather than an outcome or an outage.
#[must_use]
pub const fn is_rejection(e: &CoreError) -> bool {
    matches!(
        e,
        CoreError::Protocol(_)
            | CoreError::AasBinding(_)
            | CoreError::Ais(_)
            | CoreError::Rejected(_)
            | CoreError::Nonce
            | CoreError::Passes
            | CoreError::Limited
    )
}

/// Longest text an audit column holds.
const MAX_TEXT: usize = 200;

/// `s` as an audit column admits it (`[A-Za-z0-9_:.-]`): unchanged when it fits, else a digest
/// of it, so a caller-chosen string never fails the write or forges a value.
#[must_use]
pub fn audit_text(s: &str) -> String {
    let fits = !s.is_empty()
        && s.len() <= MAX_TEXT
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-'));
    if fits {
        s.to_owned()
    } else {
        let d = suiss_crypto::digest::context_digest("access/audit-text/v1", s.as_bytes());
        format!("h:{}", b64url_encode(&d.0))
    }
}

/// `s` as the reason column admits it (`[a-z0-9_.:-]`, up to 64), else `other`.
fn reason_text(s: &str) -> &str {
    let fits = s.len() <= 64
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b':' | b'-')
        });
    if fits { s } else { "other" }
}

/// The common `txn` of a request (OP-41): its nonce, which the record carries too.
#[must_use]
pub fn txn(inc: &Incoming) -> String {
    audit_text(&b64url_encode(&inc.request.nonce))
}

/// Who made a request: the actor's Instance once known, else the PEP.
pub(super) fn who(inc: &Incoming, instance: Option<&access_kernel::model::Id>) -> String {
    instance.map_or_else(
        || audit_text(&inc.pep),
        |i| format!("inst:{}", b64url_encode(&i.0)),
    )
}

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// Writes one operational row about `inc` (OP-44).
    pub(super) async fn operational(
        &self,
        inc: &Incoming,
        (event, actor, target, reason): (&str, &str, &str, &str),
    ) -> Result<(), CoreError> {
        let mut clock = self.setup.clock.clone();
        let now = clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let id = DomainId::from_bytes(inc.request.domain.0);
        let tenant = domain_tenant(&self.setup.sequencer, &id).await?;
        record_operational(
            &self.setup.app,
            &OperationalEvent {
                occurred_at_ms: now,
                tenant,
                domain: tenant.map(|_| inc.request.domain.0),
                event_type: event,
                actor,
                target: &audit_text(target),
                reason: reason_text(reason),
                correlation: &txn(inc),
            },
        )
        .await
        .map_err(|_| CoreError::Unavailable("audit"))
    }

    /// Passes `result` on after writing a rejection to the stream (OP-39, carry-over of OP-142):
    /// a rejection the stream cannot take is answered `unavailable`.
    pub(crate) async fn audited<T>(
        &self,
        inc: &Incoming,
        operation: &str,
        result: Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        match result {
            Err(e) if is_rejection(&e) => {
                let reason = e.reason().unwrap_or_else(|| e.code());
                self.operational(
                    inc,
                    (AUDIT_EVENT_REJECTED, &who(inc, None), operation, reason),
                )
                .await?;
                Err(e)
            }
            other => other,
        }
    }

    /// Explains the recorded decision at `record`; at audit scope the read is written to the
    /// stream before the answer leaves (U53, OP-44).
    ///
    /// # Errors
    /// As [`crate::app::Authority::explain_recorded`]; [`CoreError::Unavailable`] `audit` when
    /// the read cannot be audited.
    pub async fn explain_recorded(
        &self,
        inc: &Incoming,
        record: u64,
        scope: Scope,
    ) -> Result<Response, CoreError> {
        let result = self.explain_led(inc, record, scope).await;
        let response = self.audited(inc, "explain", result).await?;
        if scope == Scope::Audit {
            self.operational(
                inc,
                (
                    AUDIT_EVENT_READ,
                    &who(inc, None),
                    &format!("record:{record}"),
                    "explain",
                ),
            )
            .await?;
        }
        Ok(response)
    }

    /// The Record Export Package of the allowed `access.audit_export` Exercise `inc` names
    /// (AP-14), written to the stream before it leaves (U53, OP-44, PI-4).
    ///
    /// # Errors
    /// As [`crate::app::Authority::export`]; [`CoreError::Unavailable`] `audit` when the export
    /// cannot be audited.
    pub async fn export(&self, inc: &Incoming) -> Result<Exported, CoreError> {
        let result = self.export_led(inc).await;
        let exported = self.audited(inc, "export", result).await?;
        let (from, to) = exported.package.range;
        self.operational(
            inc,
            (
                AUDIT_EVENT_EXPORT,
                &who(inc, Some(&exported.instance)),
                &format!("records:{from}-{to}"),
                exported.package.replay_coverage.word(),
            ),
        )
        .await?;
        Ok(exported)
    }

    async fn export_led(&self, inc: &Incoming) -> Result<Exported, CoreError> {
        let mut guard = self.leading(inc.request.domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let result = led.core.export(inc, now).await;
        if matches!(result, Err(CoreError::Sequencer(_) | CoreError::Store(_))) {
            *guard = None;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-39, OP-44: a caller-chosen string never fails the audit write and never forges a column
    #[test]
    fn audit_text_fits_the_columns() {
        assert_eq!(audit_text("pep.example"), "pep.example");
        let odd = audit_text("https://pep.example/a b");
        assert!(odd.starts_with("h:") && odd.len() <= MAX_TEXT);
        assert_eq!(audit_text(&"x".repeat(201)).len(), 45);
        assert_eq!(reason_text("ais-signature"), "ais-signature");
        assert_eq!(reason_text("Bad Reason"), "other");
    }
}
