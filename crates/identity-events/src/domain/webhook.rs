//! Webhook registrations and their delivery rules, free of I/O (TN-136, OP-151 m.3 (i), E42).
//!
//! - A webhook is realm configuration: `idp.webhook.register`, `idp.webhook.update`,
//!   `idp.webhook.retire` (MD-14). Its URL is `https` on a DNS name; private targets are
//!   refused unless the realm allows them (§14.3).
//! - Every delivery is the Suiss webhook profile shared with Relay: a `CloudEvents` 1.0
//!   structured JSON body signed per Standard Webhooks, `v1a` Ed25519 by default, `v1` HMAC for
//!   compatibility. A rotated key keeps signing beside the new one for
//!   [`ROTATION_OVERLAP_MS`].
//! - At least once: a delivery is retried with exponential backoff from [`FIRST_RETRY_MS`] up to
//!   [`MAX_RETRY_MS`] between attempts, for [`GIVE_UP_AFTER_MS`], then it is `exhausted`. The
//!   receiver answers `2xx` within [`DELIVERY_TIMEOUT_MS`]. There is no ordering guarantee: a
//!   receiver orders by the event's `time` and deduplicates by `webhook-id`.
//! - A webhook is a notification, never an authority source: a lost or late delivery changes no
//!   decision (INV-24).

use access_identity_hooks::actions::ExtensionAction;
use access_identity_hooks::domain::{Signing, change_intent, check_target, uuid};
use access_kernel::model::Window;
use suiss_crypto::dcbor::Value as Cbor;

use crate::domain::Invalid;
use crate::domain::catalog::{IdentityKind, subscribable};

/// The first retry waits this long, ms (OP-151 m.3 (i)).
pub const FIRST_RETRY_MS: u64 = 60_000;

/// No wait between attempts is longer, ms.
pub const MAX_RETRY_MS: u64 = 86_400_000;

/// A delivery is given up this long after it was queued, ms.
pub const GIVE_UP_AFTER_MS: u64 = 7 * 86_400_000;

/// The receiver answers within this, ms.
pub const DELIVERY_TIMEOUT_MS: u64 = 10_000;

/// A rotated key keeps signing this long beside the new one, ms.
pub const ROTATION_OVERLAP_MS: u64 = 86_400_000;

/// Most event names one webhook receives.
pub const MAX_EVENTS: usize = 64;

/// When to try again after `attempts` failed attempts of a delivery queued at `queued_ms`,
/// as of `now_ms`: `None` once the next attempt would fall past [`GIVE_UP_AFTER_MS`].
#[must_use]
pub fn next_attempt(attempts: u32, queued_ms: u64, now_ms: u64) -> Option<u64> {
    let shift = attempts.saturating_sub(1).min(20);
    let wait = FIRST_RETRY_MS
        .checked_shl(shift)
        .unwrap_or(MAX_RETRY_MS)
        .min(MAX_RETRY_MS);
    let at = now_ms.saturating_add(wait);
    (at <= queued_ms.saturating_add(GIVE_UP_AFTER_MS)).then_some(at)
}

/// A webhook as an actor registers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookSpec {
    /// The tenant's HTTPS endpoint.
    pub url: String,
    /// The event names it receives, sorted and unique.
    pub events: Vec<String>,
    /// How its deliveries are signed.
    pub signing: Signing,
}

/// The event names of a request: each an identity event of the catalogue, sorted, unique,
/// between 1 and [`MAX_EVENTS`].
///
/// # Errors
/// [`Invalid`] `events`.
pub fn event_names(names: &[String]) -> Result<Vec<String>, Invalid> {
    let mut out: Vec<String> = names.to_vec();
    out.sort();
    out.dedup();
    if out.is_empty()
        || out.len() > MAX_EVENTS
        || out
            .iter()
            .any(|n| IdentityKind::of_name(n).is_none() || !subscribable(n))
    {
        return Err(Invalid("events"));
    }
    Ok(out)
}

impl WebhookSpec {
    /// Checks the registration: a valid target and known identity events.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn check(&self, allow_private: bool) -> Result<(), Invalid> {
        check_target(&self.url, allow_private).map_err(|_| Invalid("url"))?;
        if event_names(&self.events)? != self.events {
            return Err(Invalid("events"));
        }
        Ok(())
    }
}

/// One `idp.webhook.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookChange {
    /// `idp.webhook.register` of a new webhook with this id.
    Register {
        /// Its id.
        id: [u8; 16],
        /// Its registration.
        spec: WebhookSpec,
    },
    /// `idp.webhook.update`: a new URL and events, and a key rotation when asked.
    Update {
        /// The webhook.
        id: [u8; 16],
        /// Its new URL.
        url: String,
        /// Its new events, sorted and unique.
        events: Vec<String>,
        /// Whether a new key takes over, the old one overlapping.
        rotate: bool,
    },
    /// `idp.webhook.retire`.
    Retire {
        /// The webhook.
        id: [u8; 16],
    },
}

fn names(list: &[String]) -> Cbor {
    Cbor::Array(list.iter().map(|n| Cbor::text(n)).collect())
}

impl WebhookChange {
    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> ExtensionAction {
        match self {
            Self::Register { .. } => ExtensionAction::WebhookRegister,
            Self::Update { .. } => ExtensionAction::WebhookUpdate,
            Self::Retire { .. } => ExtensionAction::WebhookRetire,
        }
    }

    /// The webhook it changes.
    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        match self {
            Self::Register { id, .. } | Self::Update { id, .. } | Self::Retire { id } => id,
        }
    }

    /// Checks the change on its own.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn check(&self, allow_private: bool) -> Result<(), Invalid> {
        match self {
            Self::Register { spec, .. } => spec.check(allow_private),
            Self::Update { url, events, .. } => WebhookSpec {
                url: url.clone(),
                events: events.clone(),
                signing: Signing::Ed25519,
            }
            .check(allow_private),
            Self::Retire { .. } => Ok(()),
        }
    }

    /// What the change digest covers.
    #[must_use]
    pub fn body(&self) -> Cbor {
        let id = Cbor::text(&uuid(self.id()));
        match self {
            Self::Register { spec, .. } => Cbor::Map(vec![
                (Cbor::text("webhook"), id),
                (Cbor::text("url"), Cbor::text(&spec.url)),
                (Cbor::text("events"), names(&spec.events)),
                (Cbor::text("signing"), Cbor::text(spec.signing.name())),
            ]),
            Self::Update {
                url,
                events,
                rotate,
                ..
            } => Cbor::Map(vec![
                (Cbor::text("webhook"), id),
                (Cbor::text("url"), Cbor::text(url)),
                (Cbor::text("events"), names(events)),
                (Cbor::text("rotate"), Cbor::Bool(*rotate)),
            ]),
            Self::Retire { .. } => Cbor::Map(vec![(Cbor::text("webhook"), id)]),
        }
    }

    /// The intent that authorizes it in realm `slug` (EI-25).
    ///
    /// # Errors
    /// [`suiss_crypto::dcbor::EncodeError`].
    pub fn intent(
        &self,
        slug: &str,
        validity: Window,
    ) -> Result<access_kernel::intent::IntentEnvelope, suiss_crypto::dcbor::EncodeError> {
        change_intent(
            self.action(),
            self.body(),
            slug,
            ["webhook", &uuid(self.id())],
            validity,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-136, OP-151 m.3 (i)
    #[test]
    fn tn_136_retry_schedule() {
        let q = 1_000_000;
        let mut now = q;
        let mut waits = Vec::new();
        let mut attempts = 0;
        while let Some(at) = next_attempt(attempts + 1, q, now) {
            waits.push(at - now);
            now = at;
            attempts += 1;
        }
        assert_eq!(waits[..4], [60_000, 120_000, 240_000, 480_000]);
        assert!(waits.iter().all(|w| *w <= MAX_RETRY_MS));
        assert_eq!(*waits.last().unwrap(), MAX_RETRY_MS);
        assert!(now <= q + GIVE_UP_AFTER_MS);
        assert!(now + MAX_RETRY_MS > q + GIVE_UP_AFTER_MS);
        assert!(attempts > 12 && attempts < 20, "{attempts}");
        assert_eq!(next_attempt(1, q, q + GIVE_UP_AFTER_MS), None);
    }

    // TN-136, §14.3
    #[test]
    fn tn_136_registrations_are_checked() {
        let ok = WebhookSpec {
            url: String::from("https://sync.shop.example/access"),
            events: vec![
                String::from("account.created"),
                String::from("session.revoked"),
            ],
            signing: Signing::Ed25519,
        };
        assert!(ok.check(false).is_ok());
        for url in [
            "http://sync.shop.example/",
            "https://10.1.2.3/",
            "https://[fd00::1]/",
            "https://localhost/",
            "https://sync.shop.example:9443/",
        ] {
            let bad = WebhookSpec {
                url: String::from(url),
                ..ok.clone()
            };
            assert_eq!(bad.check(false), Err(Invalid("url")), "{url}");
        }
        for events in [
            vec![],
            vec![String::from("authority-revoked")],
            vec![String::from("nope")],
            vec![
                String::from("session.revoked"),
                String::from("account.created"),
            ],
        ] {
            let bad = WebhookSpec {
                events,
                ..ok.clone()
            };
            assert!(bad.check(false).is_err());
        }
        assert_eq!(
            event_names(&[
                String::from("session.revoked"),
                String::from("account.created")
            ])
            .unwrap(),
            ok.events
        );
    }

    // TN-136, §12.4.2
    #[test]
    fn unproduced_events_are_not_subscribable() {
        for name in crate::domain::catalog::UNPRODUCED {
            assert!(event_names(&[String::from(name)]).is_err(), "{name}");
        }
        assert!(event_names(&[String::from("account.suspended")]).is_ok());
        // IDP-37, OP-153 m.4
        assert!(event_names(&[String::from("preference.changed")]).is_ok());
        assert!(event_names(&[String::from("document.accepted")]).is_ok());
        // OP-154 m.3 (e), SI-21
        assert!(event_names(&[String::from("agent.suspended")]).is_ok());
        assert!(event_names(&[String::from("agent.sponsor_assigned")]).is_ok());
    }

    // EI-25
    #[test]
    fn webhook_changes_name_their_action() {
        let w = Window { from: 0, until: 1 };
        let r = WebhookChange::Update {
            id: [1; 16],
            url: String::from("https://sync.shop.example/a"),
            events: vec![String::from("account.created")],
            rotate: true,
        };
        let s = WebhookChange::Update {
            id: [1; 16],
            url: String::from("https://sync.shop.example/a"),
            events: vec![String::from("account.created")],
            rotate: false,
        };
        assert_eq!(r.action().label(), "idp.webhook.update");
        assert_ne!(
            r.intent("shop", w).unwrap().opaque,
            s.intent("shop", w).unwrap().opaque
        );
        assert_eq!(
            WebhookChange::Retire { id: [1; 16] }.action().label(),
            "idp.webhook.retire"
        );
    }
}
