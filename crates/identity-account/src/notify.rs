//! The Relay seam, Access side (E42, OP-146 m.2, m.4 (b); Ek B "Relay seam"): every message
//! to a person leaves Access through Relay. Access writes the message into the identity outbox
//! in the business transaction; a courier with its own cursor (OP-131) posts it to Relay as a
//! `CloudEvent`. While Relay is unreachable messages wait in the outbox (E42 m.5). Access never
//! speaks SMTP or SMS itself.
//!
//! Layers (OP-63): [`message`], [`envelope`] and [`delivery`] are the domain; [`ports`];
//! [`notifier`] and [`courier`] the use cases; [`pg`] and [`http`] the adapters.

pub mod courier;
pub mod delivery;
pub mod envelope;
pub mod http;
pub mod message;
pub mod notifier;
pub mod pg;
pub mod ports;

use access_store::StoreError;

use crate::notify::message::Invalid;

/// Why the seam failed. A message Relay refuses is not an error but an undeliverable record
/// ([`delivery::Undeliverable`]).
#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    /// Storage failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The message breaks the contract.
    #[error(transparent)]
    Invalid(#[from] Invalid),
    /// The subject is not in the realm, or its key is gone.
    #[error("no such subject")]
    NoSubject,
    /// The realm KEK is not held by this process.
    #[error("realm key unavailable")]
    KeyUnavailable,
    /// Key wrapping or sealing failed.
    #[error("sealing failed")]
    Seal,
    /// The random source failed.
    #[error("no randomness")]
    Random,
}
