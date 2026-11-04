//! Event delivery of the identity plane (MD-13, OP-149 m.4, m.7, §9.16).
//!
//! - Sources: the identity outbox (tenant, organization and API client events, suspensions)
//!   and each domain's authority outbox (the §9.16 semantic events).
//! - A fan-out step turns each event into one unsigned SET per matching subscription and
//!   queues it; the event id is the dedup key, so a repeated step queues nothing twice.
//! - Each subscription has one channel: the Suiss webhook profile (`CloudEvents` 1.0 structured
//!   JSON signed per Standard Webhooks), SSF push (RFC 8935) or SSF poll (RFC 8936).
//! - Push delivery is at least once with backoff, per delivery, so a dead endpoint delays only
//!   its own events. Every endpoint is reached through the SSRF-guarded outbound client.
//! - Delivery is best effort and never a security input: a receiver re-queries (PI-9, §9.16.2).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

pub use access_identity_oauth::ports::Unavailable;
