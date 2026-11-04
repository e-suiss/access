//! Delivery rules free of I/O (OP-63): the event catalog and payloads, the SET and
//! `CloudEvents` forms, streams and their channels, and how a receiver's answer is read.

pub mod catalog;
pub mod set;
pub mod stream;

/// A request body or value outside the contract; the code is the RFC 9457 reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid: {0}")]
pub struct Invalid(pub &'static str);
