//! The experience rules without I/O (OP-63): the search reads a hub needs, the rows it renders
//! from the domains' answers (§6.4 XI-1…XI-22, §8.17.7), the honest outcome of an
//! authority-changing request (§8.13, G39) and the status ladder (XI-2).

pub mod honesty;
pub mod hub;
pub mod ladder;
pub mod plan;
pub mod texts;

/// A malformed request or answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed {0}")]
pub struct Malformed(pub &'static str);
