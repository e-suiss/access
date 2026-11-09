//! The agent's side of an Access decision (§8.18, §11.16, A-1 to A-12, OP-154 m.3 (w)): an agent
//! Instance asks for one exact intent with an explicit basis and capacity, reads the answer as
//! typed planning data, and does only what that answer allows.
//!
//! - [`contract::Exercise`] is one intent under one nonce: no request without a capacity (A-1);
//!   an ALLOW holds for this envelope only (A-2); a DENY closes the nonce and a new one needs a
//!   typed change of state (A-3); a `REQUIRE_ACTION` waits on the same nonce for a proof (A-4).
//! - A proof is a recorded contribution or a Claim, never prose or an elicitation answer (A-5).
//! - [`request`] builds the typed authority request a coordinator shows; the agent's own words
//!   are the separate "Requester's note" (A-6, §8.17.5.2).
//! - Every text Access or a peer sends is [`text::Untrusted`] data, never an instruction (A-7,
//!   SI-16).
//! - [`contract::Continuation`] asks `continue` before the horizon, at checkpoints and after a
//!   pause or takeover (A-8); [`contract::Refusals`] refuses a split under a refused amount
//!   (A-9); a `check` answer is an [`contract::Advisory`] that never becomes an ALLOW (A-10).
//! - [`status`] reads the agent's own summary (A-11); [`identity`] is how the agent names itself
//!   to people (A-12).
//! - [`a2a`] carries all of this over A2A (`urn:suiss:access:a2a:authority:v1`) and reads an
//!   Agent Card as a Claim whose signer must be accepted (AG-34, AGI-7).
//!
//! The SDK does no I/O and holds no key: the decision point, the Instance key and the clock are
//! ports the caller supplies. Access does not own prompt-injection defence: injected content is
//! not prevented, only bounded by authority (§11.0 #8, L28).

pub mod a2a;
pub mod contract;
pub mod decision;
pub mod identity;
pub mod request;
pub mod status;
pub mod text;
