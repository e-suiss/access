//! Product twin kit (OP-156 m.2 Q1, §7.9.10.3, E16, E24, PI-14): the Generic Domain Product
//! contract as a library a test, or a third party, builds a product with. A twin is built on the
//! public crates alone (`esuiss-access-kernel`, `esuiss-access-sdk`, `esuiss-crypto`) and reaches
//! Access only over its public listener ([`wire::ENDPOINTS`]).
//!
//! A product publishes its action namespace and typed schemas ([`schema`]), owns its domain
//! truth, issues predicate, lifecycle and effect Claims as its own issuer, is the PEP of its
//! own effects and asks Access before each one ([`twin`]). It never writes an Anchor, a Grant or
//! an Acceptance: its only effect on authority is a Claim a domain chose to accept.

pub mod schema;
pub mod twin;
pub mod wire;

pub use schema::Schema;
pub use twin::{
    Attempt, Config, Issue, Issued, Keys, Paired, Proof, Published, Random, Request, Signed, Twin,
    TwinError,
};
pub use wire::{Call, Method, Wire};
