//! PEP conformance harness (CMP-17, X21, TI-9, OP-150 m.1 (a)): fault cases, fake
//! upstreams (ADP, AS introspection, JWKS, status list) and a language-independent
//! JSON-lines adapter protocol. A PEP under test passes when no fault produces an effect.

pub mod case;
pub mod fixture;
pub mod profile;
pub mod protocol;
pub mod reference;
pub mod run;
pub mod sdk;
pub mod sut;
pub mod upstream;
pub mod verdict;
