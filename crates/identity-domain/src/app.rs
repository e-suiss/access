//! Custom domain use cases (OP-156 m.3 (i)): one ACME issuance, and the pass that checks a
//! realm's registrations, issues the certificates of verified ones and renews them.

pub mod acme;
pub mod pass;
