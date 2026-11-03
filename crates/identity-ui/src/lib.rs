//! The login node contract and the hosted login surface (CMP-15.6).
//!
//! The server answers every login step with a typed [`domain::flow::Ui`]: what is still
//! required, which fields and buttons the step offers, and messages with stable ids. Clients
//! (the hosted login in `web/login`, embedded components, a tenant's own screens) draw it in
//! any order and layout; the server checks what comes back against the step it issued
//! (TN-106, TN-132, X40).

pub mod app;
pub mod domain;
pub mod ports;
