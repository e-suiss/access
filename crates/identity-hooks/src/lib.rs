//! Inline hooks of the identity plane (TN-135, OP-151 m.3 (j), F23).
//!
//! At three call points Access calls the tenant's registered HTTPS endpoint with a request
//! signed per Standard Webhooks (the Suiss webhook profile, `v1a` Ed25519 by default). The
//! tenant's code runs on the tenant's server, never in the Access process.
//!
//! | Call point | The answer may | Body |
//! |---|---|---|
//! | `pre_registration` | refuse the registration | `{"decision": "allow" \| "deny", "reason_code"?}` |
//! | `token_issuance` | add identity claims to the ID token | `{"claims": {…}}` |
//! | `post_login` | refuse the sign-in | `{"decision": "allow" \| "deny", "reason_code"?}` |
//!
//! - A claim name matches `^[a-z][a-z0-9_]{0,63}$` and is never a reserved protocol claim
//!   (must-never #18) nor an authority claim (OP-150 m.11 (e)); a hook's claim is identity
//!   data, it never carries authority (INV-12). One bad name drops the whole answer.
//! - The request carries pseudonymous ids only; an e-mail address only when the registration
//!   declares `disclose: ["email"]` and the realm allows it.
//! - Fail-closed (MD-8): a timeout (3 s), an unreachable endpoint, a non-`2xx` answer or an
//!   answer outside its schema refuses. Only a `token_issuance` hook registered with
//!   `on_no_answer = "continue_without_claims"` lets a missing answer through, without claims;
//!   a schema violation refuses even then.
//! - Registration is realm configuration: `idp.hook.register` and `idp.hook.retire` (CT2,
//!   MD-14). A URL change is a new registration. When no hook is registered nothing changes.

pub mod actions;
pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
