//! Social and upstream sign-in of the identity plane (CMP-15.10, IDP-31, OP-153 m.3 (l)).
//!
//! - Presets are data (`presets/*.toml`, F23): endpoints, scopes, logo, the subject claims and
//!   what the provider's e-mail address is worth.
//! - Every provider answer is checked in the back end: the ID token's signature, `iss`, `aud`,
//!   `exp` and `nonce`, or for OAuth 2.0 the user-info read with the code's own access token.
//! - An external identity is keyed by `(provider, provider_subject_id)` (P-ID-9, TN-66); an
//!   e-mail address is never a key and never links accounts (MD-5, TN-3, nOAuth).
//! - A shared development client works only in a sandbox realm (IDP-31 (4)).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
