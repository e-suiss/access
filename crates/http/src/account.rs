//! The account BFF (OP-153 m.3 (w), m.8 (e)): the realm's `/account` pages on its public
//! listener, realm-branded, over the hosted login session they reuse. The built app is served
//! at `/account` (or `/realms/{slug}/account` for a path issuer), its API under `…/account/api/`.
//!
//! # What the cookie can and cannot do
//!
//! The hosted login session cookie carries the Account section (S11): who am I, my session and
//! the Frontend API's own privacy screens. It authorises no authority read and no write
//! (TN-128, MD-14):
//!
//! - the session registers a **device Instance**: a non-extractable key generated in the
//!   browser opens its own Instance through its self-signed `instance_create` (and, for an
//!   account without a Party, `party_register`) Exercise, after the session stepped up
//!   (OP-149 m.6, OP-151 m.3 (e));
//! - a **hub read** (`/account/api/proxy/adp/search/{inventory|activity|changes|revocation-impact}`
//!   and `explain`) is forwarded only with an AIS by the session's device Instance, for the
//!   session's domain (TN-128, OP-153 m.8 (a));
//! - the **write** (`/account/api/proxy/adp/evaluation`) is forwarded only as a `commit` whose
//!   AIS the session's device Instance signed; the authority plane commits it as that
//!   Instance's Exercise (TN-110). The BFF never signs;
//! - `/account/api/intents` drafts the intent a screen asks for, for a read proof by the same
//!   key (PI-7).
//!
//! A stolen cookie, without the browser's key, can therefore neither read nor change authority.
//! Every state-changing call names the realm's own origin and carries the session's CSRF token
//! (TN-131). A store failure answers `503`; nothing is passed through (fail closed).

pub mod domain;

mod app;

pub use app::router;
