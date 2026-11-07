//! The console's Backend-for-Frontend (TN-128–TN-131, OP-151 m.2 M3, m.3 (b), (e), (f)), served
//! on the management listener under `/console/*`, an origin of its own apart from every realm's
//! login pages.
//!
//! # What the cookie can and cannot do
//!
//! The console session cookie (`__Host-access-console`, `Secure`, `HttpOnly`,
//! `SameSite=Strict`, 12 hours absolute, 15 minutes idle, bound to the client's network) carries
//! navigation and the identity plane's own, authority-free screens: who am I, my profile, my
//! sessions and revoking one of them. It authorises no authority read and no write (TN-128,
//! MD-14):
//!
//! - a **write** through `/console/api/proxy/admin/*` passes on the AIS the browser signed with
//!   the session's device Instance key (non-extractable, in the browser) and nothing else; the
//!   management API verifies it and compiles the write into an Exercise (TN-110);
//! - a **read** through the same proxy must carry a read proof: an AIS in `check` mode (CT0) by
//!   the session's device Instance over this very request. Only then does the BFF present the
//!   session's management read token, which is issued to that Instance, lives at most 60
//!   minutes, carries `realm.read` only and is bound to a DPoP key the BFF holds for the
//!   session. The token authorises CT0 reads only, so the BFF is not an authority holder;
//! - `/console/api/proxy/adp/*` (explain, search, eligibility) passes the body on as the browser
//!   wrote it: with the browser's AIS the reader is the user's Instance, without it the reader
//!   is `Anonymous` and sees Public only.
//! - `/console/api/proxy/adp/evaluation` and `audit/export` pass on only a `commit` whose AIS
//!   the session's device Instance signed; the authority plane commits it as that Instance's
//!   Exercise (OP-151 m.19);
//! - `/console/api/intents` drafts the intent a screen asks for, for a read proof (PI-7).
//!
//! A stolen cookie, without the browser's key, can therefore neither write nor read authority
//! state. A session store failure answers `503`; nothing is ever passed through (fail closed).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod drafts;
pub mod ports;

pub use app::{Console, router};
