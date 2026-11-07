//! TN-135, OP-151 m.3 (j), MD-8, MUST-NEVER-18: the `token_issuance` hook at the realm's token
//! endpoint. Real PostgreSQL, real identity signer; the hook is scripted.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "support/mod.rs"]
mod support;

use access_identity_hooks::domain::{Outcome, Refusal};
use access_identity_oauth::app::oauth::Reply;
use serde_json::{Map, Value};
use support::{Cluster, body, claims};

// TN-135, MUST-NEVER-18: a token_issuance hook adds identity claims to the ID token, never to
// the access token, and never over a claim the token already has
#[tokio::test]
async fn tn_135_token_issuance_hook_adds_identity_claims() {
    let c = Cluster::new(&["hookclaims"]).await;
    let at = c.at(0);
    let mut extra = Map::new();
    extra.insert("tier".into(), Value::from("gold"));
    extra.insert("sid".into(), Value::from("forged"));
    *c.env().hooks.0.lock().unwrap() = Some(Outcome::Proceed { claims: extra });
    let t = at.tokens().await;
    let id = claims(t["id_token"].as_str().unwrap());
    assert_eq!(id["tier"], "gold");
    assert_ne!(id["sid"], "forged");
    let access = claims(t["access_token"].as_str().unwrap());
    assert!(
        access.get("tier").is_none(),
        "the access token is untouched"
    );
}

// TN-135, MD-8: a token_issuance hook that fails (and was not registered to continue) means no
// token is issued; the code stays unspent for a retry
#[tokio::test]
async fn md_8_a_failing_token_hook_issues_no_token() {
    let c = Cluster::new(&["hookfail"]).await;
    let at = c.at(0);
    *c.env().hooks.0.lock().unwrap() = Some(Outcome::Refused(Refusal::Unanswered));
    let code = at.code(&at.f.public).await;
    assert!(matches!(at.exchange(&code).await, Reply::Unavailable));
    *c.env().hooks.0.lock().unwrap() = None;
    let t = body(&at.exchange(&code).await, 200);
    assert!(t["id_token"].is_string());
}
