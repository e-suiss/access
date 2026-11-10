//! First-contact tokens on the Frontend API (E58, OP-156 m.3 (z), Ek B 4495): the realm's
//! RFC 9578 issuer directory, public, and the signed-in person's blind token issuance. A token
//! names nobody and produces no authority; Relay verifies and spends it.

use access_identity_account::AccountError;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::Actor;
use access_identity_account::app::first_contact::{self, DAILY_LIMIT, Refused, TokenRequest};
use access_identity_account::domain::login::Problem;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::ports::Clock;
use access_kernel::json::{b64url_decode, b64url_encode};
use serde::Deserialize;
use serde_json::json;

use super::{Browser, Hosted, Reply};
use crate::ports::{Kits, Messages};

/// A token request as the Frontend API takes it (`first-contact-request`, base64url bytes).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequestBody {
    /// `2`.
    pub token_type: u16,
    /// The last byte of the key's `token_key_id`.
    pub truncated_key_id: u8,
    /// The blinded message, base64url.
    pub blinded_msg: String,
}

const BAD_REQUEST: Problem = Problem {
    status: 400,
    code: "invalid-token-request",
    title: "That token request isn't a type 2 request for this issuer",
    retry_after_s: None,
};

const UNKNOWN_KEY: Problem = Problem {
    status: 400,
    code: "token-key-unknown",
    title: "The request names a key that isn't the current one. Read the directory again.",
    retry_after_s: None,
};

const LIMIT: Problem = Problem {
    status: 429,
    code: "first-contact-limit",
    title: "This account has had its first-contact tokens for today",
    retry_after_s: Some(3600),
};

const INACTIVE: Problem = Problem {
    status: 403,
    code: "account-inactive",
    title: "This account can't sign in right now",
    retry_after_s: None,
};

fn unavailable() -> Reply {
    Reply::problem(Problem {
        status: 503,
        code: "unavailable",
        title: "Temporarily unavailable",
        retry_after_s: Some(1),
    })
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// `GET /v1/first-contact/keys`: the RFC 9578 §4 issuer directory of the realm, the
    /// current key first.
    pub async fn first_contact_keys(&self, entry: &RealmEntry) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let realm = kit.realm();
        let read = async {
            let mut tx = PgAccounts::sealed(self.db.clone(), kit.vault())
                .begin(kit.tenant, kit.realm)
                .await?;
            let keys = first_contact::directory(&mut tx, &realm).await?;
            tx.commit().await?;
            Ok::<_, AccountError>(keys)
        };
        let Ok(keys) = read.await else {
            return unavailable();
        };
        let keys: Vec<_> = keys
            .iter()
            .map(|k| {
                json!({
                    "token-type": first_contact::TOKEN_TYPE,
                    "token-key": b64url_encode(&k.token_key),
                    "not-before": k.not_before_ms / 1000,
                })
            })
            .collect();
        Reply::json(
            200,
            json!({
                "issuer-request-uri": "tokens",
                "token-keys": keys,
                "daily-limit": DAILY_LIMIT,
            }),
        )
    }

    /// `POST /v1/first-contact/tokens`: one blind signature for the signed-in person, at most
    /// [`DAILY_LIMIT`] a day (E58).
    pub async fn issue_first_contact_token(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &TokenRequestBody,
    ) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let Some(blinded_msg) = b64url_decode(&body.blinded_msg).ok() else {
            return Reply::problem(BAD_REQUEST);
        };
        let request = TokenRequest {
            token_type: body.token_type,
            truncated_key_id: body.truncated_key_id,
            blinded_msg,
        };
        let realm = kit.realm();
        let Ok(actor) = realm.external(me) else {
            return unavailable();
        };
        let who = Actor {
            actor: &actor,
            correlation: b.correlation,
        };
        let made = async {
            let mut tx = PgAccounts::sealed(self.db.clone(), kit.vault())
                .begin(kit.tenant, kit.realm)
                .await?;
            let out = first_contact::issue(&mut tx, &realm, me, &request, &who).await?;
            tx.commit().await?;
            Ok::<_, AccountError>(out)
        };
        match made.await {
            Ok(Ok(sig)) => Reply::json(200, json!({ "blind_sig": b64url_encode(&sig) })),
            Ok(Err(Refused::Request)) => Reply::problem(BAD_REQUEST),
            Ok(Err(Refused::Key)) => Reply::problem(UNKNOWN_KEY),
            Ok(Err(Refused::Limit)) => Reply::problem(LIMIT),
            Ok(Err(Refused::Inactive)) => Reply::problem(INACTIVE),
            Err(_) => unavailable(),
        }
    }
}
