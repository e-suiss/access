//! `POST /register` (RFC 7591) under the realm's DCR profile (OP-154 m.3 (j), §11.4.5 #31-35):
//! open only while the decided policy is, and only with an initial access token it names; limited
//! per IP prefix, per realm and in live clients; and the DCR clients' resolution, which retires a
//! client the policy no longer admits or that went unused for 30 days (OP-73: nothing is deleted).

use std::net::IpAddr;

use access_kernel::json::b64url_encode;
use access_store::dcr::{DcrClientRow, DcrPolicyRow, NewDcrClient};
use serde_json::json;

use super::{Env, OAuth, Realm, Reply};
use crate::domain::cimd::{self, redirect_hosts};
use crate::domain::client::{CimdFacts, Client, TrustLevel};
use crate::domain::dcr::{
    self, CLIENT_PREFIX, DcrPolicy, MAX_LIVE, PER_PREFIX_PER_HOUR, PER_REALM_PER_DAY, UNUSED_MS,
};
use crate::ports::Unavailable;
use crate::ports::oauth::{OAuthDb, OAuthTx};

/// The prefix a registration's rate is counted by: the /24 of an IPv4 address, the /56 of an
/// IPv6 one.
#[must_use]
pub fn ip_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v) => {
            let [first, second, third, fourth, ..] = v.segments();
            format!("{first:x}:{second:x}:{third:x}:{:x}::/56", fourth & 0xff00)
        }
    }
}

const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;

/// The decided policy as the domain reads it.
#[must_use]
pub fn policy_of(row: &DcrPolicyRow) -> DcrPolicy {
    DcrPolicy {
        enabled: row.enabled,
        domains: row.domains.iter().cloned().collect(),
        tokens: row.tokens.iter().copied().collect(),
    }
}

fn refused(status: u16, error: &str, description: &str) -> Reply {
    Reply::oauth_error(status, error, description)
}

fn bearer(authorization: Option<&str>) -> Option<&str> {
    let (scheme, token) = authorization?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && token.len() <= 512)
        .then_some(token.trim())
}

/// The client a live DCR registration describes; `None` when its metadata no longer checks.
#[must_use]
pub fn of_dcr(row: &DcrClientRow) -> Option<Client> {
    let doc = cimd::parse(&row.metadata, &row.client_id).ok()?;
    let facts = CimdFacts {
        metadata_hash: suiss_crypto::digest::sha256(&row.metadata),
        first_seen_ms: row.registered_ms,
        visual_changed_ms: None,
        logo: false,
        native: doc.application_type == cimd::ApplicationType::Native,
    };
    let mut c = Client::from_cimd(row.client_uuid, &doc, facts);
    c.trust = TrustLevel::Dcr;
    Some(c)
}

impl<E: Env> OAuth<E> {
    /// `POST /register` for `realm` from `peer` (RFC 7591 §3).
    pub async fn register_client(
        &self,
        realm: &Realm,
        authorization: Option<&str>,
        body: &[u8],
        peer: Option<IpAddr>,
    ) -> Reply {
        match self.register_inner(realm, authorization, body, peer).await {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    async fn register_inner(
        &self,
        realm: &Realm,
        authorization: Option<&str>,
        body: &[u8],
        peer: Option<IpAddr>,
    ) -> Result<Reply, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let policy = policy_of(&tx.dcr_policy().await?);
        // §10.1.2
        if !policy.enabled {
            return Ok(Reply::NotFound);
        }
        // §10.1.2, OP-154 m.3 (j)
        let Some(token) = bearer(authorization) else {
            return Ok(refused(
                401,
                "invalid_token",
                "an initial access token is required",
            ));
        };
        let digest = suiss_crypto::digest::sha256(token.as_bytes());
        if !policy.tokens.contains(&digest) {
            return Ok(refused(
                401,
                "invalid_token",
                "the initial access token is not accepted",
            ));
        }
        // §11.4.5
        let prefix = peer.map_or_else(|| String::from("unknown"), ip_prefix);
        let (ip, day, live) = tx
            .dcr_counts(
                &prefix,
                now.saturating_sub(HOUR_MS),
                now.saturating_sub(DAY_MS),
            )
            .await?;
        if ip >= PER_PREFIX_PER_HOUR || day >= PER_REALM_PER_DAY || live >= MAX_LIVE {
            return Ok(Reply::Problem {
                status: 429,
                code: "registration-limited",
            });
        }
        let client_id = format!("{CLIENT_PREFIX}{}", b64url_encode(&self.random::<32>()?));
        let (metadata, doc) = match dcr::register(body, &client_id) {
            Ok(m) => m,
            Err(e) => return Ok(refused(400, e.code(), e.description())),
        };
        // §11.4.5
        if !policy.admits(&digest, &redirect_hosts(&doc.redirect_uris)) {
            return Ok(refused(
                400,
                dcr::Refused::RedirectUri.code(),
                "a redirect host is outside the realm's registration policy",
            ));
        }
        tx.insert_dcr_client(&NewDcrClient {
            client_id: &client_id,
            metadata: &metadata,
            issuer: realm.issuer.as_str(),
            token: digest,
            ip_prefix: &prefix,
            now_ms: now,
        })
        .await?;
        tx.commit().await?;
        let native = doc.application_type == cimd::ApplicationType::Native;
        Ok(Reply::Json {
            status: 201,
            body: json!({
                "client_id": client_id,
                "client_id_issued_at": now / 1000,
                "client_name": doc.client_name,
                "redirect_uris": doc.redirect_uris,
                "application_type": if native { "native" } else { "web" },
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                // §11.4.5
                "issuer": realm.issuer.as_str(),
            })
            .to_string(),
            dpop_nonce: None,
            challenge: None,
        })
    }

    /// The live DCR client `client_id` (IDP-1): a client the policy no longer admits, or one
    /// unused for 30 days, retires now and resolves to nothing.
    pub(crate) async fn dcr_client_of(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        client_id: &str,
    ) -> Result<Option<Client>, Unavailable> {
        let Some(row) = tx.dcr_client(client_id).await? else {
            return Ok(None);
        };
        let now = self.now()?;
        let Some(client) = of_dcr(&row) else {
            return Ok(None);
        };
        let policy = policy_of(&tx.dcr_policy().await?);
        // §11.4.5
        let reason = if !policy.admits(&row.token, &redirect_hosts(&client.redirect_uris)) {
            Some("policy")
        } else if row.last_used_ms.saturating_add(UNUSED_MS) < now {
            Some("unused")
        } else {
            None
        };
        if let Some(r) = reason {
            tx.retire_dcr_client(row.client_uuid, r, now).await?;
            return Ok(None);
        }
        tx.touch_dcr_client(row.client_uuid, now).await?;
        Ok(Some(client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // §11.4.5
    #[test]
    fn registrations_are_counted_by_network_prefix() {
        assert_eq!(ip_prefix("192.0.2.77".parse().unwrap()), "192.0.2.0/24");
        assert_eq!(
            ip_prefix("2001:db8:1:2ff::1".parse().unwrap()),
            "2001:db8:1:200::/56"
        );
    }
}
