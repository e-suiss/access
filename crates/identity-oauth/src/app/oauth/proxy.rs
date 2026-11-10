//! The authorization server's part of forward-auth (IDP-30 (1), (3), OP-156 m.3 (l)): the
//! proxy's browser session rides on an ordinary OAuth grant of the registration's client, opened
//! by redeeming its authorization code once with the PKCE verifier Access kept for it; no token
//! leaves Access. The grant ends with its login session, its subject's epoch or a revocation,
//! and the proxy session with it. The application token is an ES256 `access-app+jwt` of 60 s
//! under the realm JOSE key, with the client's pairwise `sub` (MD-10).

use access_kernel::json::b64url_encode;
use serde_json::json;

use super::{OAuth, Realm, code_digest, decode32, from_day, session_live, signed, unsigned};
use crate::app::oauth::Env;
use crate::domain::client::Client;
use crate::domain::metadata::Endpoint;
use crate::domain::tokens::{CodeDetails, GrantDetails};
use crate::ports::Unavailable;
use crate::ports::oauth::{OAuthTx, TokenSigner as _};
use access_crypto::jose::JwsAlg;
use access_crypto::oauth::pkce_matches;
use access_store::oauth::NewGrant;

/// The application token `typ` (OP-156 m.3 (l)).
pub const APP_TYP: &str = "access-app+jwt";

/// The application token's lifetime, seconds (OP-156 m.3 (l)).
pub const APP_TTL_S: u64 = 60;

/// A redeemed proxy sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyGrant {
    /// The grant's session id.
    pub sid: [u8; 16],
    /// When the grant ends with its login session, ms.
    pub expires_ms: u64,
}

/// Who a live proxy grant is now; its `Debug` shows no identifier of the person (OP-64).
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyHolder {
    /// The account.
    pub subject: [u8; 16],
    /// The Party it is bound to, once bound.
    pub party: Option<[u8; 16]>,
    /// The realm's governing domain.
    pub domain: [u8; 32],
    /// When the grant ends, ms.
    pub expires_ms: u64,
    /// The client's pairwise `sub`.
    pub sub: String,
    /// The verified e-mail the client may read, if any.
    pub email: Option<String>,
}

impl core::fmt::Debug for ProxyHolder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProxyHolder")
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

fn verifier_ok(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'))
}

impl<E: Env> OAuth<E> {
    /// The live realm with slug `slug`.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn realm_by_slug(&self, slug: &str) -> Result<Option<Realm>, Unavailable> {
        crate::ports::Directory::by_slug(self.env.directory(), slug).await
    }

    /// The realm's authorization endpoint.
    #[must_use]
    pub fn authorize_endpoint(realm: &Realm) -> String {
        realm.issuer.endpoint(Endpoint::Authorize.path())
    }

    async fn proxy_client(
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        client_id: &str,
    ) -> Result<Option<Client>, Unavailable> {
        Ok(tx.client(client_id).await?.and_then(Client::from_row))
    }

    /// Redeems the authorization code `code` of client `client_id` for `redirect_uri` once with
    /// its PKCE `verifier` (RFC 6749 §4.1.3, RFC 7636 §4.6), as a proxy sign-in: a code of
    /// another client, URI or verifier, bound to a DPoP key or carrying authority, used or
    /// expired, or of an ended login session opens nothing. A second redemption revokes the
    /// first one's grant (§11.4.5 #20).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn proxy_redeem(
        &self,
        realm: &Realm,
        client_id: &str,
        redirect_uri: &str,
        (code, verifier): (&str, &str),
    ) -> Result<Option<ProxyGrant>, Unavailable> {
        let now = self.now()?;
        let Some(code) = decode32(code) else {
            return Ok(None);
        };
        if !verifier_ok(verifier) {
            return Ok(None);
        }
        let mut tx = self.begin(realm).await?;
        let Some(client) = Self::proxy_client(&mut tx, client_id).await? else {
            return Ok(None);
        };
        let hash = code_digest(&code);
        let Some(row) = tx.code(from_day(now), &hash).await? else {
            return Ok(None);
        };
        if row.client != client.uuid {
            return Ok(None);
        }
        if let Some(issued) = row.grant {
            tx.revoke_grant(issued, signed(now), "code_reuse").await?;
            tx.commit().await?;
            return Ok(None);
        }
        if unsigned(row.expires_ms) <= now {
            return Ok(None);
        }
        let details: CodeDetails = serde_json::from_slice(&row.details).map_err(|_| Unavailable)?;
        // IDP-7, CR-39
        if details.redirect_uri != redirect_uri
            || !pkce_matches(&details.code_challenge, verifier)
            || details.dpop_jkt.is_some()
            || details.grant.authority.is_some()
        {
            return Ok(None);
        }
        // G57
        let Some(session) = tx
            .session(row.session)
            .await?
            .filter(|s| session_live(s, now))
        else {
            return Ok(None);
        };
        let sid = self.random::<16>()?;
        let encoded = serde_json::to_vec(&details.grant).map_err(|_| Unavailable)?;
        let grant = tx
            .insert_grant(&NewGrant {
                sid,
                client: client.uuid,
                subject: session.subject,
                session: session.id,
                session_epoch: session.session_epoch,
                dpop_jkt: None,
                details: &encoded,
                created_ms: signed(now),
                expires_ms: session.expires_ms,
            })
            .await?;
        if !tx.redeem_code(row.day, &hash, signed(now), grant).await? {
            return Ok(None);
        }
        super::token::presented(&mut tx, grant, session.subject, now).await?;
        // OP-156 m.3 (l)
        tx.audit("proxy.sign_in", &client.id, &b64url_encode(&sid), "-")
            .await?;
        tx.commit().await?;
        Ok(Some(ProxyGrant {
            sid,
            expires_ms: unsigned(session.expires_ms),
        }))
    }

    /// Who the proxy grant `sid` of client `client_id` is now; `None` once the grant, its login
    /// session or its client ended.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn proxy_holder(
        &self,
        realm: &Realm,
        client_id: &str,
        sid: &[u8; 16],
    ) -> Result<Option<ProxyHolder>, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let Some(client) = Self::proxy_client(&mut tx, client_id).await? else {
            return Ok(None);
        };
        let Some(grant) = self
            .live_grant(&mut tx, sid, now)
            .await?
            .filter(|g| g.client == client.uuid)
        else {
            return Ok(None);
        };
        let party = tx.subject_party(grant.subject).await?;
        let domain = tx.governing().await?.ok_or(Unavailable)?;
        let sub = self
            .pairwise(&mut tx, grant.subject, client.sector())
            .await?;
        tx.commit().await?;
        let details: GrantDetails =
            serde_json::from_slice(&grant.details).map_err(|_| Unavailable)?;
        let claims = self
            .released(
                realm,
                &client,
                &details,
                grant.subject,
                crate::domain::claims_request::Target::Userinfo,
            )
            .await?;
        let email = claims
            .get("email_verified")
            .and_then(serde_json::Value::as_bool)
            .filter(|v| *v)
            .and_then(|_| claims.get("email"))
            .and_then(serde_json::Value::as_str)
            .map(String::from);
        Ok(Some(ProxyHolder {
            subject: grant.subject,
            party,
            domain,
            expires_ms: unsigned(grant.expires_ms),
            sub,
            email,
        }))
    }

    /// The application token of `subject` for `audience` and decision `decision` (OP-156 m.3
    /// (l)): ES256 under the realm JOSE key, `typ: access-app+jwt`, 60 s, the pairwise `sub` of
    /// `client_id`. A realm whose JOSE algorithm is not ES256 signs none.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn app_token(
        &self,
        realm: &Realm,
        client_id: &str,
        sub: &str,
        (audience, decision): (&str, &str),
    ) -> Result<String, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let alg = tx.jose_alg().await?;
        let known = Self::proxy_client(&mut tx, client_id).await?.is_some();
        tx.commit().await?;
        if alg != JwsAlg::Es256 || !known {
            return Err(Unavailable);
        }
        let iat = now / 1000;
        let claims = json!({
            "iss": realm.issuer.as_str(),
            "sub": sub,
            "aud": audience,
            "iat": iat,
            "exp": iat.saturating_add(APP_TTL_S),
            "jti": b64url_encode(&self.random::<16>()?),
            "decision": decision,
        });
        let payload = serde_json::to_vec(&claims).map_err(|_| Unavailable)?;
        self.env
            .signer()
            .sign(realm.realm, JwsAlg::Es256, APP_TYP, &payload, now)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::verifier_ok;

    // RFC 7636 §4.1, IDP-7
    #[test]
    fn a_verifier_is_43_to_128_unreserved_characters() {
        assert!(verifier_ok(&"a".repeat(43)));
        assert!(verifier_ok(&"a".repeat(128)));
        assert!(!verifier_ok(&"a".repeat(42)));
        assert!(!verifier_ok(&"a".repeat(129)));
        assert!(!verifier_ok(&format!("{}+", "a".repeat(43))));
    }
}
