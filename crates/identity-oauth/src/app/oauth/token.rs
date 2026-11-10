//! `POST /token` (RFC 6749 §3.2, §4.1.3, §4.4, §6; RFC 7636 §4.6; RFC 9449 §5): the code
//! exchange, refresh rotation and client credentials. Every token request carries a DPoP proof:
//! there is no bearer access token (TN-27). A request for authority (RFC 9396
//! `authorization_details`) is a `projection.issue` decision of the authority plane (§9.9);
//! client credentials exist for it and, towards a platform product, for the identity-assertion
//! service token (OP-149 m.31 (a), m.34 (b)). An Instance's management read token is an RFC 8693
//! exchange (TN-130, see `management`). ROPC and implicit do not exist; device code is a later
//! stage (OP-146 m.6). A refused request is written to the identity audit log (OP-39).

use access_crypto::dpop::Role;
use access_crypto::oauth::pkce_matches;
use access_identity_account::domain::signal::{Initiator, Signal};
use access_kernel::digest::Digest;
use access_store::oauth::{GrantRow, NewGrant};

use super::authority::Asked;
use super::{
    Env, OAuth, Realm, Reply, code_digest, decode32, from_day, grant_live, refresh_digest,
    session_live, signed, unsigned,
};
use crate::app::dpop::DpopRequest;
use crate::domain::client::Client;
use crate::domain::dpop::{
    BindingError, Failure, Jkt, check_code_exchange, check_refresh, refresh_binding,
};
use crate::domain::fapi::Binding;
use crate::domain::metadata::{
    DEVICE_CODE_GRANT, Endpoint, Feature, JWT_BEARER_GRANT, SERVED, TOKEN_EXCHANGE_GRANT,
};
use crate::domain::request::Params;
use crate::domain::scope;
use crate::domain::tokens::{CodeDetails, GrantDetails};
use crate::ports::Unavailable;
use crate::ports::oauth::OAuthTx;

/// What a token request presents besides its form. `Debug` shows neither credential.
#[derive(Clone, Copy)]
pub struct TokenHttp<'a> {
    /// `Authorization`, when sent.
    pub authorization: Option<&'a str>,
    /// Every `DPoP` header value.
    pub dpop: &'a [&'a str],
    /// The X.509-SVID chain the connection presented, leaf first (OP-154 m.3 (r)).
    pub client_chain: &'a [Vec<u8>],
}

impl core::fmt::Debug for TokenHttp<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenHttp")
            .field("authorization", &self.authorization.map(|_| "[redacted]"))
            .field("dpop", &self.dpop.len())
            .finish()
    }
}

fn invalid_grant() -> Reply {
    Reply::oauth_error(400, "invalid_grant", "the grant is not valid")
}

fn binding_refused(e: BindingError) -> Reply {
    Reply::oauth_error(400, e.error(), "the DPoP key does not match the grant")
}

/// RFC 8707 §2.2, OP-149 m.26 (a): a `resource` sent to the token endpoint for a protocol-scope
/// grant must be the one the authorization request named, the realm itself when it named
/// none; an authority grant's resource is read with its details instead.
fn resource_matches(params: &Params, details: &GrantDetails, realm: &Realm) -> bool {
    details.authority.is_some()
        || params
            .get("resource")
            .is_none_or(|r| r == details.audience(&realm.issuer))
}

fn invalid_target() -> Reply {
    Reply::oauth_error(400, "invalid_target", "not the authorized resource")
}

/// A request value as an audit field: identifiers only (OP-10); anything else is `-`.
fn audit_text(v: Option<&str>, max: usize) -> &str {
    v.filter(|s| {
        !s.is_empty()
            && s.len() <= max
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b':' | b'.' | b'-'))
    })
    .unwrap_or("-")
}

/// TN-56, OP-153 m.3 (e): while the subject is in the grace period after a recovery, a new
/// grant gets no long-lived token: `offline_access` is withheld from its scope.
async fn withhold_offline<T: OAuthTx>(
    tx: &mut T,
    granted: &mut String,
    subject: [u8; 16],
    now: u64,
) -> Result<(), Unavailable> {
    if !granted.split(' ').any(|s| s == scope::OFFLINE_ACCESS) {
        return Ok(());
    }
    let now = i64::try_from(now).map_err(|_| Unavailable)?;
    if tx.recovery_grace_until(subject, now).await?.is_some() {
        *granted = granted
            .split(' ')
            .filter(|s| *s != scope::OFFLINE_ACCESS)
            .collect::<Vec<_>>()
            .join(" ");
    }
    Ok(())
}

/// Whether the token endpoint serves `grant_type`, and whether it is an agent grant: token
/// exchange or JWT bearer once served (OP-154 m.3 (m), (q)); otherwise the RFC 6749 §5.2
/// refusal.
fn admitted(grant_type: Option<&str>) -> Result<bool, Reply> {
    let agent = match grant_type {
        Some(TOKEN_EXCHANGE_GRANT) => SERVED.feature(Feature::TokenExchange),
        Some(JWT_BEARER_GRANT) => SERVED.feature(Feature::JwtBearer),
        // OP-155 m.3 (k)
        Some(crate::domain::metadata::SAML2_BEARER_GRANT) => SERVED.feature(Feature::SamlBearer),
        _ => false,
    };
    // OP-154 m.3 (p)
    let device = grant_type == Some(DEVICE_CODE_GRANT) && SERVED.has(Endpoint::DeviceAuthorization);
    // OP-155 m.3 (l)
    let ciba = grant_type == Some(crate::domain::metadata::CIBA_GRANT)
        && SERVED.has(Endpoint::BackchannelAuthentication);
    if agent
        || device
        || ciba
        || matches!(
            grant_type,
            Some("authorization_code" | "refresh_token" | "client_credentials")
        )
    {
        return Ok(agent);
    }
    Err(match grant_type {
        None => Reply::oauth_error(400, "invalid_request", "grant_type is required"),
        Some(_) => Reply::oauth_error(
            400,
            "unsupported_grant_type",
            "the grant type is not supported",
        ),
    })
}

fn verifier_ok(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'))
}

impl<E: Env> OAuth<E> {
    /// `POST /token`, form-encoded (§11.4.5 #19).
    pub async fn token(&self, realm: &Realm, params: &Params, http: TokenHttp<'_>) -> Reply {
        let reply = match self.token_inner(realm, params, http).await {
            Ok(r) => r,
            Err(Unavailable) => return Reply::Unavailable,
        };
        // OP-39
        if let Some(error) = super::authority::error_of(&reply)
            && self.audit_refusal(realm, params, &error).await.is_err()
        {
            return Reply::Unavailable;
        }
        reply
    }

    async fn audit_refusal(
        &self,
        realm: &Realm,
        params: &Params,
        error: &str,
    ) -> Result<(), Unavailable> {
        let mut tx = self.begin(realm).await?;
        tx.audit(
            "oauth.token.refused",
            audit_text(params.get("client_id"), 200),
            audit_text(Some(error), 200),
            audit_text(params.get("grant_type"), 128),
        )
        .await?;
        tx.commit().await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one token request, its grant types in order"
    )]
    async fn token_inner(
        &self,
        realm: &Realm,
        params: &Params,
        http: TokenHttp<'_>,
    ) -> Result<Reply, Unavailable> {
        let grant_type = params.get("grant_type");
        // TN-130, OP-151 m.3 (c)
        if grant_type == Some(crate::domain::management::TOKEN_EXCHANGE)
            && params.get("subject_token_type") == Some(crate::domain::management::AIS_TOKEN_TYPE)
        {
            return self.exchange_read(realm, params, http).await;
        }
        let agent = match admitted(grant_type) {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        // TN-35, OP-154 m.3 (dd)
        if grant_type == Some(DEVICE_CODE_GRANT) {
            let mut tx = self.begin(realm).await?;
            let on = tx.device_code_enabled().await?;
            tx.commit().await?;
            if !on {
                return Ok(Reply::oauth_error(
                    400,
                    "unsupported_grant_type",
                    "the grant type is not supported",
                ));
            }
        }
        // OP-155 m.3 (l)
        if grant_type == Some(crate::domain::metadata::CIBA_GRANT) {
            let mut tx = self.begin(realm).await?;
            let on = tx.ciba_settings().await?.enabled;
            tx.commit().await?;
            if !on {
                return Ok(Reply::oauth_error(
                    400,
                    "unsupported_grant_type",
                    "the grant type is not supported",
                ));
            }
        }
        // IDP-1, AG-4
        if self.prepare_client(realm, params).await?.is_err() {
            return Ok(Reply::oauth_error(
                401,
                "invalid_client",
                "client authentication failed",
            ));
        }
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let req = http.client_request(params);
        let client = match self.authenticate(&mut tx, realm, &req, now).await? {
            Ok(c) => c,
            Err(e) => {
                let status = if e.error() == "invalid_client" {
                    401
                } else {
                    400
                };
                return Ok(Reply::oauth_error(
                    status,
                    e.error(),
                    "client authentication failed",
                ));
            }
        };
        tx.commit().await?;
        let token_uri = realm.issuer.endpoint(Endpoint::Token.path());
        // IDP-11, TN-27
        let proof = match self
            .dpop(
                realm,
                Role::AuthorizationServer,
                &DpopRequest {
                    proofs: http.dpop,
                    method: "POST",
                    uri: &token_uri,
                    access_token: None,
                    bound: None,
                },
            )
            .await
        {
            Ok(p) => p,
            Err(Failure::Unavailable) => return Err(Unavailable),
            Err(f) => {
                // OP-155 m.3 (k), RFC 8705 §3, Ek B 5090
                if let Some(binding) = unproven_binding(&client, grant_type, http.dpop) {
                    let mut tx = self.begin(realm).await?;
                    let reply = if grant_type == Some("authorization_code") {
                        self.exchange(&mut tx, realm, &client, params, binding, now)
                            .await?
                    } else {
                        self.rotate(&mut tx, realm, &client, params, binding, now)
                            .await?
                    };
                    tx.commit().await?;
                    return Ok(reply);
                }
                let nonce = f.nonce().map(String::from);
                let reply = if http.dpop.is_empty() {
                    Reply::oauth_error(400, "invalid_dpop_proof", "a DPoP proof is required")
                } else {
                    Reply::oauth_error(400, f.error(), "the DPoP proof was not accepted")
                };
                return Ok(reply.with_nonce(nonce));
            }
        };
        if agent {
            let reply = self.agent_grant(realm, &client, params, proof.jkt, now);
            return Ok(reply.await?.with_nonce(Some(proof.nonce)));
        }
        if grant_type == Some("client_credentials") {
            // OP-149 m.31 (a), m.34 (b)
            let reply = match self.service_target(realm, &client, params).await? {
                Some(Ok(target)) => {
                    self.service_token(realm, &client, &target, proof.jkt, now)
                        .await?
                }
                Some(Err(refusal)) => refusal,
                None => {
                    self.client_credentials(realm, &client, params, proof.jkt, now)
                        .await?
                }
            };
            return Ok(reply.with_nonce(Some(proof.nonce)));
        }
        let mut tx = self.begin(realm).await?;
        let reply = if grant_type == Some(DEVICE_CODE_GRANT) {
            self.device_token(&mut tx, realm, &client, params, proof.jkt, now)
                .await?
        } else if grant_type == Some(crate::domain::metadata::CIBA_GRANT) {
            self.ciba_token(&mut tx, realm, &client, params, proof.jkt, now)
                .await?
        } else if grant_type == Some("authorization_code") {
            self.exchange(
                &mut tx,
                realm,
                &client,
                params,
                Binding::Dpop(proof.jkt),
                now,
            )
            .await?
        } else {
            self.rotate(
                &mut tx,
                realm,
                &client,
                params,
                Binding::Dpop(proof.jkt),
                now,
            )
            .await?
        };
        tx.commit().await?;
        Ok(reply.with_nonce(Some(proof.nonce)))
    }

    /// RFC 6749 §4.1.3, §11.4.5 #20: the code is redeemed once by compare-and-set; a second
    /// redemption revokes what the first one issued.
    #[expect(
        clippy::too_many_lines,
        reason = "one code redemption, its checks in order"
    )]
    async fn exchange(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        params: &Params,
        binding: Binding,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let jkt = binding.jkt();
        let Some(code) = params.get("code").and_then(decode32) else {
            return Ok(invalid_grant());
        };
        let hash = code_digest(&code);
        let Some(row) = tx.code(from_day(now), &hash).await? else {
            return Ok(invalid_grant());
        };
        if row.client != client.uuid {
            return Ok(invalid_grant());
        }
        if let Some(issued) = row.grant {
            tx.revoke_grant(issued, signed(now), "code_reuse").await?;
            return Ok(invalid_grant());
        }
        if unsigned(row.expires_ms) <= now {
            return Ok(invalid_grant());
        }
        let mut details: CodeDetails =
            serde_json::from_slice(&row.details).map_err(|_| Unavailable)?;
        // IDP-7
        if params.get("redirect_uri") != Some(details.redirect_uri.as_str()) {
            return Ok(invalid_grant());
        }
        // IDP-7, CR-39
        let verified = params
            .get("code_verifier")
            .filter(|v| verifier_ok(v))
            .is_some_and(|v| pkce_matches(&details.code_challenge, v));
        if !verified {
            return Ok(invalid_grant());
        }
        if let Err(e) = check_code_exchange(details.dpop_jkt.map(Jkt), jkt) {
            return Ok(binding_refused(e));
        }
        if !resource_matches(params, &details.grant, realm) {
            return Ok(invalid_target());
        }
        // G57
        let Some(session) = tx
            .session(row.session)
            .await?
            .filter(|s| session_live(s, now))
        else {
            return Ok(invalid_grant());
        };
        let Ok(bound) = refresh_binding(client.client_type(), jkt) else {
            return Ok(binding_refused(BindingError::ProofRequired));
        };
        // TN-56, OP-153 m.3 (e)
        withhold_offline(tx, &mut details.grant.scope, session.subject, now).await?;
        let mut grant_details = details.grant.clone();
        // OP-155 m.3 (k)
        let projected = match jkt {
            Some(jkt) => match self
                .code_projection(realm, client, params, &mut grant_details, jkt)
                .await?
            {
                Ok(p) => p,
                Err(r) => return Ok(r),
            },
            None if grant_details.authority.is_some()
                || params
                    .get(crate::domain::authority::DETAILS_PARAM)
                    .is_some() =>
            {
                return Ok(binding_refused(BindingError::ProofRequired));
            }
            None => None,
        };
        let sid = self.random::<16>()?;
        let encoded = serde_json::to_vec(&grant_details).map_err(|_| Unavailable)?;
        let grant_id = tx
            .insert_grant(&NewGrant {
                sid,
                client: client.uuid,
                subject: session.subject,
                session: session.id,
                session_epoch: session.session_epoch,
                dpop_jkt: bound.as_ref().map(|j| &j.0),
                details: &encoded,
                created_ms: signed(now),
                expires_ms: session.expires_ms,
            })
            .await?;
        if !tx
            .redeem_code(row.day, &hash, signed(now), grant_id)
            .await?
        {
            if let Some(p) = &projected {
                self.invalidate(tx, p.domain, p.token.family, &p.token.exercise, now)
                    .await?;
            }
            return Ok(invalid_grant());
        }
        let grant = presented(tx, grant_id, session.subject, now).await?;
        let nonce = details.nonce.as_deref();
        if let Some(p) = &projected {
            let body = self
                .authority_tokens(tx, realm, client, &grant, &grant_details, p, nonce, now)
                .await?;
            return Ok(Reply::json(200, &body));
        }
        let body = self
            .issue(
                tx,
                realm,
                client,
                &grant,
                &details.grant,
                &binding,
                nonce,
                now,
            )
            .await?;
        Ok(Reply::json(200, &body))
    }

    /// RFC 6749 §6, TN-31: the refresh token rotates on every use; a rotated token presented
    /// again revokes the whole grant and raises the subject's `session_epoch`. A refresh never
    /// outlives the session it came from (G57, EP-2).
    #[expect(clippy::too_many_lines, reason = "one refresh, its checks in order")]
    async fn rotate(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        params: &Params,
        binding: Binding,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let jkt = binding.jkt();
        let Some(token) = params.get("refresh_token").and_then(decode32) else {
            return Ok(invalid_grant());
        };
        let hash = refresh_digest(&token);
        let Some(row) = tx.refresh(&hash).await? else {
            return Ok(invalid_grant());
        };
        let Some(grant) = tx.grant(row.grant).await? else {
            return Err(Unavailable);
        };
        if grant.client != client.uuid {
            return Ok(invalid_grant());
        }
        let details: GrantDetails =
            serde_json::from_slice(&grant.details).map_err(|_| Unavailable)?;
        if row.rotated_ms.is_some() {
            // TN-31, RR-18
            tx.revoke_grant(grant.id, signed(now), "reuse").await?;
            tx.end_sessions(grant.subject).await?;
            // TN-41, MD-7
            signal(tx, |id| {
                Signal::session_revoked(id, grant.subject, Initiator::Policy, now)
            })
            .await?;
            // §9.9.3 rule 6, P50
            if let (Some(family), Some(root), Some(domain)) =
                (details.family, details.projection, tx.governing().await?)
            {
                self.invalidate(tx, Digest(domain), family, &Digest(root), now)
                    .await?;
            }
            return Ok(invalid_grant());
        }
        if !grant_live(&grant, now) {
            return Ok(invalid_grant());
        }
        if !tx
            .session(grant.session)
            .await?
            .is_some_and(|s| session_live(&s, now))
        {
            return Ok(invalid_grant());
        }
        if let Err(e) = check_refresh(grant.dpop_jkt.map(Jkt), jkt) {
            return Ok(binding_refused(e));
        }
        if !resource_matches(params, &details, realm) {
            return Ok(invalid_target());
        }
        if let (Some(a), Some(family)) = (&details.authority, details.family) {
            let Some(jkt) = jkt else {
                return Ok(binding_refused(BindingError::ProofRequired));
            };
            // §9.9.3 rule 6, L19
            let asked = Asked {
                params,
                authorized: Some(a),
                family: Some(family),
            };
            let p = match self.project(realm, client, &asked, jkt).await? {
                Ok(p) => p,
                Err(r) => return Ok(r),
            };
            if !tx.rotate_refresh(&hash, signed(now)).await? {
                self.invalidate(tx, p.domain, family, &p.token.exercise, now)
                    .await?;
                return Ok(invalid_grant());
            }
            let body = self
                .authority_tokens(tx, realm, client, &grant, &details, &p, None, now)
                .await?;
            return Ok(Reply::json(200, &body));
        }
        if let Some(scope) = params.get("scope") {
            let mut asked = scope.split(' ').filter(|s| !s.is_empty());
            // §2.2.2, S-1
            if asked
                .clone()
                .any(|s| scope::classify(s) == scope::ScopeClass::Resource)
            {
                return Ok(Reply::oauth_error(
                    400,
                    "invalid_scope",
                    scope::RESOURCE_SCOPE,
                ));
            }
            if asked.any(|s| !details.scope.split(' ').any(|g| g == s)) {
                return Ok(Reply::oauth_error(
                    400,
                    "invalid_scope",
                    "the scope exceeds the grant",
                ));
            }
        }
        // OP-155 m.3 (k)
        let refresh = if client.profile.fapi2 {
            false
        } else if tx.rotate_refresh(&hash, signed(now)).await? {
            true
        } else {
            return Ok(invalid_grant());
        };
        let body = self
            .issue_with(
                tx, realm, client, &grant, &details, &binding, None, refresh, now,
            )
            .await?;
        Ok(Reply::json(200, &body))
    }
}

/// OP-155 m.3 (k), RFC 8705 §3, Ek B 4854, 5090: the binding of a code exchange or refresh
/// sent without a DPoP proof: the certificate a mutual TLS client authenticated with, or no
/// `cnf` for a client holding the legacy bearer exception. Anything else needs a proof.
fn unproven_binding(client: &Client, grant_type: Option<&str>, dpop: &[&str]) -> Option<Binding> {
    if !dpop.is_empty() || !matches!(grant_type, Some("authorization_code" | "refresh_token")) {
        return None;
    }
    if let Some(x5t) = client.certificate {
        return Some(Binding::Mtls(x5t));
    }
    (client.profile.legacy_bearer && !client.profile.fapi2).then_some(Binding::Bearer)
}

impl<E: Env> OAuth<E> {
    /// RFC 8628 §3.4-3.5, OP-154 m.3 (p): the device polls with its `device_code`; while the
    /// person has not answered it waits, too fast it slows down, declined it is denied, and once
    /// approved it is redeemed once into a DPoP-bound grant of the approving session (G57).
    async fn device_token(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        use crate::domain::device;
        let Some(code) = params
            .get("device_code")
            .and_then(|c| access_kernel::json::b64url_decode(c).ok())
        else {
            return Ok(invalid_grant());
        };
        let Some(row) = tx.device_code(&device::device_hash(&code)).await? else {
            return Ok(invalid_grant());
        };
        if row.client != client.uuid || row.used_ms.is_some() {
            return Ok(invalid_grant());
        }
        if row.expires_ms <= now {
            return Ok(Reply::oauth_error(
                400,
                "expired_token",
                "the device code expired",
            ));
        }
        match row.decision.as_deref() {
            Some("denied") => {
                return Ok(Reply::oauth_error(
                    400,
                    "access_denied",
                    "the person declined",
                ));
            }
            Some("approved") => {}
            _ => {
                let (interval, early) = device::poll(row.polled_ms, row.interval_s, now);
                tx.poll_device_code(row.device_id, now, interval).await?;
                return Ok(if early {
                    Reply::oauth_error(400, "slow_down", "poll less often")
                } else {
                    Reply::oauth_error(400, "authorization_pending", "the person has not answered")
                });
            }
        }
        let (Some(subject), Some(session_id)) = (row.subject, row.session) else {
            return Ok(invalid_grant());
        };
        // G57
        let Some(session) = tx
            .session(session_id)
            .await?
            .filter(|s| session_live(s, now) && s.subject == subject)
        else {
            return Ok(invalid_grant());
        };
        let Ok(bound) = refresh_binding(client.client_type(), Some(jkt)) else {
            return Ok(binding_refused(BindingError::ProofRequired));
        };
        if !tx.use_device_code(row.device_id, now).await? {
            return Ok(invalid_grant());
        }
        let mut details = GrantDetails {
            scope: row.scope.clone(),
            auth_time_ms: unsigned(session.auth_time_ms),
            aal: super::session_aal(&session)?,
            openid: row.scope.split(' ').any(|s| s == "openid"),
            authority: None,
            family: None,
            projection: None,
            resource: None,
            claims: None,
        };
        // TN-56
        withhold_offline(tx, &mut details.scope, session.subject, now).await?;
        let sid = self.random::<16>()?;
        let encoded = serde_json::to_vec(&details).map_err(|_| Unavailable)?;
        let grant_id = tx
            .insert_grant(&NewGrant {
                sid,
                client: client.uuid,
                subject: session.subject,
                session: session.id,
                session_epoch: session.session_epoch,
                dpop_jkt: bound.as_ref().map(|j| &j.0),
                details: &encoded,
                created_ms: signed(now),
                expires_ms: session.expires_ms,
            })
            .await?;
        let grant = presented(tx, grant_id, session.subject, now).await?;
        let body = self
            .issue(
                tx,
                realm,
                client,
                &grant,
                &details,
                &Binding::Dpop(jkt),
                None,
                now,
            )
            .await?;
        Ok(Reply::json(200, &body))
    }
}

/// Queues the identity plane signal `make` builds with a fresh id, in the token transaction
/// (TN-41, OP-10).
async fn signal<T: OAuthTx>(
    tx: &mut T,
    make: impl FnOnce([u8; 32]) -> Signal,
) -> Result<(), Unavailable> {
    let id = access_identity_account::app::signal::fresh_id().map_err(|_| Unavailable)?;
    let s = make(id);
    let bytes = s.to_outbox().map_err(|_| Unavailable)?;
    tx.outbox(&s.kind.outbox_kind(), &bytes).await
}

/// The grant a redeemed code opened, with the CAEP `session-presented` of the login session
/// the client redeemed queued beside it (TN-41).
async fn presented<T: OAuthTx>(
    tx: &mut T,
    grant: [u8; 16],
    subject: [u8; 16],
    now: u64,
) -> Result<GrantRow, Unavailable> {
    signal(tx, |id| Signal::session_presented(id, subject, now)).await?;
    tx.grant(grant).await?.ok_or(Unavailable)
}
