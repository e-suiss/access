//! Social sign-in, linked sign-ins and combined accounts on the hosted login (IDP-31,
//! OP-153 m.3 (l), (m); TN-65–TN-67).
//!
//! - The browser only carries redirects; every provider answer is checked in the back end.
//! - A sign-in answers the same whether the identity was linked before or a new account was
//!   created, and whatever account holds the provider's address (CR-40): an address never links.
//! - Linking is an explicit action of a signed-in user who re-authenticated within five
//!   minutes, proven by the provider in the same flow; every session then ends.
//! - Combining is irreversible: the absorbed account's own fresh session offers a ticket that
//!   the surviving account's fresh session spends within five minutes.

use std::collections::BTreeMap;

use access_identity_account::app::Actor;
use access_identity_account::app::external::{
    Asserted, Combined, Externals, Linked, Resolved, Unlinked,
};
use access_identity_account::domain::login::Problem;
use access_identity_federation::app::{DevClient, Enabled, Federation, FederationError};
use access_identity_federation::domain::preset::Presets;
use access_identity_federation::domain::rules::{ATTEMPT_TTL_MS, LINK_FRESHNESS_MS};
use access_identity_federation::domain::token::{Secrets, authorization_url};
use access_identity_federation::ports::{ProviderHttp, SocialSecrets};
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::app::{FLOW_GONE, Step as Outcome};
use access_identity_session::domain::flow::device_digest;
use access_identity_session::domain::session::{
    FLOW_COOKIE, SESSION_COOKIE, clear_cookie, set_cookie,
};
use access_identity_session::ports::Clock;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::identity::TenantTx;
use serde_json::json;

use super::signup::STEP_UP_REQUIRED;
use super::{Body, Browser, Hosted, Reply, SESSION_REQUIRED, failed, signin};
use crate::ports::{Kits, Messages, RealmKit};

/// What social sign-in needs beyond the login's services.
pub struct Social<H, S> {
    /// HTTPS to providers.
    pub http: H,
    /// The secret store of the realms' client secrets.
    pub secrets: S,
    /// The operator's shared development clients by preset (`social.dev_clients`).
    pub dev: BTreeMap<String, DevClient>,
    /// The shipped presets.
    pub presets: Presets,
}

/// No enabled provider or upstream by that name.
const NO_PROVIDER: Problem = Problem {
    status: 404,
    code: "no-such-provider",
    title: "That sign-in option isn't available here",
    retry_after_s: None,
};

/// One neutral answer for every refused provider answer and every unusable account (CR-40).
const SOCIAL_FAILED: Problem = Problem {
    status: 401,
    code: "social-sign-in-failed",
    title: "That didn't work. Try again or use another way to sign in.",
    retry_after_s: None,
};

/// The external identity is linked to another account; nothing changed.
const LINKED_ELSEWHERE: Problem = Problem {
    status: 409,
    code: "linked-to-another-account",
    title: "This sign-in is linked to another account",
    retry_after_s: None,
};

/// The last way to sign in stays (TN-68).
const LAST_METHOD: Problem = Problem {
    status: 409,
    code: "last-sign-in-method",
    title: "Add another way to sign in first",
    retry_after_s: None,
};

/// A combination was refused: no live ticket, the same account, or a stale authentication.
const COMBINE_REFUSED: Problem = Problem {
    status: 409,
    code: "combine-refused",
    title: "Confirm it's you on both accounts within five minutes, then try again",
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

fn refused(e: FederationError) -> Reply {
    match e {
        FederationError::Unavailable => unavailable(),
        FederationError::Client(c) => Reply::problem(Problem {
            status: 409,
            code: c.code(),
            title: "This sign-in option isn't set up for this site yet",
            retry_after_s: None,
        }),
        FederationError::Refused(_) | FederationError::Connection(_) => {
            Reply::problem(SOCIAL_FAILED)
        }
    }
}

/// The callback the provider redirects to.
fn redirect_uri(kit: &RealmKit, provider: &str) -> String {
    format!("{}/v1/login/social/{provider}/callback", kit.issuer)
}

fn redirect(to: String) -> Reply {
    Reply::new(303, Body::Redirect(to))
}

fn ticket_hash(ticket: &str) -> [u8; 32] {
    let mut m = b"access/combine-ticket/v1\0".to_vec();
    m.extend_from_slice(ticket.as_bytes());
    suiss_crypto::digest::sha256(&m)
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn enabled<H: ProviderHttp, S: SocialSecrets>(
        &self,
        kit: &RealmKit,
        social: &Social<H, S>,
        provider: &str,
    ) -> Result<(Enabled, bool), Reply> {
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let sandbox = t.realm_is_sandbox().await.map_err(|_| unavailable())?;
        let row = t
            .social_provider(provider)
            .await
            .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        if let Some(r) = row.filter(|r| r.active) {
            let preset = social
                .presets
                .get(&r.preset)
                .ok_or_else(|| Reply::problem(NO_PROVIDER))?;
            return Ok((
                Enabled {
                    preset: preset.clone(),
                    client_id: r.client_id,
                    secret_ref: r.client_secret_ref,
                },
                sandbox,
            ));
        }
        Err(Reply::problem(NO_PROVIDER))
    }

    /// The session's subject and its last authentication time, fresh within `max_age_ms`.
    /// Records the domain upstream `issuer` asserted for `subject` (TN-90, Ek B 3611).
    async fn assert_domain(
        &self,
        kit: &RealmKit,
        subject: [u8; 16],
        issuer: &str,
        domain: &str,
        tenant: Option<&str>,
    ) -> Result<(), access_store::StoreError> {
        let mut t =
            access_store::identity::TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
        t.assert_upstream_domain(subject, issuer, domain, tenant)
            .await?;
        t.commit().await
    }

    pub(crate) async fn fresh(
        &self,
        kit: &RealmKit,
        b: &Browser<'_>,
        max_age_ms: Option<u64>,
    ) -> Result<([u8; 16], u64), Reply> {
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Err(Reply::problem(SESSION_REQUIRED));
        };
        let v = match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => v,
            Ok(_) => return Err(Reply::problem(SESSION_REQUIRED)),
            Err(e) => return Err(failed(&e)),
        };
        let last = v.step_up_ms.unwrap_or(v.auth_time_ms).max(v.auth_time_ms);
        if max_age_ms.is_some_and(|m| self.clock.now_ms().saturating_sub(last) > m) {
            return Err(Reply::problem(STEP_UP_REQUIRED));
        }
        Ok((v.subject, last))
    }

    /// Opens a social attempt and answers with the provider's authorization URL; a link names
    /// the session's freshly re-authenticated subject (TN-65 (3)).
    async fn begin_social<H: ProviderHttp, S: SocialSecrets>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        provider: &str,
        link: bool,
        social: &Social<H, S>,
    ) -> Result<(String, Option<String>), Reply> {
        let kit = self.kit(entry).await?;
        let link_to = if link {
            Some(self.fresh(&kit, b, Some(LINK_FRESHNESS_MS)).await?.0)
        } else {
            None
        };
        let (enabled, sandbox) = self.enabled(&kit, social, provider).await?;
        // IDP-31 (4)
        let client = federation(social)
            .client(&enabled, sandbox)
            .await
            .map_err(refused)?;
        let random = access_crypto::random::bytes::<96>().map_err(|_| unavailable())?;
        let secrets = Secrets::from_random(&random);
        let (device, fresh) = match b.flow.and_then(|f| b64url_decode(f).ok()) {
            Some(d) if d.len() == 32 => (<[u8; 32]>::try_from(d).unwrap_or([0; 32]), false),
            _ => (
                access_crypto::random::bytes::<32>().map_err(|_| unavailable())?,
                true,
            ),
        };
        let now = self.clock.now_ms();
        let state_hash = suiss_crypto::digest::sha256(secrets.state.as_bytes());
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        t.insert_social_attempt(&access_store::federation::NewAttempt {
            state_hash: &state_hash,
            device_hash: &device_digest(&device),
            provider,
            link_to,
            nonce: &secrets.nonce,
            verifier: &secrets.verifier,
            now_ms: now,
            expires_ms: now.saturating_add(ATTEMPT_TTL_MS),
        })
        .await
        .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        let url = authorization_url(
            &enabled.preset,
            &client.id,
            &redirect_uri(&kit, provider),
            &secrets,
        );
        let cookie = fresh.then(|| set_cookie(FLOW_COOKIE, &b64url_encode(&device), None));
        Ok((url, cookie))
    }

    /// `GET /v1/login/social/{provider}` (OP-153 m.3 (l)): to the provider.
    pub async fn start_social<H: ProviderHttp, S: SocialSecrets>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        provider: &str,
        social: &Social<H, S>,
    ) -> Reply {
        match self.begin_social(entry, b, provider, false, social).await {
            Ok((url, cookie)) => redirect(url).cookie(cookie),
            Err(r) => r,
        }
    }

    /// `POST /v1/account/linked` (TN-65): the provider URL that proves control of the sign-in
    /// to link, after a re-authentication within five minutes.
    pub async fn start_link<H: ProviderHttp, S: SocialSecrets>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        provider: &str,
        social: &Social<H, S>,
    ) -> Reply {
        // TN-56, OP-153 m.3 (e)
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        if let Some(r) = self
            .grace_refusal(
                &kit,
                b,
                access_identity_session::domain::recovery::Restricted::IdpLink,
            )
            .await
        {
            return r;
        }
        let begun = match self.begin_social(entry, b, provider, true, social).await {
            Err(r) if matches!(&r.body, Body::Problem(p) if p.code == NO_PROVIDER.code) => {
                // TN-66, OP-155 m.3 (h)
                match self.fresh(&kit, b, Some(LINK_FRESHNESS_MS)).await {
                    Ok((subject, _)) => {
                        self.begin_upstream(
                            &kit,
                            b,
                            provider,
                            Some(subject),
                            social,
                            super::upstream::StartQuery::default(),
                        )
                        .await
                    }
                    Err(r) => Err(r),
                }
            }
            other => other,
        };
        match begun {
            Ok((url, cookie)) => Reply::json(200, json!({ "redirect_to": url })).cookie(cookie),
            Err(r) => r,
        }
    }

    /// `GET /v1/login/social/{provider}/callback` (§10.2.6): the attempt this browser opened is
    /// used once, the code exchanged and the answer checked in the back end.
    #[expect(clippy::too_many_lines, reason = "the callback's steps in their order")]
    pub async fn finish_social<H: ProviderHttp, S: SocialSecrets>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        provider: &str,
        (code, state): (&str, &str),
        social: &Social<H, S>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let Some(device) = b
            .flow
            .and_then(|f| b64url_decode(f).ok())
            .and_then(|d| <[u8; 32]>::try_from(d).ok())
        else {
            return Reply::problem(FLOW_GONE);
        };
        let now = self.clock.now_ms();
        let attempt = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let a = t
                .take_social_attempt(
                    &suiss_crypto::digest::sha256(state.as_bytes()),
                    &device_digest(&device),
                    provider,
                    now,
                )
                .await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(a)
        }
        .await;
        let attempt = match attempt {
            Ok(Some(a)) => a,
            Ok(None) => return Reply::problem(FLOW_GONE),
            Err(_) => return unavailable(),
        };
        let (enabled, sandbox) = match self.enabled(&kit, social, provider).await {
            Ok(e) => e,
            Err(r) => return r,
        };
        let fed = federation(social);
        // IDP-31 (4)
        let client = match fed.client(&enabled, sandbox).await {
            Ok(c) => c,
            Err(e) => return refused(e),
        };
        let secrets = Secrets {
            state: String::from(state),
            nonce: attempt.nonce.clone(),
            verifier: attempt.verifier.clone(),
        };
        let external = match fed
            .finish(
                &enabled.preset,
                &client,
                &redirect_uri(&kit, provider),
                code,
                &secrets,
                now,
            )
            .await
        {
            Ok(x) => x,
            Err(FederationError::Refused(_)) => return Reply::problem(SOCIAL_FAILED),
            Err(e) => return refused(e),
        };
        let realm = kit.realm();
        let vault = kit.vault();
        let externals = Externals {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
        };
        let address = external
            .email
            .as_ref()
            .map(|e| (e.address.as_str(), e.vouched));
        let asserted = Asserted {
            provider,
            key: &external.key,
            address,
            name: external.name.as_deref(),
        };
        if let Some(subject) = attempt.link_to {
            let (current, _) = match self.fresh(&kit, b, None).await {
                Ok(s) => s,
                Err(r) => return r,
            };
            if current != subject {
                return Reply::problem(SESSION_REQUIRED);
            }
            let actor_ref = realm.external(subject).unwrap_or_default();
            let who = Actor {
                actor: &actor_ref,
                correlation: b.correlation,
            };
            return match externals.link(subject, &asserted, now, &who).await {
                Ok(Linked::Linked) => {
                    Reply::json(200, json!({ "linked": true, "signed_out": true }))
                        .cookie(Some(clear_cookie(SESSION_COOKIE)))
                }
                Ok(Linked::Already) => {
                    Reply::json(200, json!({ "linked": true, "signed_out": false }))
                }
                Ok(Linked::Elsewhere) => Reply::problem(LINKED_ELSEWHERE),
                Err(e) => failed(&e.into()),
            };
        }
        let who = Actor {
            actor: "social",
            correlation: b.correlation,
        };
        let subject = match externals.sign_in(&asserted, now, &who).await {
            Ok(Resolved::Existing(s) | Resolved::Created(s)) => s,
            Ok(Resolved::Unusable) => return Reply::problem(SOCIAL_FAILED),
            Err(e) => return failed(&e.into()),
        };
        // TN-90, Ek B 3611
        if let Some((issuer, domain, tenant)) = &external.asserted
            && let Err(e) = self
                .assert_domain(&kit, subject, issuer, domain, tenant.as_deref())
                .await
        {
            tracing::warn!(error = %e, "upstream domain assertion not recorded");
            return Reply::problem(SOCIAL_FAILED);
        }
        signin!(self, kit, auth, Some(b.ip));
        match auth.federated(subject, now, b.flow, b.correlation).await {
            Ok(opened) => match opened.step {
                Outcome::SignedIn(s) => redirect(self.done_to(&kit))
                    .cookie(s.set_cookie)
                    .cookie(s.marker_cookie),
                Outcome::Continue { .. } => {
                    redirect(format!("{}/login?flow={}", kit.issuer, opened.handle))
                }
                _ => Reply::problem(FLOW_GONE),
            },
            Err(e) => failed(&e),
        }
    }

    /// `GET /v1/account/linked` (S11 "Linked sign-ins", §8.5): never "merged".
    pub async fn linked(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let realm = kit.realm();
        let vault = kit.vault();
        let externals = Externals {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
        };
        match externals.links(subject).await {
            Ok(rows) => Reply::json(
                200,
                json!({
                    "linked": rows.iter().map(|r| json!({
                        "link": b64url_encode(&r.link),
                        "provider": r.provider,
                        "linked_at_ms": r.created_ms,
                        "verified_at_ms": r.verified_ms,
                    })).collect::<Vec<_>>(),
                }),
            ),
            Err(e) => failed(&e.into()),
        }
    }

    /// `DELETE /v1/account/linked/{link}`: ends a linked sign-in after a fresh step-up; the
    /// record stays (OP-73) and the last way to sign in stays (TN-68).
    pub async fn unlink(&self, entry: &RealmEntry, b: &Browser<'_>, link: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        // TN-56, OP-153 m.3 (e)
        if let Some(r) = self
            .grace_refusal(
                &kit,
                b,
                access_identity_session::domain::recovery::Restricted::IdpLink,
            )
            .await
        {
            return r;
        }
        let (subject, _) = match self.fresh(&kit, b, Some(LINK_FRESHNESS_MS)).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Some(link) = b64url_decode(link)
            .ok()
            .and_then(|l| <[u8; 16]>::try_from(l).ok())
        else {
            return Reply::problem(NO_PROVIDER);
        };
        let realm = kit.realm();
        let vault = kit.vault();
        let externals = Externals {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
        };
        let actor_ref = realm.external(subject).unwrap_or_default();
        let who = Actor {
            actor: &actor_ref,
            correlation: b.correlation,
        };
        match externals
            .unlink(subject, link, self.clock.now_ms(), &who)
            .await
        {
            Ok(Unlinked::Ended) => Reply::new(204, Body::Empty),
            Ok(Unlinked::Missing) => Reply::problem(NO_PROVIDER),
            Ok(Unlinked::LastMethod) => Reply::problem(LAST_METHOD),
            Err(e) => failed(&e.into()),
        }
    }

    /// `POST /v1/account/combine` (OP-153 m.3 (m)): without a ticket, the absorbed account's
    /// fresh session gets one; with a ticket, the surviving account's fresh session combines.
    pub async fn combine(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        ticket: Option<&str>,
    ) -> Reply {
        use access_identity_account::domain::combine::COMBINE_FRESHNESS_MS;
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, auth_ms) = match self.fresh(&kit, b, Some(COMBINE_FRESHNESS_MS)).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let realm = kit.realm();
        let vault = kit.vault();
        let externals = Externals {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
        };
        let now = self.clock.now_ms();
        let Some(ticket) = ticket else {
            let Ok(secret) = access_crypto::random::bytes::<32>() else {
                return unavailable();
            };
            let ticket = b64url_encode(&secret);
            return match externals
                .offer(subject, auth_ms, &ticket_hash(&ticket), now)
                .await
            {
                Ok(()) => Reply::json(
                    201,
                    json!({ "ticket": ticket, "expires_in_s": COMBINE_FRESHNESS_MS / 1000 }),
                ),
                Err(e) => failed(&e.into()),
            };
        };
        let actor_ref = realm.external(subject).unwrap_or_default();
        let who = Actor {
            actor: &actor_ref,
            correlation: b.correlation,
        };
        match externals
            .combine(subject, auth_ms, &ticket_hash(ticket), now, &who)
            .await
        {
            Ok(Combined::Done { .. }) => Reply::json(
                200,
                json!({
                    "combined": true,
                    // OP-153 m.3 (m), INV-39
                    "notice": "Your accounts are combined. Delegations from the other account must be given again.",
                }),
            ),
            Ok(Combined::Refused) => Reply::problem(COMBINE_REFUSED),
            Err(e) => failed(&e.into()),
        }
    }
}

/// No third-party request waits at that `return_to`, or no consent by that client.
const NO_SHARE: Problem = Problem {
    status: 404,
    code: "no-such-app",
    title: "That app isn't asking for anything here",
    retry_after_s: None,
};

/// The claims a waiting authorization request of a third-party client asks the person to share
/// (OP-153 m.3 (z)): the request `return_to` names, still open.
struct Pending {
    client: access_store::idp::ClientRow,
    claims: Vec<String>,
    authority: Option<access_identity_oauth::domain::request::AuthorityAsk>,
    redirect_uri: String,
    state: Option<String>,
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn pending(&self, kit: &RealmKit, return_to: &str) -> Result<Pending, Reply> {
        use access_identity_oauth::domain::claims_request::{ClaimsAsk, shared_set};
        use access_identity_oauth::domain::request::{AuthRequest, REQUEST_URI_PREFIX};
        let issuer = access_identity_oauth::domain::issuer::Issuer::parse(&kit.issuer)
            .map_err(|_| unavailable())?;
        if !access_identity_oauth::domain::login::return_to_ok(&issuer, return_to) {
            return Err(Reply::problem(NO_SHARE));
        }
        let query = return_to.split_once('?').map_or("", |(_, q)| q);
        let params = access_identity_oauth::domain::request::Params::parse(query)
            .map_err(|_| Reply::problem(NO_SHARE))?;
        let handle = params
            .get("request_uri")
            .and_then(|u| u.strip_prefix(REQUEST_URI_PREFIX))
            .and_then(|h| b64url_decode(h).ok())
            .ok_or_else(|| Reply::problem(NO_SHARE))?;
        let hash = access_crypto::oauth::opaque_digest(
            access_identity_oauth::app::oauth::REQUEST_CONTEXT,
            &handle,
        );
        let now = self.clock.now_ms();
        let from_day = i32::try_from((now / 86_400_000).saturating_sub(1)).unwrap_or(i32::MAX);
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let row = t
            .oauth_request(from_day, &hash)
            .await
            .map_err(|_| unavailable())?
            .filter(|r| r.used_ms.is_none() && u64::try_from(r.expires_ms).is_ok_and(|e| e > now));
        let Some(row) = row else {
            t.commit().await.map_err(|_| unavailable())?;
            return Err(Reply::problem(NO_SHARE));
        };
        let client = access_store::idp::client_by_uuid(&mut t, row.client)
            .await
            .map_err(|_| unavailable())?
            .filter(|c| c.active && c.third_party);
        t.commit().await.map_err(|_| unavailable())?;
        let (Some(client), Ok(req)) = (client, serde_json::from_slice::<AuthRequest>(&row.params))
        else {
            return Err(Reply::problem(NO_SHARE));
        };
        if params.get("client_id") != Some(client.client_id.as_str()) {
            return Err(Reply::problem(NO_SHARE));
        }
        let scopes: Vec<&str> = req.scope.iter().map(String::as_str).collect();
        let requested = req
            .claims
            .as_ref()
            .map(ClaimsAsk::requested)
            .unwrap_or_default();
        let claims = shared_set(&scopes, &requested)
            .into_iter()
            .map(String::from)
            .collect();
        Ok(Pending {
            client,
            claims,
            authority: req.authority,
            redirect_uri: req.redirect_uri,
            state: req.state,
        })
    }

    /// `POST /v1/account/connected-apps/preview` (OP-153 m.3 (z)): what the waiting third-party
    /// request asks the person to share, for the "Share with *App*" screen. Identity claims
    /// only; authority is asked for through RAR and S1, never here.
    pub async fn share_preview(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        return_to: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        if let Err(r) = self.fresh(&kit, b, None).await {
            return r;
        }
        match self.pending(&kit, return_to).await {
            Ok(p) => Reply::json(
                200,
                json!({
                    "client_id": p.client.client_id,
                    "app": p.client.display_name,
                    "claims": p.claims,
                }),
            ),
            Err(r) => r,
        }
    }

    /// `POST /v1/account/connect/preview` (§8.17.4.3, X27, OP-153 m.3 (x)): the S1 draft the
    /// waiting third-party request's typed bounds open, for the hosted Delegation sheet. A draft
    /// only: what is committed is the `grant.issue` of the exact preview the person signs with
    /// the browser's device key.
    pub async fn connect_preview(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        return_to: &str,
    ) -> Reply {
        use access_identity_oauth::domain::authority::{connect_draft, parse_details};
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        if let Err(r) = self.fresh(&kit, b, None).await {
            return r;
        }
        let p = match self.pending(&kit, return_to).await {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Some(ask) = p.authority else {
            return Reply::problem(NO_SHARE);
        };
        let draft = parse_details(&ask.details, &ask.resource).and_then(|(kind, details)| {
            connect_draft(&p.client.display_name, kind, &details, self.clock.now_ms())
        });
        match draft {
            Ok(draft) => Reply::json(
                200,
                json!({
                    "client_id": p.client.client_id,
                    "app": p.client.display_name,
                    "resource": ask.resource,
                    "draft": draft,
                }),
            ),
            Err(_) => Reply::problem(NO_SHARE),
        }
    }

    /// `POST /v1/account/connected-apps` (OP-153 m.3 (z)): the person shares the claims the
    /// waiting request asks for; the consent is kept per (person, app, claim set) and the
    /// browser goes back to the request.
    pub async fn share(&self, entry: &RealmEntry, b: &Browser<'_>, return_to: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let p = match self.pending(&kit, return_to).await {
            Ok(p) => p,
            Err(r) => return r,
        };
        let stored = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            t.put_consent(
                subject,
                p.client.client_uuid,
                &p.claims,
                self.clock.now_ms(),
            )
            .await?;
            t.commit().await
        };
        match stored.await {
            Ok(()) => Reply::json(200, json!({ "redirect_to": return_to })),
            Err(_) => unavailable(),
        }
    }

    /// N5: `POST /v1/account/connected-apps/decline` (OP-153 m.3 (z), X-L8): the person chose
    /// not to share; the waiting request goes back to the app as `access_denied` with its
    /// `state` and `iss` (RFC 6749 §4.1.2.1, RFC 9207). Nothing is stored.
    pub async fn decline(&self, entry: &RealmEntry, b: &Browser<'_>, return_to: &str) -> Reply {
        use access_identity_oauth::domain::request::{AuthError, error_redirect};
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        if let Err(r) = self.fresh(&kit, b, None).await {
            return r;
        }
        let p = match self.pending(&kit, return_to).await {
            Ok(p) => p,
            Err(r) => return r,
        };
        let Ok(issuer) = access_identity_oauth::domain::issuer::Issuer::parse(&kit.issuer) else {
            return unavailable();
        };
        let to = error_redirect(
            &p.redirect_uri,
            AuthError::ACCESS_DENIED,
            p.state.as_deref(),
            &issuer,
        );
        Reply::json(200, json!({ "redirect_to": to }))
    }

    /// `GET /v1/account/connected-apps` (S11 "Connected apps", OP-153 m.3 (z)): the apps the
    /// person shares identity claims with, and which claims.
    pub async fn connected_apps(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let rows = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let rows = t.consents_of(subject).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(rows)
        };
        match rows.await {
            Ok(rows) => Reply::json(
                200,
                json!({
                    "apps": rows.iter().map(|r| json!({
                        "client_id": r.client_id,
                        "app": r.display_name,
                        "claims": r.claims,
                        "since_ms": r.created_ms,
                    })).collect::<Vec<_>>(),
                }),
            ),
            Err(_) => unavailable(),
        }
    }

    /// `DELETE /v1/account/connected-apps/{client}` (OP-153 m.3 (z)): stops sharing with the
    /// app; it receives no identity claims until the person shares again. The record stays.
    pub async fn stop_sharing(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        client_id: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let stopped = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let done = t
                .stop_consent(subject, client_id, self.clock.now_ms())
                .await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(done)
        };
        match stopped.await {
            Ok(true) => Reply::new(204, Body::Empty),
            Ok(false) => Reply::problem(NO_SHARE),
            Err(_) => unavailable(),
        }
    }
}

/// The binding token was refused: no such offer, a lapsed one, or a half this realm keeps.
const BINDING_REFUSED: Problem = Problem {
    status: 409,
    code: "binding-refused",
    title: "That code didn't work. Start again from the other account.",
    retry_after_s: None,
};

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// `POST /v1/account/bindings` (§12.1.3, TN-65): after a fresh re-authentication, an offer
    /// to bind this account to one in another realm; the token goes to the other realm.
    pub async fn offer_binding(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, Some(LINK_FRESHNESS_MS)).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let realm = kit.realm();
        let vault = kit.vault();
        let externals = Externals {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
        };
        match externals.offer_binding(subject, self.clock.now_ms()).await {
            Ok(token) => Reply::json(
                201,
                json!({
                    "token": token,
                    "expires_in_s": access_identity_account::app::binding::OFFER_TTL_MS / 1000,
                }),
            ),
            Err(e) => failed(&e.into()),
        }
    }

    /// `POST /v1/account/bindings/accept` and `/complete` (§12.1.3): this realm's half is
    /// committed with the other realm's token and its Claim stated; an acceptance answers with
    /// the token to carry back. A matching address never binds anything (MD-5).
    pub async fn bind_half(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        token: &str,
        accept: bool,
    ) -> Reply {
        use access_identity_account::app::binding::Bound;
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, Some(LINK_FRESHNESS_MS)).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let realm = kit.realm();
        let vault = kit.vault();
        let externals = Externals {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
        };
        let actor_ref = realm.external(subject).unwrap_or_default();
        let who = Actor {
            actor: &actor_ref,
            correlation: b.correlation,
        };
        let now = self.clock.now_ms();
        let done = if accept {
            externals.accept_binding(subject, token, now, &who).await
        } else {
            externals.complete_binding(subject, token, now, &who).await
        };
        match done {
            Ok(Bound::Committed(Some(back))) => Reply::json(200, json!({ "token": back })),
            Ok(Bound::Committed(None)) => Reply::json(200, json!({ "bound": true })),
            Ok(Bound::Refused) => Reply::problem(BINDING_REFUSED),
            Err(e) => failed(&e.into()),
        }
    }

    /// `GET /v1/account/bindings`: this realm's halves of the account's cross-realm bindings.
    pub async fn bindings(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (subject, _) = match self.fresh(&kit, b, None).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let realm = kit.realm();
        let vault = kit.vault();
        let externals = Externals {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
        };
        match externals.binding_halves(subject).await {
            Ok(rows) => Reply::json(
                200,
                json!({
                    "bindings": rows.iter().map(|h| json!({
                        "binding": b64url_encode(&h.binding),
                        "role": h.role,
                        "proof": h.proof,
                        "state": h.state,
                        "committed_at_ms": h.committed_ms,
                    })).collect::<Vec<_>>(),
                }),
            ),
            Err(e) => failed(&e.into()),
        }
    }
}

fn federation<H: ProviderHttp, S: SocialSecrets>(s: &Social<H, S>) -> Federation<'_, H, S> {
    Federation {
        http: &s.http,
        secrets: &s.secrets,
        dev: &s.dev,
    }
}
