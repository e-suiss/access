//! Enterprise upstream sign-in on the hosted login (OP-155 m.3 (h); IDP-27, IDP-34, TN-66,
//! TN-95, TN-98, TN-108, SEC9).
//!
//! - A connection is a registered upstream (`idp.upstream.register`, reserved CT3) with its own
//!   profile; its discovery fixes algorithms and client authentication.
//! - It signs nobody in, and yields no Claim, unless the governing domain holds an
//!   actor-binding Acceptance of its issuer; once that is cut off, the sessions it opened end.
//! - The person is keyed by `(iss, sub)` or Entra's `(tid, oid)`; an address or `login_hint`
//!   never proves who they are. A subject new to the connection for an address one of its links
//!   holds is a conflict, never a relink.
//! - Its `acr`/`amr` reach assurance only through the connection's assurance map.
//! - An upstream that does not answer leaves every account as it was.

use std::sync::Arc;

use access_identity_account::app::Actor;
use access_identity_account::app::external::{
    Asserted, Externals, Linked, UpstreamFacts, UpstreamResolved,
};
use access_identity_account::domain::login::Problem;
use access_identity_federation::app::connection::{
    Connection, Resolved, SamlFailure, UpstreamSignIn, saml_sign_in, verify_saml,
};
use access_identity_federation::app::{Federation, FederationError};
use access_identity_federation::domain::connection::Mapped;
use access_identity_federation::domain::connection::{
    ConnectionProtocol, Profile, issuer_id, mapped,
};
use access_identity_federation::domain::rules::ATTEMPT_TTL_MS;
use access_identity_federation::domain::saml::{self as sp_saml, Sp};
use access_identity_federation::domain::token::Secrets;
use access_identity_federation::ports::{
    AssertionReader, ClientAssertion, ProviderHttp, SamlRequestSigner, SocialSecrets, UpstreamTrust,
};
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::{FLOW_GONE, Step as Outcome};
use access_identity_session::domain::assurance::{Factor, UpstreamStep};
use access_identity_session::domain::flow::device_digest;
use access_identity_session::domain::session::{
    FLOW_COOKIE, SESSION_COOKIE, clear_cookie, set_cookie,
};
use access_identity_session::ports::Clock;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::identity::TenantTx;
use serde_json::json;

use super::social::Social;
use super::{Body, Browser, Hosted, Reply, SESSION_REQUIRED, failed, signin};
use crate::ports::{Kits, Messages, RealmKit};

/// What enterprise upstream sign-in needs beyond social sign-in's services.
pub struct Upstreams {
    /// The governing domain's Acceptances of upstream issuers.
    pub trust: Arc<dyn UpstreamTrust>,
    /// The realm's signer of `private_key_jwt` client assertions.
    pub assertions: Arc<dyn ClientAssertion>,
    /// The parser worker, for SAML upstreams' Responses.
    pub reader: Arc<dyn AssertionReader>,
    /// The realm's SAML key, for `AuthnRequest`s.
    pub saml_signer: Arc<dyn SamlRequestSigner>,
}

impl core::fmt::Debug for Upstreams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Upstreams").finish_non_exhaustive()
    }
}

/// No enabled connection by that name.
const NO_CONNECTION: Problem = Problem {
    status: 404,
    code: "no-such-provider",
    title: "That sign-in option isn't available here",
    retry_after_s: None,
};

/// §8.13 `upstream.unreachable`: nothing falls back and no account changes.
pub const UPSTREAM_UNREACHABLE: Problem = Problem {
    status: 503,
    code: "upstream-unreachable",
    title: "The sign-in provider isn't responding. Try another sign-in method if you've set one up.",
    retry_after_s: None,
};

/// The connection is registered but its issuer is not accepted, or its discovery does not fit.
const UPSTREAM_NOT_SET_UP: Problem = Problem {
    status: 409,
    code: "upstream-not-accepted",
    title: "This sign-in option isn't set up for this site yet",
    retry_after_s: None,
};

/// TN-66 `upstream.subject_conflict`: nothing was relinked.
const UPSTREAM_CONFLICT: Problem = Problem {
    status: 409,
    code: "upstream-subject-conflict",
    title: "Your account at this provider has changed. Sign in another way, then link it again from your account.",
    retry_after_s: None,
};

/// One neutral answer for every refused upstream answer (CR-40).
/// An organization's connection named an identity outside the organization's verified domains
/// (TN-134 (1), (3)).
const OUTSIDE_ORGANIZATION: Problem = Problem {
    status: 403,
    code: "upstream-identity-outside-organization",
    title: "This identity provider can't sign in this address",
    retry_after_s: None,
};

const UPSTREAM_FAILED: Problem = Problem {
    status: 401,
    code: "social-sign-in-failed",
    title: "That didn't work. Try again or use another way to sign in.",
    retry_after_s: None,
};

const LINKED_ELSEWHERE: Problem = Problem {
    status: 409,
    code: "linked-to-another-account",
    title: "This sign-in is linked to another account",
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

fn unreachable(name: &str) -> Reply {
    tracing::info!(
        event = "login.upstream.unreachable",
        outcome = "refused",
        connection = name,
        "upstream unreachable"
    );
    Reply::problem(UPSTREAM_UNREACHABLE)
}

/// The callback the connection redirects to.
fn redirect_uri(kit: &RealmKit, connection: &str) -> String {
    format!("{}/v1/login/upstream/{connection}/callback", kit.issuer)
}

/// Access's entity ID and ACS for SAML connection `name`.
fn sp_urls(kit: &RealmKit, name: &str) -> (String, String) {
    let base = format!("{}/v1/login/upstream/{name}/saml", kit.issuer);
    (format!("{base}/metadata"), format!("{base}/acs"))
}

/// The `AuthnRequest` ID of an attempt: an XML name from its random nonce.
fn request_id(nonce: &str) -> String {
    format!("_{nonce}")
}

/// Digest context of a SAML assertion's one use, shared with the SAML 2.0 bearer grant.
const ASSERTION_ID_CONTEXT: &str = "access/saml-assertion-id/v1";

fn redirect(to: String) -> Reply {
    Reply::new(303, Body::Redirect(to))
}

/// A connection as this realm holds it.
pub(crate) struct Held {
    resolved: Resolved,
    domain: [u8; 32],
    map: Option<String>,
}

/// The query of a start: only `ui_locales` is read; `domain_hint` and `login_hint` never
/// change which connection is used, nor travel to it (TN-98, TN-3).
#[derive(Clone, Copy, Debug, Default)]
pub struct StartQuery<'a> {
    /// The asked locales.
    pub ui_locales: Option<&'a str>,
}

fn federation<H: ProviderHttp, S: SocialSecrets>(s: &Social<H, S>) -> Federation<'_, H, S> {
    Federation {
        http: &s.http,
        secrets: &s.secrets,
        dev: &s.dev,
    }
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// The active connection `name` of the realm as registered, its governing domain and its
    /// assurance map; `None` when the realm has no such connection.
    pub(crate) async fn registered_connection(
        &self,
        kit: &RealmKit,
        name: &str,
    ) -> Result<Option<(Connection, [u8; 32], Option<String>)>, Reply> {
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let row = access_store::idp::realm::upstream(&mut t, name).await?;
            let domain = access_store::idp::governance(&mut t)
                .await?
                .map(|g| *g.domain.as_bytes());
            let map = t.upstream_assurance_map(name).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>((row, domain, map))
        };
        let (row, domain, map) = read.await.map_err(|_| unavailable())?;
        let (Some(row), Some(domain)) = (row.filter(|r| r.active), domain) else {
            return Ok(None);
        };
        let profile = Profile::stored(row.profile.as_deref(), row.client_secret_ref.is_some())
            .map_err(|_| unavailable())?;
        Ok(Some((
            Connection {
                name: row.name,
                issuer: row.issuer,
                client_id: row.client_id,
                secret_ref: row.client_secret_ref,
                jwks_uri: row.jwks_uri,
                profile,
            },
            domain,
            map,
        )))
    }

    /// The active OIDC connection `name` of the realm with its discovery read; `None` when the
    /// realm has no such connection.
    pub(crate) async fn upstream_connection<H: ProviderHttp, S: SocialSecrets>(
        &self,
        kit: &RealmKit,
        social: &Social<H, S>,
        name: &str,
    ) -> Result<Option<Held>, Reply> {
        let Some((connection, domain, map)) = self.registered_connection(kit, name).await? else {
            return Ok(None);
        };
        if connection.profile.protocol != ConnectionProtocol::Oidc {
            return Ok(None);
        }
        match federation(social).resolve(connection).await {
            Ok(resolved) => Ok(Some(Held {
                resolved,
                domain,
                map,
            })),
            Err(FederationError::Unavailable) => Err(unreachable(name)),
            Err(_) => Err(Reply::problem(UPSTREAM_NOT_SET_UP)),
        }
    }

    /// Opens an attempt at connection `name` and answers with its authorization URL; a link
    /// names the session's freshly re-authenticated subject (TN-65 (3)).
    pub(crate) async fn begin_upstream<H: ProviderHttp, S: SocialSecrets>(
        &self,
        kit: &RealmKit,
        b: &Browser<'_>,
        name: &str,
        link_to: Option<[u8; 16]>,
        social: &Social<H, S>,
        q: StartQuery<'_>,
    ) -> Result<(String, Option<String>), Reply> {
        let held = self
            .upstream_connection(kit, social, name)
            .await?
            .ok_or_else(|| Reply::problem(NO_CONNECTION))?;
        let random = access_crypto::random::bytes::<96>().map_err(|_| unavailable())?;
        let secrets = Secrets::from_random(&random);
        let (device, fresh) = match b
            .flow
            .and_then(|f| b64url_decode(f).ok())
            .and_then(|d| <[u8; 32]>::try_from(d).ok())
        {
            Some(d) => (d, false),
            None => (
                access_crypto::random::bytes::<32>().map_err(|_| unavailable())?,
                true,
            ),
        };
        let now = self.clock.now_ms();
        let state_hash = suiss_crypto::digest::sha256(secrets.state.as_bytes());
        let stored = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            t.insert_social_attempt(&access_store::federation::NewAttempt {
                state_hash: &state_hash,
                device_hash: &device_digest(&device),
                provider: name,
                link_to,
                nonce: &secrets.nonce,
                verifier: &secrets.verifier,
                now_ms: now,
                expires_ms: now.saturating_add(ATTEMPT_TTL_MS),
            })
            .await?;
            t.commit().await
        };
        stored.await.map_err(|_| unavailable())?;
        // TN-108
        let url = held
            .resolved
            .authorization_url(&redirect_uri(kit, name), &secrets, q.ui_locales);
        let cookie = fresh.then(|| set_cookie(FLOW_COOKIE, &b64url_encode(&device), None));
        Ok((url, cookie))
    }

    /// `GET /v1/login/upstream/{connection}` (OP-155 m.3 (h)): to the connection; a SAML
    /// connection gets a signed `AuthnRequest` in the HTTP-Redirect binding.
    pub async fn start_upstream<H: ProviderHttp, S: SocialSecrets>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        name: &str,
        q: StartQuery<'_>,
        social: &Social<H, S>,
        upstreams: &Upstreams,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        match self.registered_connection(&kit, name).await {
            Ok(Some((c, _, _))) if c.profile.protocol == ConnectionProtocol::Saml => {
                match self.begin_saml(&kit, b, &c, upstreams).await {
                    Ok((url, cookie)) => redirect(url).cookie(cookie),
                    Err(r) => r,
                }
            }
            Ok(_) => match self.begin_upstream(&kit, b, name, None, social, q).await {
                Ok((url, cookie)) => redirect(url).cookie(cookie),
                Err(r) => r,
            },
            Err(r) => r,
        }
    }

    /// The flow device of this browser, and the cookie that sets one when it has none.
    fn device(b: &Browser<'_>) -> Result<([u8; 32], Option<String>), Reply> {
        if let Some(d) = b
            .flow
            .and_then(|f| b64url_decode(f).ok())
            .and_then(|d| <[u8; 32]>::try_from(d).ok())
        {
            return Ok((d, None));
        }
        let d = access_crypto::random::bytes::<32>().map_err(|_| unavailable())?;
        Ok((d, Some(set_cookie(FLOW_COOKIE, &b64url_encode(&d), None))))
    }

    /// Opens an attempt at SAML connection `c`: its `AuthnRequest` ID and `RelayState` are kept
    /// with this browser's flow device, then signed into the identity provider's SSO URL (OP-155 m.3 (h)).
    async fn begin_saml(
        &self,
        kit: &RealmKit,
        b: &Browser<'_>,
        c: &Connection,
        upstreams: &Upstreams,
    ) -> Result<(String, Option<String>), Reply> {
        let Some(idp) = c.profile.saml.as_ref() else {
            return Err(unavailable());
        };
        let random = access_crypto::random::bytes::<96>().map_err(|_| unavailable())?;
        let secrets = Secrets::from_random(&random);
        let (device, cookie) = Self::device(b)?;
        let now = self.clock.now_ms();
        let state_hash = suiss_crypto::digest::sha256(secrets.state.as_bytes());
        let stored = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            t.insert_social_attempt(&access_store::federation::NewAttempt {
                state_hash: &state_hash,
                device_hash: &device_digest(&device),
                provider: &c.name,
                link_to: None,
                nonce: &secrets.nonce,
                verifier: &secrets.verifier,
                now_ms: now,
                expires_ms: now.saturating_add(ATTEMPT_TTL_MS),
            })
            .await?;
            t.commit().await
        };
        stored.await.map_err(|_| unavailable())?;
        let (entity, acs) = sp_urls(kit, &c.name);
        let request = sp_saml::authn_request(
            &Sp {
                entity_id: &entity,
                acs: &acs,
            },
            &request_id(&secrets.nonce),
            &access_identity_saml::time::format(now),
            &idp.sso_url,
        );
        let url = upstreams
            .saml_signer
            .redirect(
                *kit.realm.as_bytes(),
                &idp.sso_url,
                &request,
                &secrets.state,
            )
            .await
            .map_err(|_| unreachable(&c.name))?;
        Ok((url, cookie))
    }

    /// `GET /v1/login/upstream/{connection}/saml/metadata`: Access's SP metadata for one SAML
    /// connection; `None` when the realm has no such connection.
    pub async fn upstream_metadata(&self, entry: &RealmEntry, name: &str) -> Option<String> {
        let kit = self.kit(entry).await.ok()?;
        let (c, _, _) = self.registered_connection(&kit, name).await.ok()??;
        if c.profile.protocol != ConnectionProtocol::Saml {
            return None;
        }
        let (entity, acs) = sp_urls(&kit, name);
        Some(sp_saml::metadata(&Sp {
            entity_id: &entity,
            acs: &acs,
        }))
    }

    /// Whether an `organization`-profile connection `name` may speak for the asserted `address`
    /// (TN-134 (1), (3)): only an address on one of the organization's verified, uncontested
    /// domains; a lapsed verification drops the domain, and an assertion without an address is
    /// refused. Other connections pass.
    async fn organization_scope(
        &self,
        kit: &RealmKit,
        name: &str,
        address: Option<&str>,
    ) -> Result<(), Reply> {
        let Some((connection, _, _)) = self.registered_connection(kit, name).await? else {
            return Err(Reply::problem(NO_CONNECTION));
        };
        let Some(party) = connection.profile.organization_party() else {
            return Ok(());
        };
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let verified = match t.org_by_party(party).await?.filter(|o| !o.ended) {
                Some(o) => t.hrd_domains(o.id).await?,
                None => Vec::new(),
            };
            t.commit().await?;
            Ok::<_, access_store::StoreError>(verified)
        };
        let verified = read.await.map_err(|_| unavailable())?;
        if address.is_some_and(|a| crate::domain::sso_setup::admits(a, &verified)) {
            Ok(())
        } else {
            Err(Reply::problem(OUTSIDE_ORGANIZATION))
        }
    }

    /// Whether the governing domain `domain` accepts upstream issuer `issuer` of connection
    /// `name`; when it does not, the sessions the connection opened end (SEC9).
    async fn upstream_accepted(
        &self,
        kit: &RealmKit,
        (name, issuer, domain): (&str, &str, [u8; 32]),
        upstreams: &Upstreams,
    ) -> Result<(), Reply> {
        match upstreams.trust.accepted(domain, issuer_id(issuer)).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                signin!(self, kit, auth);
                // SEC9
                if let Err(e) = auth.quarantine_upstream(name).await {
                    tracing::warn!(error = %e, "upstream sessions not ended");
                    return Err(unavailable());
                }
                Err(Reply::problem(UPSTREAM_NOT_SET_UP))
            }
            Err(_) => Err(unavailable()),
        }
    }

    /// `GET /v1/login/upstream/{connection}/callback` (OP-155 m.3 (h)): the attempt this
    /// browser opened is used once; the response's `iss`, the connection's Acceptance and the
    /// ID token are checked in the back end before any account is touched.
    pub async fn finish_upstream<H: ProviderHttp, S: SocialSecrets>(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        name: &str,
        (code, state, iss): (&str, &str, Option<&str>),
        social: &Social<H, S>,
        upstreams: &Upstreams,
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
                    name,
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
        let held = match self.upstream_connection(&kit, social, name).await {
            Ok(Some(h)) => h,
            Ok(None) => return Reply::problem(NO_CONNECTION),
            Err(r) => return r,
        };
        // RFC 9207 §2.4
        if held.resolved.discovered.check_iss(iss).is_err() {
            return Reply::problem(UPSTREAM_FAILED);
        }
        // TN-95, INV-17, SEC9
        let c = &held.resolved.connection;
        if let Err(r) = self
            .upstream_accepted(&kit, (&c.name, &c.issuer, held.domain), upstreams)
            .await
        {
            return r;
        }
        let secrets = Secrets {
            state: String::from(state),
            nonce: attempt.nonce.clone(),
            verifier: attempt.verifier.clone(),
        };
        let signed = federation(social)
            .finish_connection(
                &held.resolved,
                &*upstreams.assertions,
                *kit.realm.as_bytes(),
                &redirect_uri(&kit, name),
                code,
                &secrets,
                now,
            )
            .await;
        let signed = match signed {
            Ok(s) => s,
            Err(FederationError::Unavailable) => return unreachable(name),
            Err(_) => return Reply::problem(UPSTREAM_FAILED),
        };
        // IDP-27
        let assurance = mapped(held.map.as_deref(), &signed.declared);
        let display = held.resolved.preset.display_name.clone();
        self.complete_upstream(
            &kit,
            b,
            name,
            (&signed, assurance, false),
            attempt.link_to,
            &display,
        )
        .await
    }

    /// The account side of a checked upstream sign-in, OIDC or SAML: a link of the signed-in
    /// subject, or the linked or just-in-time account, a conflict, and the flow (TN-66,
    /// §10.2.6).
    #[expect(
        clippy::too_many_lines,
        reason = "the account side's steps in their order"
    )]
    async fn complete_upstream(
        &self,
        kit: &RealmKit,
        b: &Browser<'_>,
        name: &str,
        (signed, assurance, saml): (&UpstreamSignIn, Mapped, bool),
        link_to: Option<[u8; 16]>,
        display: &str,
    ) -> Reply {
        let now = self.clock.now_ms();
        let realm = kit.realm();
        let vault = kit.vault();
        let externals = Externals {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
        };
        let address = signed
            .external
            .email
            .as_ref()
            .map(|e| (e.address.as_str(), false));
        let asserted = Asserted {
            provider: name,
            key: &signed.external.key,
            address,
            name: signed.external.name.as_deref(),
        };
        // TN-134 (1), (3)
        if let Err(r) = self
            .organization_scope(kit, name, address.map(|a| a.0))
            .await
        {
            return r;
        }
        let national = signed.national.as_ref().map(|n| n.expose().clone());
        let facts = UpstreamFacts {
            connection: name,
            issuer: issuer_id(&signed.issuer),
            evidence: &signed.evidence,
            raw: signed.raw.expose(),
            national: national.as_deref(),
        };
        if let Some(subject) = link_to {
            let (current, _) = match self.fresh(kit, b, None).await {
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
            // TN-66
            return match externals
                .link_upstream(subject, &asserted, &facts, now, &who)
                .await
            {
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
            actor: "upstream",
            correlation: b.correlation,
        };
        let subject = match externals
            .sign_in_upstream(&asserted, &facts, now, &who)
            .await
        {
            Ok(UpstreamResolved::Existing(s) | UpstreamResolved::Created(s)) => s,
            Ok(UpstreamResolved::Unusable) => return Reply::problem(UPSTREAM_FAILED),
            Ok(UpstreamResolved::Conflict { holder, fresh }) => {
                if fresh {
                    signin!(self, kit, auth);
                    if let Err(e) = auth.upstream_conflict_notice(holder, display).await {
                        tracing::warn!(error = %e, "upstream conflict notice not queued");
                    }
                }
                return Reply::problem(UPSTREAM_CONFLICT);
            }
            Err(e) => return failed(&e.into()),
        };
        let factor = Factor::upstream(
            UpstreamStep {
                connection: String::from(name),
                saml,
                iss: signed.issuer.clone(),
                acr: signed.declared.acr.clone(),
                amr: signed.declared.amr.clone(),
                evidence: signed.evidence,
                aal: assurance.aal,
                loa_eidas: assurance.loa_eidas,
            },
            now,
        );
        signin!(self, kit, auth, Some(b.ip));
        match auth.upstream(subject, factor, b.flow, b.correlation).await {
            Ok(opened) => match opened.step {
                Outcome::SignedIn(s) => redirect(self.redirect_to.clone())
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
}

/// The fields of a SAML upstream's answer at the ACS.
#[derive(Clone, Copy, Debug)]
pub struct SamlAnswer<'a> {
    /// `SAMLResponse`, base64.
    pub response: &'a str,
    /// `RelayState`, the attempt's state, absent for an unsolicited Response.
    pub relay_state: Option<&'a str>,
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// `POST /v1/login/upstream/{connection}/saml/acs` (OP-155 m.3 (h), §10.6.1): the Response
    /// is read and its assertion's signature verified in the parser worker against the identity provider's
    /// pinned certificates; it must answer the `AuthnRequest` this browser's attempt sent, or be
    /// an unsolicited Response the connection opens, and it is used once.
    #[expect(clippy::too_many_lines, reason = "the ACS's steps in their order")]
    pub async fn finish_upstream_saml(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        name: &str,
        answer: SamlAnswer<'_>,
        upstreams: &Upstreams,
    ) -> Reply {
        use access_identity_oauth::ports::dpop::ReplayCache as _;
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (c, domain, map) = match self.registered_connection(&kit, name).await {
            Ok(Some(x)) if x.0.profile.protocol == ConnectionProtocol::Saml => x,
            Ok(_) => return Reply::problem(NO_CONNECTION),
            Err(r) => return r,
        };
        let Some(idp) = c.profile.saml.clone() else {
            return unavailable();
        };
        // TN-95, INV-17, SEC9
        if let Err(r) = self
            .upstream_accepted(&kit, (&c.name, &idp.entity_id, domain), upstreams)
            .await
        {
            return r;
        }
        let now = self.clock.now_ms();
        let device = b
            .flow
            .and_then(|f| b64url_decode(f).ok())
            .and_then(|d| <[u8; 32]>::try_from(d).ok());
        let attempt = match (answer.relay_state, device) {
            (Some(state), Some(device)) => {
                let taken = async {
                    let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
                    let a = t
                        .take_social_attempt(
                            &suiss_crypto::digest::sha256(state.as_bytes()),
                            &device_digest(&device),
                            name,
                            now,
                        )
                        .await?;
                    t.commit().await?;
                    Ok::<_, access_store::StoreError>(a)
                };
                match taken.await {
                    Ok(Some(a)) => Some(a),
                    Ok(None) => return Reply::problem(FLOW_GONE),
                    Err(_) => return unavailable(),
                }
            }
            _ => None,
        };
        let Some(message) = access_identity_saml::sp::b64::decode(answer.response) else {
            return Reply::problem(UPSTREAM_FAILED);
        };
        let (entity, acs) = sp_urls(&kit, name);
        let wanted = attempt.as_ref().map(|a| request_id(&a.nonce));
        let expect = sp_saml::Expect {
            idp: &idp.entity_id,
            audience: &entity,
            recipient: Some(&acs),
            in_response_to: wanted.as_deref(),
            allow_unsolicited: c.profile.allow_unsolicited,
            now_ms: now,
        };
        let (facts, declared) = match verify_saml(&*upstreams.reader, &c, &message, &expect).await {
            Ok(x) => x,
            Err(SamlFailure::Unavailable) => return unreachable(name),
            Err(SamlFailure::Refused) => {
                tracing::info!(
                    event = "login.upstream.saml.refused",
                    outcome = "refused",
                    connection = name,
                    "SAML upstream answer refused"
                );
                return Reply::problem(UPSTREAM_FAILED);
            }
        };
        // §10.6.1
        let mut input = facts.issuer.as_bytes().to_vec();
        input.push(0);
        input.extend_from_slice(facts.id.as_bytes());
        let key = suiss_crypto::digest::context_digest(ASSERTION_ID_CONTEXT, &input).0;
        let end = sp_saml::bearer_end(&facts).unwrap_or(now);
        let day = u32::try_from(end / 86_400_000).unwrap_or(u32::MAX);
        let replay = access_identity_oauth::adapters::dpop::PgReplayCache::new(
            self.db.clone(),
            kit.tenant,
            kit.realm,
        );
        match replay.first_use(day, key).await {
            Ok(true) => {}
            Ok(false) => return Reply::problem(UPSTREAM_FAILED),
            Err(_) => return unavailable(),
        }
        let Ok(signed) = saml_sign_in(&c, &facts, declared, &message) else {
            return Reply::problem(UPSTREAM_FAILED);
        };
        // IDP-27
        let assurance = mapped(map.as_deref(), &signed.declared);
        let display = c
            .profile
            .display_name
            .clone()
            .unwrap_or_else(|| c.name.clone());
        self.complete_upstream(&kit, b, name, (&signed, assurance, true), None, &display)
            .await
    }
}
