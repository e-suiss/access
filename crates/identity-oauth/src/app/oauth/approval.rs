//! The Approval Surface's side of an authorization by a client the realm did not register
//! (§11.6, P58, EI-18, OP-154 m.3 (k)): what the consent screen shows, read from the waiting
//! request and the client's snapshot, and the consent record kept once the person's own
//! `grant.issue` is allowed. The screen is never a decision: a record names a Grant that stands,
//! held by and signed for the signed-in person, or nothing is kept.

use access_crypto::oauth::opaque_digest;
use access_identity_session::domain::dbsc::split_cookie;
use access_identity_session::domain::session::cookie_digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{HoldingRef, Payload};
use access_kernel::model::{Id, Window};
use access_store::clients::NewConsentRecord;

use super::authorize::{REQUEST_CONTEXT, consent_resource};
use super::{Env, OAuth, Realm, bound_live, decode32, from_day, session_live, unsigned};
use crate::domain::cimd::{self, loopback_only, new_app, redirect_hosts};
use crate::domain::client::Client;
use crate::domain::login::return_to_ok;
use crate::domain::request::{AuthError, AuthRequest, Params, REQUEST_URI_PREFIX, error_redirect};
use crate::ports::Unavailable;
use crate::ports::oauth::{OAuthDb, OAuthTx};

/// What the consent screen shows (AS-M14, AG-6, AG-5, §11.3): the hostnames always, the
/// client's name and logo only as its own claim.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one warning the screen shows"
)]
pub struct ApprovalView {
    /// The client's `client_id`.
    pub client_id: String,
    /// The hostname of its `client_id` (§11.3.6 §8.5).
    pub client_host: String,
    /// What the client calls itself; authority-opaque.
    pub client_says: String,
    /// Whether a prefetched logo is served for it.
    pub logo: bool,
    /// The hostnames of its redirect URIs, always shown.
    pub redirect_hosts: Vec<String>,
    /// Every redirect is a loopback one: the extra warning (AG-6).
    pub loopback_only: bool,
    /// First seen less than seven days ago (OP-154 m.3 (i)).
    pub new_app: bool,
    /// Its name or logo changed since it was first seen (AG-5).
    pub visual_changed: bool,
    /// The protected resource the Grant is for.
    pub resource: String,
    /// The scopes asked for.
    pub scopes: Vec<String>,
    /// The `grant.issue` the person signs to approve; `None` when they hold nothing they may
    /// pass on, so nothing can be approved (EI-18).
    pub draft: Option<ApprovalDraft>,
}

/// The `grant.issue` Exercise the consent page has the person's device Instance sign (EI-18,
/// §11.6): a Grant to themselves from a holding of theirs, in the realm's governing domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalDraft {
    /// The governing domain.
    pub domain: [u8; 32],
    /// The intent, valid while the request may be approved.
    pub envelope: IntentEnvelope,
    /// The encoded `grant_issue` payload.
    pub payload: Vec<u8>,
    /// The holding the Exercise is based on.
    pub basis: HoldingRef,
}

/// How long a waiting request may be approved after it was stored (§11.6 rule 3, OP-154 m.3 (k)).
pub const CONSENT_STATE_TTL_MS: u64 = 10 * 60 * 1000;

const CSRF_CONTEXT: &str = "access/consent-csrf/v1";

/// The consent page's CSRF token for the request `return_to` names, bound to the session
/// cookie `cookie` (§11.4.5 #28): only a page of this origin that read the session's own
/// preview knows it. `None` when either is malformed.
#[must_use]
pub fn consent_csrf(cookie: &str, return_to: &str) -> Option<String> {
    let value = decode32(split_cookie(cookie).0)?;
    let handle = request_handle(return_to)?;
    let mut bound = Vec::with_capacity(64);
    bound.extend_from_slice(&value);
    bound.extend_from_slice(&opaque_digest(REQUEST_CONTEXT, &handle));
    Some(b64url_encode(&opaque_digest(CSRF_CONTEXT, &bound)))
}

fn request_handle(return_to: &str) -> Option<Vec<u8>> {
    let query = return_to.split_once('?').map_or("", |(_, q)| q);
    Params::parse(query)
        .ok()
        .and_then(|p| p.get("request_uri").map(String::from))
        .and_then(|u| u.strip_prefix(REQUEST_URI_PREFIX).map(String::from))
        .and_then(|h| b64url_decode(&h).ok())
}

/// Why nothing is shown or kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotApproved {
    /// No live session: the person signs in first (§11.6 rule 5).
    SignIn,
    /// No open request of a client that needs the Approval Surface at that `return_to`.
    NoRequest,
    /// No standing Grant from an allowed `grant.issue` of this person (EI-18).
    NoGrant,
}

struct Waiting {
    client: Client,
    request: AuthRequest,
    subject: [u8; 16],
}

impl<E: Env> OAuth<E> {
    async fn waiting(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        cookie: Option<&str>,
        return_to: &str,
        now: u64,
    ) -> Result<Result<Waiting, NotApproved>, Unavailable> {
        // §11.6 rule 5, Ek B 4541
        let session = match cookie.and_then(|c| decode32(split_cookie(c).0).map(|v| (c, v))) {
            Some((c, value)) => tx
                .session_by_cookie(&cookie_digest(&value))
                .await?
                .filter(|s| session_live(s, now) && bound_live(s, c, now)),
            None => None,
        };
        let Some(session) = session else {
            return Ok(Err(NotApproved::SignIn));
        };
        if !return_to_ok(&realm.issuer, return_to) {
            return Ok(Err(NotApproved::NoRequest));
        }
        let Some(handle) = request_handle(return_to) else {
            return Ok(Err(NotApproved::NoRequest));
        };
        let hash = opaque_digest(REQUEST_CONTEXT, &handle);
        // §11.6 rule 3, Ek B 4540
        let Some(row) = tx.request(from_day(now), &hash).await?.filter(|r| {
            r.used_ms.is_none()
                && unsigned(r.expires_ms) > now
                && unsigned(r.created_ms).saturating_add(CONSENT_STATE_TTL_MS) > now
        }) else {
            return Ok(Err(NotApproved::NoRequest));
        };
        let Ok(request) = serde_json::from_slice::<AuthRequest>(&row.params) else {
            return Err(Unavailable);
        };
        let url = match tx.cimd_client_by_uuid(row.client).await? {
            Some(u) => Some(u),
            None => tx.dcr_client_by_uuid(row.client).await?,
        };
        let Some(url) = url else {
            return Ok(Err(NotApproved::NoRequest));
        };
        let Some(client) = self
            .client_of(tx, &url)
            .await?
            .filter(Client::approval_required)
        else {
            return Ok(Err(NotApproved::NoRequest));
        };
        if consent_resource(&request).is_none() {
            return Ok(Err(NotApproved::NoRequest));
        }
        Ok(Ok(Waiting {
            client,
            request,
            subject: session.subject,
        }))
    }

    /// What the consent screen for the request `return_to` names shows, for the signed-in
    /// person (§11.6, AS-M14).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn approval_view(
        &self,
        realm: &Realm,
        cookie: Option<&str>,
        return_to: &str,
    ) -> Result<Result<ApprovalView, NotApproved>, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let w = match self.waiting(&mut tx, realm, cookie, return_to, now).await? {
            Ok(w) => w,
            Err(n) => return Ok(Err(n)),
        };
        let party = tx.subject_party(w.subject).await?;
        let domain = tx.governing().await?;
        tx.commit().await?;
        let draft = match (party, domain) {
            (Some(party), Some(domain)) => self.draft(domain, party, now).await?,
            _ => None,
        };
        let facts = w.client.cimd.clone();
        Ok(Ok(ApprovalView {
            client_host: cimd::host(&w.client.id).unwrap_or_default(),
            client_id: w.client.id.clone(),
            client_says: w.client.name.clone(),
            logo: facts.as_ref().is_some_and(|f| f.logo),
            redirect_hosts: redirect_hosts(&w.client.redirect_uris),
            loopback_only: loopback_only(&w.client.redirect_uris),
            new_app: facts
                .as_ref()
                .is_some_and(|f| new_app(f.first_seen_ms, now)),
            visual_changed: facts.is_some_and(|f| f.visual_changed_ms.is_some()),
            resource: consent_resource(&w.request)
                .map(String::from)
                .unwrap_or_default(),
            scopes: w.request.scope.clone(),
            draft,
        }))
    }

    /// The consent `grant.issue` of `party` in `domain`, valid while the request may be
    /// approved (EI-18).
    async fn draft(
        &self,
        domain: [u8; 32],
        party: [u8; 16],
        now: u64,
    ) -> Result<Option<ApprovalDraft>, Unavailable> {
        let Some(basis) = self.env.standing().consent_basis(domain, party).await? else {
            return Ok(None);
        };
        let payload = Payload::GrantIssue(basis.content);
        let validity = Window {
            from: now.saturating_sub(60_000),
            until: now.saturating_add(CONSENT_STATE_TTL_MS),
        };
        let Some(envelope) =
            access_internal_api::instances::self_signed_intent(&payload, Id(party), validity)
        else {
            return Err(Unavailable);
        };
        let bytes = access_kernel::codec::Canonical::to_bytes(&payload).map_err(|_| Unavailable)?;
        Ok(Some(ApprovalDraft {
            domain,
            envelope,
            payload: bytes,
            basis: basis.holding,
        }))
    }

    /// The person declined (X-L8): the waiting request goes back to the client with
    /// `access_denied`, and nothing is kept.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn decline_approval(
        &self,
        realm: &Realm,
        cookie: Option<&str>,
        return_to: &str,
    ) -> Result<Result<String, NotApproved>, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let w = match self.waiting(&mut tx, realm, cookie, return_to, now).await? {
            Ok(w) => w,
            Err(n) => return Ok(Err(n)),
        };
        tx.commit().await?;
        Ok(Ok(error_redirect(
            &w.request.redirect_uri,
            AuthError::ACCESS_DENIED,
            w.request.state.as_deref(),
            &realm.issuer,
        )))
    }

    /// Keeps the consent record of the request `return_to` names (§9.14.5 k.3, P58): only when
    /// `exercise` in `domain` is the signed-in person's own allowed `grant.issue`, held by
    /// their Party, whose Grant stands (EI-18). The browser then goes back to the request.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn approve(
        &self,
        realm: &Realm,
        cookie: Option<&str>,
        return_to: &str,
        domain: [u8; 32],
        exercise: [u8; 32],
    ) -> Result<Result<String, NotApproved>, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let w = match self.waiting(&mut tx, realm, cookie, return_to, now).await? {
            Ok(w) => w,
            Err(n) => return Ok(Err(n)),
        };
        let party = tx.subject_party(w.subject).await?;
        if tx.governing().await? != Some(domain) {
            return Ok(Err(NotApproved::NoGrant));
        }
        let issued = self.env.standing().issued(domain, exercise).await?;
        // EI-18, §11.6, Ek B 4542
        let Some(issued) = issued.filter(|g| party.is_some_and(|p| p == g.holder && p == g.signer))
        else {
            return Ok(Err(NotApproved::NoGrant));
        };
        let resource = consent_resource(&w.request).unwrap_or_default();
        let metadata_hash = w.client.cimd.as_ref().map_or([0; 32], |f| f.metadata_hash);
        tx.put_consent_record(&NewConsentRecord {
            subject: w.subject,
            client: w.client.uuid,
            source: w.client.trust.as_str(),
            resource,
            scopes: &w.request.scope,
            metadata_hash,
            grant_domain: domain,
            grant_ref: issued.grant,
            exercise,
            now_ms: now,
        })
        .await?;
        tx.commit().await?;
        Ok(Ok(String::from(return_to)))
    }
}
