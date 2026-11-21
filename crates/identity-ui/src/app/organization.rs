//! The organization step of a sign-in for an app that asked for the `organization` scope
//! (TN-177): a person in more than one organization chooses which one to continue with. The
//! choice is context for the app's `organization` claim, never authority; authority comes from
//! Grants on each action. Organization names are attacker input, answered as text.

use access_identity_account::domain::login::Problem;
use access_identity_oauth::domain::request::{AuthRequest, Params, REQUEST_URI_PREFIX};
use access_identity_oauth::domain::scope::ORGANIZATION;
use access_identity_oauth::ports::EnvironmentEntry;
use access_identity_session::ports::Clock;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::identity::TenantTx;
use serde_json::json;

use super::{Browser, Hosted, Reply};
use crate::ports::{EnvironmentKit, Kits, Messages};

/// No live request is waiting, or it does not ask for what the step does.
pub const NO_WAITING_REQUEST: Problem = Problem {
    status: 404,
    code: "no-waiting-request",
    title: "There is no request waiting here",
    retry_after_s: None,
};

const UNAVAILABLE: Problem = Problem {
    status: 503,
    code: "unavailable",
    title: "Temporarily unavailable",
    retry_after_s: Some(1),
};

/// The waiting request and its app.
struct Waiting {
    client: [u8; 16],
    app: String,
    request: AuthRequest,
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// The live request `return_to` names, of an active client.
    async fn waiting(&self, kit: &EnvironmentKit, return_to: &str) -> Result<Waiting, Reply> {
        let issuer = access_identity_oauth::domain::issuer::Issuer::parse(&kit.issuer)
            .map_err(|_| Reply::problem(UNAVAILABLE))?;
        if !access_identity_oauth::domain::login::return_to_ok(&issuer, return_to) {
            return Err(Reply::problem(NO_WAITING_REQUEST));
        }
        let query = return_to.split_once('?').map_or("", |(_, q)| q);
        let params = Params::parse(query).map_err(|_| Reply::problem(NO_WAITING_REQUEST))?;
        let handle = params
            .get("request_uri")
            .and_then(|u| u.strip_prefix(REQUEST_URI_PREFIX))
            .and_then(|h| b64url_decode(h).ok())
            .ok_or_else(|| Reply::problem(NO_WAITING_REQUEST))?;
        let hash = access_crypto::oauth::opaque_digest(
            access_identity_oauth::app::oauth::REQUEST_CONTEXT,
            &handle,
        );
        let now = self.clock.now_ms();
        let from_day = i32::try_from((now / 86_400_000).saturating_sub(1)).unwrap_or(i32::MAX);
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.environment).await?;
            let row = t.oauth_request(from_day, &hash).await?.filter(|r| {
                r.used_ms.is_none() && u64::try_from(r.expires_ms).is_ok_and(|e| e > now)
            });
            let client = match &row {
                Some(r) => access_store::idp::client_by_uuid(&mut t, r.client)
                    .await?
                    .filter(|c| c.active),
                None => None,
            };
            t.commit().await?;
            Ok::<_, access_store::StoreError>((row, client))
        };
        let (row, client) = read.await.map_err(|_| Reply::problem(UNAVAILABLE))?;
        let (Some(row), Some(client)) = (row, client) else {
            return Err(Reply::problem(NO_WAITING_REQUEST));
        };
        let Ok(request) = serde_json::from_slice::<AuthRequest>(&row.params) else {
            return Err(Reply::problem(NO_WAITING_REQUEST));
        };
        if params.get("client_id") != Some(client.client_id.as_str()) {
            return Err(Reply::problem(NO_WAITING_REQUEST));
        }
        Ok(Waiting {
            client: client.client_uuid,
            app: client.display_name,
            request,
        })
    }

    /// The waiting request when it asks for the `organization` scope.
    async fn waiting_for_organization(
        &self,
        kit: &EnvironmentKit,
        return_to: &str,
    ) -> Result<Waiting, Reply> {
        let w = self.waiting(kit, return_to).await?;
        if w.request.scope.iter().any(|s| s == ORGANIZATION) {
            Ok(w)
        } else {
            Err(Reply::problem(NO_WAITING_REQUEST))
        }
    }

    /// `POST /v1/login/decline` (TN-178, X-L8): the person did not accept the environment's
    /// documents; the waiting request goes back to the app as `access_denied` with its `state` and
    /// `iss`. The sign-in it waited for never completes; nothing is stored.
    pub async fn decline_waiting(&self, entry: &EnvironmentEntry, return_to: &str) -> Reply {
        use access_identity_oauth::domain::request::{AuthError, error_redirect};
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let w = match self.waiting(&kit, return_to).await {
            Ok(w) => w,
            Err(r) => return r,
        };
        let Ok(issuer) = access_identity_oauth::domain::issuer::Issuer::parse(&kit.issuer) else {
            return Reply::problem(UNAVAILABLE);
        };
        let to = error_redirect(
            &w.request.redirect_uri,
            AuthError::ACCESS_DENIED,
            w.request.state.as_deref(),
            &issuer,
        );
        Reply::json(200, json!({ "redirect_to": to }))
    }

    async fn live_organizations(
        &self,
        kit: &EnvironmentKit,
        subject: [u8; 16],
    ) -> Result<Vec<([u8; 16], String)>, Reply> {
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.environment).await?;
            let orgs = t.live_organizations_of(subject).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(orgs)
        };
        read.await.map_err(|_| Reply::problem(UNAVAILABLE))
    }

    /// `POST /v1/login/organization/preview` (TN-177): the app and the person's organizations
    /// for "Which organization do you want to continue with?".
    pub async fn organization_preview(
        &self,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
        return_to: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let waiting = match self.waiting_for_organization(&kit, return_to).await {
            Ok(w) => w,
            Err(r) => return r,
        };
        let orgs = match self.live_organizations(&kit, subject).await {
            Ok(o) => o,
            Err(r) => return r,
        };
        Reply::json(
            200,
            json!({
                "app": waiting.app,
                "organizations": orgs
                    .iter()
                    .map(|(party, name)| json!({ "id": b64url_encode(party), "name": name }))
                    .collect::<Vec<_>>(),
            }),
        )
    }

    /// `POST /v1/login/organization` (TN-177): continues the waiting request with one of the
    /// person's live organizations; the browser goes back to the request.
    pub async fn choose_organization(
        &self,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
        return_to: &str,
        organization: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let subject = match self.fresh(&kit, b, None).await {
            Ok((s, _)) => s,
            Err(r) => return r,
        };
        let waiting = match self.waiting_for_organization(&kit, return_to).await {
            Ok(w) => w,
            Err(r) => return r,
        };
        let Some(party) = b64url_decode(organization)
            .ok()
            .and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
        else {
            return Reply::problem(NO_WAITING_REQUEST);
        };
        let now = self.clock.now_ms();
        let write = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.environment).await?;
            let live = t
                .live_organizations_of(subject)
                .await?
                .iter()
                .any(|(p, _)| *p == party);
            if live {
                t.choose_organization(subject, waiting.client, party, now)
                    .await?;
            }
            t.commit().await?;
            Ok::<_, access_store::StoreError>(live)
        };
        match write.await {
            Ok(true) => Reply::json(200, json!({ "redirect_to": return_to })),
            Ok(false) => Reply::problem(NO_WAITING_REQUEST),
            Err(_) => Reply::problem(UNAVAILABLE),
        }
    }
}
