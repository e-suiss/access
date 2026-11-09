//! The hosted Approval Surface (OP-150 m.3 (r), OP-149 m.9, §9.14.1 A, §9.14.5 WYSIWYS): a
//! coordinator's pushed request is shown as the decision point rendered it, the signed-in
//! approver's one passkey assertion commits to H(AAS), the `authentication` Claim bound to the
//! statement is issued at once through the realm's Claim courier (SI-5) and the contribution is
//! committed as PEP. Everything the surface refuses is a decision, not an error (OP-64).

use access_identity_account::app::claims::Issued;
use access_identity_account::domain::claims::{self, AuthFacts, Bind, assertion_evidence};
use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::claims::levels;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::domain::assurance::{Factor, vector};
use access_identity_webauthn::domain::assurance::Binding as KeyBinding;
use access_identity_webauthn::domain::ceremony::{AuthenticationState, verify_assertion};
use access_identity_webauthn::domain::ids::{CredentialId, UserHandle};
use access_identity_webauthn::domain::options::{CredentialDescriptor, request_options};
use access_identity_webauthn::ports::CredentialRegistry;
use access_internal_api::approvals::Contribution;
use access_internal_api::claims::ClaimVerdict;
use access_internal_api::idp::Verdict;
use access_kernel::aas::{self, Act, ApprovalAct};
use access_kernel::assurance;
use access_kernel::claim::body::{AuthMethod, WebauthnDetail};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::model::Id;
use access_kernel::render;
use access_kernel::tier::Tier;
use access_kernel::verify::cose::{self, PublicKey};
use access_kernel::verify::key_scope::thumbprint;
use access_store::approvals::{self as store, ApprovalRow, NewApproval};
use access_store::identity::TenantTx;
use access_store::idp;
use access_store::issuer::{DeviceKeyRow, subject_device_keys};
use serde_json::{Value, json};
use suiss_crypto::dcbor::{self, Limits};

use super::me::{Devices, governing, unavailable};
use super::{Browser, Hosted, Reply, SESSION_REQUIRED, failed, signin};
use crate::app::credential;
use crate::domain::approval::{
    ApprovalFinish, ApprovalPush, ApprovalStart, ContributionEnvelope, Envelope, FieldView,
    PAGE_HTML, Pushed, RenderView, SURFACE_PROFILE, SURFACE_VERSION, cooling_text, envelope,
    kept_until, pushed, request_digest, request_uri,
};
use crate::domain::frontend::{
    ApprovalRequest, ApproveQuery, ApproveRejection, approval_redirect, approval_request, rfc3339,
};
use crate::ports::{ApprovalClaims, Approvals, Kits, Messages, RealmKit};

fn problem(status: u16, code: &'static str, title: &'static str) -> Reply {
    Reply::problem(Problem {
        status,
        code,
        title,
        retry_after_s: None,
    })
}

const UNKNOWN: Problem = Problem {
    status: 404,
    code: "approval-request-unknown",
    title: "This request is not waiting for an approval here",
    retry_after_s: None,
};

const CHANGED: Problem = Problem {
    status: 409,
    code: "approval-request-changed",
    title: "The request changed after you approved it; nothing was approved",
    retry_after_s: None,
};

fn tier_of(code: u8) -> Option<Tier> {
    match code {
        0 => Some(Tier::Ct0),
        1 => Some(Tier::Ct1),
        2 => Some(Tier::Ct2),
        3 => Some(Tier::Ct3),
        _ => None,
    }
}

/// The `kid` of a `COSE_Sign1`'s protected header.
fn kid_of(sign1: &[u8]) -> Option<[u8; 32]> {
    let msg = cose::parse_sign1(sign1).ok()?;
    let header = dcbor::decode(&msg.protected, Limits::CEILING).ok()?;
    let dcbor::Value::Map(entries) = header else {
        return None;
    };
    entries.iter().find_map(|(k, v)| match (k, v) {
        (dcbor::Value::Unsigned(cose::KID), dcbor::Value::Bytes(b)) => {
            <[u8; 32]>::try_from(b.as_slice()).ok()
        }
        _ => None,
    })
}

fn public_key(row: &DeviceKeyRow) -> Option<PublicKey> {
    match row.key_type.as_str() {
        "OKP" => <[u8; 32]>::try_from(row.public_key.as_slice())
            .ok()
            .map(PublicKey::Ed25519),
        "EC2" => Some(PublicKey::P256(row.public_key.clone())),
        _ => None,
    }
}

/// The pushed request a call names, if it is kept and not expired.
async fn find(
    t: &mut TenantTx,
    named: &ApprovalRequest,
    now: u64,
) -> Result<Option<ApprovalRow>, access_store::StoreError> {
    let row = match named {
        ApprovalRequest::Digest(d) => store::approval_by_digest(t, d).await?,
        ApprovalRequest::RequestUri(u) => store::approval_by_uri(t, u).await?,
    };
    Ok(row.filter(|r| r.expires_ms > now))
}

/// Whether `redirect_uri` is exactly a return address a client registered (RFC 6749 §3.1.2): a
/// client of this realm, or a platform product's client in the platform realm, which needs no
/// registration in the tenant realm (OP-149 m.33 (d)).
async fn registered_redirect(
    t: &mut TenantTx,
    products: &access_store::Pool,
    redirect_uri: &str,
) -> Result<bool, access_store::StoreError> {
    if !idp::clients_with_redirect(t, redirect_uri)
        .await?
        .is_empty()
    {
        return Ok(true);
    }
    Ok(!idp::platform_clients_with_redirect(products, redirect_uri)
        .await?
        .is_empty())
}

/// The call's checks shared by the page and the flow: parameters, a registered redirect URI, a
/// kept request.
async fn call(
    db: &access_store::Pool,
    products: &access_store::Pool,
    kit: &RealmKit,
    query: &ApproveQuery,
    now: u64,
) -> Result<ApprovalRow, Reply> {
    let named = approval_request(query)
        .map_err(|e| problem(400, e.code(), "The approval call is not valid"))?;
    let mut t = TenantTx::begin(db, kit.tenant, kit.realm)
        .await
        .map_err(|_| unavailable())?;
    if !registered_redirect(&mut t, products, &query.redirect_uri)
        .await
        .map_err(|_| unavailable())?
    {
        return Err(problem(
            400,
            ApproveRejection::RedirectUri.code(),
            "The approval call is not valid",
        ));
    }
    let row = find(&mut t, &named, now).await.map_err(|_| unavailable())?;
    t.commit().await.map_err(|_| unavailable())?;
    row.ok_or_else(|| Reply::problem(UNKNOWN))
}

fn render_view(r: &render::Render, reason: &str, tier: Tier, expires_at: u64) -> RenderView {
    RenderView {
        fields: r
            .fields
            .iter()
            .map(|f| FieldView {
                name: f.name.clone(),
                text: f.text.clone(),
                material: f.material,
            })
            .collect(),
        reason: String::from(reason),
        tier: match tier {
            Tier::Ct0 => 0,
            Tier::Ct1 => 1,
            Tier::Ct2 => 2,
            Tier::Ct3 => 3,
        },
        expires_at: rfc3339(expires_at),
    }
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: crate::ports::Clock + Sync,
    M: Messages,
{
    /// `POST /v1/approve/requests` (OP-149 m.9, XI-7): keeps a coordinator's request and the
    /// approver's pre-signed contribution until the request expires.
    pub async fn push_approval(&self, entry: &RealmEntry, body: &ApprovalPush) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let now = self.clock.now_ms();
        let p = match pushed(&body.request) {
            Ok(p) => p,
            Err(e) => return problem(400, e.code(), "The pushed request is not valid"),
        };
        if let Err(e) = envelope(&body.contribution) {
            return problem(400, e.code(), "The pushed contribution is not valid");
        }
        let until = match kept_until(p.expires_at, now) {
            Ok(u) => u,
            Err(e) => return problem(400, e.code(), "The pushed request has expired"),
        };
        let (Ok(request), Ok(contribution)) = (
            serde_json::to_vec(&body.request),
            serde_json::to_vec(&body.contribution),
        ) else {
            return problem(400, "invalid-request", "The request is not valid");
        };
        if request.len() > crate::domain::approval::MAX_PUSH_BYTES
            || contribution.len() > crate::domain::approval::MAX_PUSH_BYTES
        {
            return problem(413, "invalid-request", "The pushed request is too large");
        }
        let mut random = [0; 32];
        if access_identity_session::ports::Random::fill(
            &access_identity_session::adapters::OsRandom,
            &mut random,
        )
        .is_err()
        {
            return unavailable();
        }
        let uri = request_uri(&random);
        let digest = request_digest(&request);
        let stored = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            store::push_approval(
                &mut t,
                &NewApproval {
                    digest,
                    request_uri: &uri,
                    request: &request,
                    contribution: &contribution,
                    expires_ms: until,
                },
            )
            .await?;
            t.commit().await
        };
        match stored.await {
            Ok(()) => Reply::json(
                201,
                json!({
                    "request_uri": uri,
                    "digest": b64url_encode(&digest),
                    "expires_at": rfc3339(until),
                }),
            ),
            Err(_) => unavailable(),
        }
    }

    /// `GET /v1/approve` (OP-149 m.9): the call contract's checks, then the page. Nothing
    /// redirects before `redirect_uri` is one a client of the realm registered; an unknown or
    /// expired request is `approval-request-unknown`.
    pub async fn approve(&self, entry: &RealmEntry, query: &ApproveQuery) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        match call(&self.db, &self.products, &kit, query, self.clock.now_ms()).await {
            Ok(_) => Reply::html(PAGE_HTML),
            Err(r) => r,
        }
    }

    /// `POST /v1/approve/flows` (§9.14.1 A step 2): the signed-in approver opens the pushed
    /// request; the statement is built from the render the decision point kept and the
    /// approver's device Instance whose key signed the contribution.
    pub async fn start_approval<A, I, P: Approvals, Q>(
        &self,
        devices: &Devices<A, I, P, Q>,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &ApprovalStart,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let now = self.clock.now_ms();
        let query = ApproveQuery {
            request: body.request.clone(),
            redirect_uri: body.redirect_uri.clone(),
            state: body.state.clone(),
        };
        let row = match call(&self.db, &self.products, &kit, &query, now).await {
            Ok(r) => r,
            Err(r) => return r,
        };
        let session = match self.approver_session(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let (p, env) = match self.opened(&kit, &row).await {
            Ok(o) => o,
            Err(r) => return r,
        };
        // §9.14.1
        let approver = match self.approver(&kit, &session.subject, &env.ais).await {
            Ok(Some(a)) => a,
            Ok(None) => {
                return problem(
                    403,
                    "approver-instance",
                    "No device of yours signed this contribution",
                );
            }
            Err(r) => return r,
        };
        // §9.14.5
        let opening = match devices.approvals.opening(p.domain, p.intent).await {
            Ok(Some(o)) => o,
            Ok(None) => return Reply::problem(CHANGED),
            Err(_) => return unavailable(),
        };
        let (Some(tier), Some(shown)) = (
            tier_of(opening.tier),
            opening
                .render
                .as_deref()
                .and_then(|bytes| render::decode(bytes).ok()),
        ) else {
            return Reply::problem(CHANGED);
        };
        let act = statement_of(
            &p,
            &env,
            &approver,
            opening.render_digest,
            &shown,
            tier,
            now,
        );
        let expires_at = act.expires_at;
        let (Ok(aas_bytes), Ok(statement)) = (act.to_bytes(), aas::digest(&act)) else {
            return unavailable();
        };
        let options = match self
            .options(&kit, &session.subject, &statement.0, tier)
            .await
        {
            Ok(o) => o,
            Err(r) => return r,
        };
        let started = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let ok =
                store::start_approval(&mut t, &row.id, &session.id, &statement.0, &aas_bytes, now)
                    .await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(ok)
        };
        match started.await {
            Ok(true) => {}
            Ok(false) => {
                return problem(409, "approval-started", "This request was opened already");
            }
            Err(_) => return unavailable(),
        }
        let view = render_view(&shown, &p.reason, tier, expires_at);
        Reply::json(
            201,
            json!({
                "flow": b64url_encode(&row.id),
                "render": view,
                "options": options,
            }),
        )
    }

    /// The live session of the approver's browser.
    async fn approver_session(
        &self,
        kit: &RealmKit,
        b: &Browser<'_>,
    ) -> Result<access_identity_session::app::sessions::SessionView, Reply> {
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Err(Reply::problem(SESSION_REQUIRED));
        };
        match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => Ok(*v),
            Ok(_) => Err(Reply::problem(SESSION_REQUIRED)),
            Err(e) => Err(failed(&e)),
        }
    }

    /// The pushed request and contribution of `row`, in this realm's domain.
    async fn opened(&self, kit: &RealmKit, row: &ApprovalRow) -> Result<(Pushed, Envelope), Reply> {
        let (Ok(request), Ok(contribution)) = (
            serde_json::from_slice::<Value>(&row.request),
            serde_json::from_slice::<ContributionEnvelope>(&row.contribution),
        ) else {
            return Err(unavailable());
        };
        let (Ok(p), Ok(env)) = (pushed(&request), envelope(&contribution)) else {
            return Err(unavailable());
        };
        let domain = governing(&self.db, kit).await?;
        if p.domain != domain {
            return Err(problem(
                400,
                "approval-domain",
                "The request is not in this realm's domain",
            ));
        }
        Ok((p, env))
    }

    /// The approver: the session subject's active device Instance whose key signed `ais`.
    async fn approver(
        &self,
        kit: &RealmKit,
        subject: &[u8; 16],
        ais: &[u8],
    ) -> Result<Option<Approver>, Reply> {
        let Some(kid) = kid_of(ais) else {
            return Ok(None);
        };
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let keys = subject_device_keys(&mut t, subject)
            .await
            .map_err(|_| unavailable())?;
        let party = idp::subject_party(&mut t, subject)
            .await
            .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        let Some(party) = party else {
            return Ok(None);
        };
        Ok(keys
            .iter()
            .filter_map(|k| public_key(k).map(|pk| (k.instance, pk)))
            .find(|(_, pk)| thumbprint(pk) == kid)
            .map(|(instance, _)| Approver {
                instance: Id(instance),
                party: Id(party),
            }))
    }

    /// The assertion options over `challenge` (H(AAS)) for the subject's passkeys; UV is
    /// required from CT2 (§13.7.3).
    async fn options(
        &self,
        kit: &RealmKit,
        subject: &[u8; 16],
        challenge: &[u8; 32],
        tier: Tier,
    ) -> Result<Value, Reply> {
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let handle = t.user_handle(*subject).await.map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        let Some(handle) = handle else {
            return Err(problem(
                403,
                "approver-passkey",
                "Add a passkey to approve requests",
            ));
        };
        let registry = access_identity_session::adapters::passkeys::PgPasskeys {
            pool: &self.db,
            tenant: kit.tenant,
            kek: &*kit.kek,
            ids: &kit.ids,
        };
        let records = registry
            .list(kit.rp.realm, &UserHandle::from_bytes(handle))
            .await
            .map_err(|_| unavailable())?;
        if records.is_empty() {
            return Err(problem(
                403,
                "approver-passkey",
                "Add a passkey to approve requests",
            ));
        }
        let allow: Vec<CredentialDescriptor> = records
            .iter()
            .map(|r| CredentialDescriptor {
                id: r.id.clone(),
                transports: r.transports.clone(),
            })
            .collect();
        let mut options = request_options(&kit.rp, &kit.webauthn, challenge, &allow);
        if tier >= Tier::Ct2
            && let Some(o) = options.as_object_mut()
        {
            o.insert(String::from("userVerification"), json!("required"));
        }
        Ok(options)
    }

    /// `POST /v1/approve/flows/{flow}` (§9.14.1 A steps 3 and 4): the assertion over H(AAS)
    /// becomes the `authentication` Claim bound to the statement, issued at once, and the
    /// contribution is committed with the statement and the Claim.
    pub async fn finish_approval<A, I, P: Approvals, Q: ApprovalClaims>(
        &self,
        devices: &Devices<A, I, P, Q>,
        entry: &RealmEntry,
        b: &Browser<'_>,
        flow: &str,
        body: &ApprovalFinish,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let now = self.clock.now_ms();
        let session = match self.approver_session(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let credential_json = match &body.credential {
            Value::String(t) => t.clone(),
            other => other.to_string(),
        };
        let Some(assertion) = credential::assertion(&credential_json) else {
            return problem(400, "invalid-request", "The credential does not decode");
        };
        let (row, statement, aas_bytes) = match self.started(&kit, flow, &session.id, now).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let query = ApproveQuery {
            request: row.request_uri.clone(),
            redirect_uri: body.redirect_uri.clone(),
            state: body.state.clone(),
        };
        if let Err(r) = call(&self.db, &self.products, &kit, &query, now).await {
            return r;
        }
        let (Ok(act_value), Ok(contribution)) = (
            dcbor::decode(&aas_bytes, Limits::CEILING),
            serde_json::from_slice::<ContributionEnvelope>(&row.contribution),
        ) else {
            return unavailable();
        };
        let (Ok(act), Ok(env)) = (ApprovalAct::from_value(&act_value), envelope(&contribution))
        else {
            return unavailable();
        };
        let tier = match still_asked(devices, &act, now).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        // §9.14.1 step 3
        let verified = match self
            .assert(&kit, &session.subject, &statement, tier, &assertion, now)
            .await
        {
            Ok(v) => v,
            Err(r) => return r,
        };
        // SEC18, §8.13
        if let Err(r) = cooled(tier, verified.created_ms, now) {
            return r;
        }
        let claim = match issue_claim(
            devices,
            &kit,
            session.subject,
            statement,
            act.instance,
            &verified,
            now,
        )
        .await
        {
            Ok(c) => c,
            Err(r) => return r,
        };
        // §9.14.1 step 4
        let verdict = devices
            .approvals
            .contribute(Contribution {
                domain: act.domain,
                nonce: env.nonce.clone(),
                target: act.target,
                class: env.class.clone(),
                basis: env.basis,
                capacity: env.capacity,
                validity: env.validity,
                ais: env.ais.clone(),
                aas: aas_bytes,
                claim,
                pep: devices.pep.clone(),
            })
            .await;
        let exercise = match committed(verdict) {
            Ok(e) => e,
            Err(r) => return r,
        };
        let finished = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let ok = store::finish_approval(&mut t, &row.id, &exercise.0, now).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(ok)
        };
        if finished.await.is_err() {
            return unavailable();
        }
        finished_reply(body, &exercise.0, &act.render_digest.0, &claim.0)
    }

    /// The started, unfinished flow `flow` of `session`: its row, H(AAS) and the statement.
    async fn started(
        &self,
        kit: &RealmKit,
        flow: &str,
        session: &[u8; 16],
        now: u64,
    ) -> Result<(ApprovalRow, [u8; 32], Vec<u8>), Reply> {
        let Some(id) = access_kernel::json::b64url_decode(flow)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            return Err(Reply::problem(UNKNOWN));
        };
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let row = store::approval(&mut t, &id)
            .await
            .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        let Some(row) = row else {
            return Err(Reply::problem(UNKNOWN));
        };
        if row.session != Some(*session) || row.expires_ms <= now {
            return Err(Reply::problem(UNKNOWN));
        }
        let (Some(statement), Some(aas), Some(_)) =
            (row.statement, row.aas.clone(), row.started_ms)
        else {
            return Err(problem(
                409,
                "approval-not-started",
                "Open the request first",
            ));
        };
        if row.finished_ms.is_some() {
            return Err(problem(
                409,
                "approval-finished",
                "This request was approved already",
            ));
        }
        Ok((row, statement, aas))
    }

    /// Verifies the assertion over `challenge` for one of the subject's passkeys and records
    /// its use.
    async fn assert(
        &self,
        kit: &RealmKit,
        subject: &[u8; 16],
        challenge: &[u8; 32],
        tier: Tier,
        assertion: &credential::Assertion,
        now: u64,
    ) -> Result<Verified, Reply> {
        let response = assertion.response();
        let Some(id) = CredentialId::new(response.raw_id) else {
            return Err(problem(
                401,
                "assertion-rejected",
                "The passkey was not accepted",
            ));
        };
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let handle = t.user_handle(*subject).await.map_err(|_| unavailable())?;
        let sibling = t
            .passkey(response.raw_id)
            .await
            .map_err(|_| unavailable())?
            .map(|p| p.credential);
        t.commit().await.map_err(|_| unavailable())?;
        let (Some(handle), Some(sibling)) = (handle, sibling) else {
            return Err(problem(
                401,
                "assertion-rejected",
                "The passkey was not accepted",
            ));
        };
        let registry = access_identity_session::adapters::passkeys::PgPasskeys {
            pool: &self.db,
            tenant: kit.tenant,
            kek: &*kit.kek,
            ids: &kit.ids,
        };
        let Some(stored) = registry
            .find(kit.rp.realm, &id)
            .await
            .map_err(|_| unavailable())?
        else {
            return Err(problem(
                401,
                "assertion-rejected",
                "The passkey was not accepted",
            ));
        };
        let now_s = now / 1_000;
        let state = AuthenticationState {
            realm: kit.rp.realm,
            challenge: *challenge,
            user: Some(UserHandle::from_bytes(handle)),
            allowed: Vec::new(),
            require_user_verification: tier >= Tier::Ct2,
            expires_at: now_s.saturating_add(1),
        };
        let verified = verify_assertion(&kit.rp, &kit.webauthn, &state, &response, &stored, now_s)
            .map_err(|e| {
                tracing::info!(error = %e, "approval assertion rejected");
                problem(401, "assertion-rejected", "The passkey was not accepted")
            })?;
        registry
            .record_use(
                kit.rp.realm,
                &id,
                verified.sign_count,
                verified.backup_state,
                now_s,
            )
            .await
            .map_err(|_| unavailable())?;
        let factor = Factor::passkey(
            sibling,
            verified.assurance.binding == KeyBinding::Synced,
            verified.assurance.user_verified,
            verified.assurance.session_login_only,
            now,
        );
        let evidence = assertion_evidence(
            response.authenticator_data,
            response.client_data_json,
            response.signature,
        );
        Ok(Verified {
            levels: levels(&vector(&[factor])),
            detail: WebauthnDetail {
                aaguid: stored.aaguid.0,
                sign_count: u64::from(verified.sign_count),
                up: true,
                uv: verified.assurance.user_verified,
                be: stored.backup_eligible,
                bs: verified.backup_state,
            },
            evidence,
            created_ms: stored.created_at.saturating_mul(1_000),
        })
    }
}

/// The approver Instance and its Party.
struct Approver {
    instance: Id,
    party: Id,
}

/// §9.14.2, XI-7: the decision point's render must still be the one the statement names, and
/// the statement must not have expired; the tier the approval is held to.
async fn still_asked<A, I, P: Approvals, Q>(
    devices: &Devices<A, I, P, Q>,
    act: &ApprovalAct,
    now: u64,
) -> Result<Tier, Reply> {
    let tier = match devices.approvals.opening(act.domain, act.target).await {
        Ok(Some(o)) if o.render_digest == act.render_digest => {
            tier_of(o.tier).ok_or_else(unavailable)?
        }
        Ok(_) => return Err(Reply::problem(CHANGED)),
        Err(e) => {
            tracing::warn!(reason = %e.0, "approval opening unavailable");
            return Err(unavailable());
        }
    };
    if now > act.expires_at {
        return Err(problem(
            409,
            "approval-expired",
            "The statement expired; open it again",
        ));
    }
    Ok(tier)
}

/// SEC18, §8.13, X38: a binding younger than 24 h meets no CT2+ approval; the refusal names
/// when it will.
fn cooled(tier: Tier, created_ms: u64, now: u64) -> Result<(), Reply> {
    assurance::cooled(tier, created_ms, now).map_err(|available| {
        Reply::json(
            403,
            json!({
                "type": "urn:suiss:access:problem:cooling",
                "status": 403,
                "code": "cooling",
                "title": cooling_text(available),
                "available_at": rfc3339(available),
            }),
        )
    })
}

/// The answer of a finished approval (`ApprovalFinished`, OP-149 m.9, m.33 (c)): where the
/// browser goes, the contribution Exercise, the render digest and the approver's Claim.
fn finished_reply(
    body: &ApprovalFinish,
    exercise: &[u8; 32],
    render: &[u8; 32],
    claim: &[u8; 16],
) -> Reply {
    Reply::json(
        200,
        json!({
            "redirect": approval_redirect(&body.redirect_uri, exercise, render, claim, &body.state),
            "exercise": b64url_encode(exercise),
            "render_digest": b64url_encode(render),
            "claim": b64url_encode(claim),
        }),
    )
}

/// SI-5, §10.1.5, OP-149 m.33 (c): the `authentication` Claim bound to the statement and to the
/// approver's Instance, issued now through the realm's courier; only an admitted Claim is a
/// proof.
async fn issue_claim<A, I, P, Q: ApprovalClaims>(
    devices: &Devices<A, I, P, Q>,
    kit: &RealmKit,
    subject: [u8; 16],
    statement: [u8; 32],
    instance: Id,
    verified: &Verified,
    now: u64,
) -> Result<Id, Reply> {
    let order = claims::authentication(AuthFacts {
        subject,
        method: AuthMethod::Webauthn,
        auth_time: now,
        assurance: verified.levels.clone(),
        webauthn: Some(verified.detail),
        evidence: Some(verified.evidence),
        bind: Bind::Statement {
            statement,
            instance: instance.0,
        },
    });
    match devices.claims.issue(kit.tenant, kit.realm, &order).await {
        Ok(Issued::Answered {
            claim,
            verdict: ClaimVerdict::Admitted { .. },
        }) => Ok(Id(claim)),
        Ok(Issued::Answered { verdict, .. }) => {
            tracing::info!(?verdict, "approval claim not admitted");
            Err(problem(
                409,
                "approval-claim-not-admitted",
                "Your sign-in could not be recorded for this approval",
            ))
        }
        Ok(Issued::Unplaced(why)) => {
            tracing::warn!(why, "approval claim not placed");
            Err(unavailable())
        }
        Err(e) => {
            tracing::warn!(reason = %e.0, "approval claim unavailable");
            Err(unavailable())
        }
    }
}

/// The statement of an approval (§9.14 fields): act, approver, target, `exercise_ref`, surface,
/// render, material fields, times within the tier's ceiling.
fn statement_of(
    p: &Pushed,
    env: &Envelope,
    approver: &Approver,
    render_digest: Digest,
    shown: &render::Render,
    tier: Tier,
    now: u64,
) -> ApprovalAct {
    ApprovalAct {
        evidence: None,
        surface_class: None,
        act: Act::Contribution(env.class.clone()),
        instance: approver.instance,
        party: approver.party,
        capacity: env.capacity,
        target: p.intent,
        domain: p.domain,
        nonce: env.nonce.clone(),
        work_gate: None,
        surface_profile: String::from(SURFACE_PROFILE),
        surface_version: SURFACE_VERSION,
        render_digest,
        material_fields: render::material_fields(shown),
        issued_at: now,
        expires_at: now.saturating_add(assurance::aas_expiry_ceiling(tier)),
    }
}

/// The Exercise a contribution verdict names, or the reply that says why there is none: a
/// statement over another render is "the request changed" (§9.14.2); a DENY or `REQUIRE_ACTION`
/// is reported with its outcome, a refusal with its reason.
fn committed(
    verdict: Result<Verdict, access_internal_api::idp::Unavailable>,
) -> Result<Digest, Reply> {
    match verdict {
        Ok(Verdict::Committed(c)) => Ok(c.exercise),
        Ok(Verdict::NotAllowed { decision, .. }) => Err(Reply::json(
            409,
            json!({
                "type": "urn:suiss:access:problem:approval-not-allowed",
                "status": 409,
                "code": "approval-not-allowed",
                "title": "The approval was not accepted",
                "outcome": format!("{:?}", decision.outcome).to_lowercase(),
            }),
        )),
        Ok(Verdict::Refused { code, .. }) if code.starts_with("aas-render") => {
            Err(Reply::problem(CHANGED))
        }
        Ok(Verdict::Refused { code, errors }) => {
            tracing::info!(%code, ?errors, "approval refused");
            // OP-149 m.24 (b), m.30 (b)
            let mut problem = json!({
                "type": "urn:suiss:access:problem:approval-refused",
                "status": 409,
                "code": "approval-refused",
                "title": "The approval was refused",
                "reason": code,
            });
            if let (Some(members), false) = (problem.as_object_mut(), errors.is_empty()) {
                members.insert(
                    String::from("errors"),
                    errors.iter().map(|code| json!({ "code": code })).collect(),
                );
            }
            Err(Reply::json(409, problem))
        }
        Err(e) => {
            tracing::warn!(reason = %e.0, "contribution unavailable");
            Err(unavailable())
        }
    }
}

/// What a verified approval assertion established.
struct Verified {
    levels: std::collections::BTreeMap<String, u64>,
    detail: WebauthnDetail,
    evidence: Digest,
    created_ms: u64,
}
