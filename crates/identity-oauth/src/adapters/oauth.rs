//! Adapters of the authorization server ports: the realm's PostgreSQL rows, the back-channel
//! courier's outbox, the identity signer, the hosted login's paths and the operating system's
//! randomness.

use access_crypto::jose::JwsAlg;
use access_identity_signer::protocol::{Realm, Request, Response};
use access_identity_signer::service::UNKNOWN_REALM;
use access_store::Pool;
use access_store::backchannel::LogoutUndelivered;
use access_store::clients::{CimdRow, CimdSnapshot, ConsentRecordRow};
use access_store::identity::{self, Cursor, OutboxEvent, RealmId, TenantId, TenantTx};
use access_store::idp::{self, ClientRow, PlatformClient};
use access_store::oauth::{
    CodeRow, GrantRow, NewCode, NewGrant, NewRequest, RefreshRow, RequestRow,
};
use access_store::sessions::SessionRow;

use crate::adapters::SignerKeys;
use crate::app::backchannel::CONSUMER;
use crate::domain::issuer::{Issuer, form_encode};
use crate::domain::tokens::LoginReason;
use crate::ports::oauth::{LoginPages, LogoutQueue, OAuthDb, OAuthTx, Random, TokenSigner};
use crate::ports::{Keys, Unavailable};

/// The realm rows over the application pool; platform product clients of every tenant over
/// the outbox reader (OP-149 m.26 (a)).
#[derive(Clone)]
pub struct PgOAuth {
    pool: Pool,
    reader: Option<Pool>,
}

impl PgOAuth {
    /// Over the application pool alone: no client is a resource.
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self { pool, reader: None }
    }

    /// Over the application pool and the outbox reader, which finds platform product clients
    /// across tenants (OP-149 m.26 (a)).
    #[must_use]
    pub const fn with_reader(pool: Pool, reader: Pool) -> Self {
        Self {
            pool,
            reader: Some(reader),
        }
    }
}

/// One transaction of [`PgOAuth`].
pub struct PgOAuthTx(TenantTx);

fn down<E>(_: E) -> Unavailable {
    Unavailable
}

impl OAuthDb for PgOAuth {
    type Tx = PgOAuthTx;

    async fn begin(&self, tenant: TenantId, realm: RealmId) -> Result<PgOAuthTx, Unavailable> {
        TenantTx::begin(&self.pool, tenant, realm)
            .await
            .map(PgOAuthTx)
            .map_err(down)
    }

    async fn platform_product(
        &self,
        client_id: &str,
    ) -> Result<Option<PlatformClient>, Unavailable> {
        let Some(reader) = &self.reader else {
            return Ok(None);
        };
        idp::platform_client_product(reader, client_id)
            .await
            .map_err(down)
    }
}

impl OAuthTx for PgOAuthTx {
    async fn workload_clients(
        &mut self,
    ) -> Result<Vec<access_store::workloads::WorkloadClient>, Unavailable> {
        access_store::workloads::workload_clients(&mut self.0)
            .await
            .map_err(down)
    }

    async fn client(&mut self, client_id: &str) -> Result<Option<ClientRow>, Unavailable> {
        idp::client(&mut self.0, client_id).await.map_err(down)
    }

    async fn previous_secret(&mut self, client_id: &str) -> Result<Option<[u8; 32]>, Unavailable> {
        idp::realm::previous_secret(&mut self.0, client_id)
            .await
            .map_err(down)
    }

    async fn client_by_uuid(&mut self, uuid: [u8; 16]) -> Result<Option<ClientRow>, Unavailable> {
        idp::client_by_uuid(&mut self.0, uuid).await.map_err(down)
    }

    async fn jose_alg(&mut self) -> Result<JwsAlg, Unavailable> {
        let s = idp::settings(&mut self.0).await.map_err(down)?;
        Ok(match s.as_ref().map(|s| s.jose_alg.as_str()) {
            Some("Ed25519") => JwsAlg::Ed25519,
            _ => JwsAlg::Es256,
        })
    }

    async fn issuer(&mut self) -> Result<Option<Issuer>, Unavailable> {
        let g = idp::governance(&mut self.0).await.map_err(down)?;
        Ok(g.and_then(|g| g.issuer)
            .and_then(|i| Issuer::parse(&i).ok()))
    }

    async fn insert_request(&mut self, r: &NewRequest<'_>) -> Result<(), Unavailable> {
        self.0.insert_oauth_request(r).await.map_err(down)
    }

    async fn request(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> Result<Option<RequestRow>, Unavailable> {
        self.0.oauth_request(from_day, hash).await.map_err(down)
    }

    async fn use_request(
        &mut self,
        day: i32,
        hash: &[u8; 32],
        at_ms: i64,
    ) -> Result<bool, Unavailable> {
        self.0
            .use_oauth_request(day, hash, at_ms)
            .await
            .map_err(down)
    }

    async fn insert_code(&mut self, c: &NewCode<'_>) -> Result<(), Unavailable> {
        self.0.insert_code(c).await.map_err(down)
    }

    async fn code(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> Result<Option<CodeRow>, Unavailable> {
        self.0.code(from_day, hash).await.map_err(down)
    }

    async fn redeem_code(
        &mut self,
        day: i32,
        hash: &[u8; 32],
        at_ms: i64,
        grant: [u8; 16],
    ) -> Result<bool, Unavailable> {
        self.0
            .redeem_code(day, hash, at_ms, grant)
            .await
            .map_err(down)
    }

    async fn assertion_first_use(&mut self, day: i32, key: &[u8; 32]) -> Result<bool, Unavailable> {
        self.0.assertion_first_use(day, key).await.map_err(down)
    }

    async fn session_by_cookie(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<SessionRow>, Unavailable> {
        self.0.session_by_cookie(hash).await.map_err(down)
    }

    async fn session(&mut self, id: [u8; 16]) -> Result<Option<SessionRow>, Unavailable> {
        self.0.session_by_id(id).await.map_err(down)
    }

    async fn end_session(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
        reason: &str,
    ) -> Result<bool, Unavailable> {
        self.0.end_session(id, at_ms, reason).await.map_err(down)
    }

    async fn end_sessions(&mut self, subject: [u8; 16]) -> Result<(), Unavailable> {
        self.0.end_sessions(subject).await.map(drop).map_err(down)
    }

    async fn recovery_grace_until(
        &mut self,
        subject: [u8; 16],
        now_ms: i64,
    ) -> Result<Option<i64>, Unavailable> {
        self.0
            .recovery_grace_until(subject, now_ms)
            .await
            .map_err(down)
    }

    async fn insert_grant(&mut self, g: &NewGrant<'_>) -> Result<[u8; 16], Unavailable> {
        self.0.insert_grant(g).await.map_err(down)
    }

    async fn grant(&mut self, id: [u8; 16]) -> Result<Option<GrantRow>, Unavailable> {
        self.0.grant(id).await.map_err(down)
    }

    async fn grant_by_sid(&mut self, sid: &[u8; 16]) -> Result<Option<GrantRow>, Unavailable> {
        self.0.grant_by_sid(sid).await.map_err(down)
    }

    async fn session_grants(&mut self, session: [u8; 16]) -> Result<Vec<GrantRow>, Unavailable> {
        self.0.session_grants(session).await.map_err(down)
    }

    async fn revoke_grant(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
        reason: &str,
    ) -> Result<bool, Unavailable> {
        self.0.revoke_grant(id, at_ms, reason).await.map_err(down)
    }

    async fn insert_refresh(
        &mut self,
        hash: &[u8; 32],
        grant: [u8; 16],
        at_ms: i64,
    ) -> Result<(), Unavailable> {
        self.0
            .insert_refresh(hash, grant, at_ms)
            .await
            .map_err(down)
    }

    async fn refresh(&mut self, hash: &[u8; 32]) -> Result<Option<RefreshRow>, Unavailable> {
        self.0.refresh(hash).await.map_err(down)
    }

    async fn rotate_refresh(&mut self, hash: &[u8; 32], at_ms: i64) -> Result<bool, Unavailable> {
        self.0.rotate_refresh(hash, at_ms).await.map_err(down)
    }

    async fn consent(
        &mut self,
        subject: [u8; 16],
        client: [u8; 16],
    ) -> Result<Option<Vec<String>>, Unavailable> {
        self.0.claim_consent(subject, client).await.map_err(down)
    }

    async fn pairwise(
        &mut self,
        subject: [u8; 16],
        sector: [u8; 16],
        candidate: &str,
    ) -> Result<String, Unavailable> {
        self.0
            .pairwise(subject, sector, candidate)
            .await
            .map_err(down)
    }

    async fn outbox(&mut self, kind: &str, payload: &[u8]) -> Result<(), Unavailable> {
        // OP-67 m.1
        let trace = access_telemetry::trace::current_header();
        self.0
            .outbox_traced(kind, payload, trace.as_deref())
            .await
            .map_err(down)
    }

    async fn governing(&mut self) -> Result<Option<[u8; 32]>, Unavailable> {
        let g = idp::governance(&mut self.0).await.map_err(down)?;
        Ok(g.map(|g| *g.domain.as_bytes()))
    }

    async fn platform_party(&mut self, client_id: &str) -> Result<Option<[u8; 16]>, Unavailable> {
        self.0.platform_party(client_id).await.map_err(down)
    }

    async fn platform_party_pairwise(
        &mut self,
        party: &[u8; 16],
        sector: [u8; 16],
        candidate: &str,
    ) -> Result<Option<String>, Unavailable> {
        self.0
            .platform_party_pairwise(party, sector, candidate)
            .await
            .map_err(down)
    }

    async fn client_pairwise(
        &mut self,
        client: [u8; 16],
        sector: [u8; 16],
        candidate: &str,
    ) -> Result<Option<String>, Unavailable> {
        self.0
            .client_pairwise(client, sector, candidate)
            .await
            .map_err(down)
    }

    async fn audit(
        &mut self,
        event_type: &str,
        actor: &str,
        target: &str,
        correlation: &str,
    ) -> Result<(), Unavailable> {
        self.0
            .audit(&access_store::audit::AuditEvent {
                event_type,
                actor,
                target,
                correlation,
            })
            .await
            .map_err(down)
    }

    async fn cimd_policy(&mut self) -> Result<(bool, Vec<String>), Unavailable> {
        let s = idp::settings(&mut self.0).await.map_err(down)?;
        Ok(s.map_or((false, Vec::new()), |s| (s.cimd_enabled, s.cimd_domains)))
    }

    async fn cimd_client(&mut self, client_id: &str) -> Result<Option<CimdRow>, Unavailable> {
        self.0.cimd_client(client_id).await.map_err(down)
    }

    async fn insert_cimd_client(
        &mut self,
        client_id: &str,
        s: &CimdSnapshot<'_>,
    ) -> Result<[u8; 16], Unavailable> {
        self.0.insert_cimd_client(client_id, s).await.map_err(down)
    }

    async fn refresh_cimd_client(
        &mut self,
        uuid: [u8; 16],
        s: &CimdSnapshot<'_>,
        visual_changed: bool,
    ) -> Result<bool, Unavailable> {
        self.0
            .refresh_cimd_client(uuid, s, visual_changed)
            .await
            .map_err(down)
    }

    async fn retire_cimd_client(
        &mut self,
        uuid: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<bool, Unavailable> {
        self.0
            .retire_cimd_client(uuid, reason, now_ms)
            .await
            .map_err(down)
    }

    async fn protected_resource(&mut self, resource: &str) -> Result<bool, Unavailable> {
        Ok(self
            .0
            .protected_resource(resource)
            .await
            .map_err(down)?
            .is_some())
    }

    async fn consent_record(
        &mut self,
        subject: [u8; 16],
        client: [u8; 16],
        resource: &str,
    ) -> Result<Option<ConsentRecordRow>, Unavailable> {
        self.0
            .consent_record(subject, client, resource)
            .await
            .map_err(down)
    }

    async fn end_consent_record(
        &mut self,
        consent: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<bool, Unavailable> {
        self.0
            .end_consent_record(consent, reason, now_ms)
            .await
            .map_err(down)
    }

    async fn subject_party(&mut self, subject: [u8; 16]) -> Result<Option<[u8; 16]>, Unavailable> {
        idp::subject_party(&mut self.0, &subject)
            .await
            .map_err(down)
    }

    async fn cimd_client_by_uuid(&mut self, uuid: [u8; 16]) -> Result<Option<String>, Unavailable> {
        self.0.cimd_client_by_uuid(uuid).await.map_err(down)
    }

    async fn device_code_enabled(&mut self) -> Result<bool, Unavailable> {
        self.0.device_code_enabled().await.map_err(down)
    }

    async fn insert_device_code(
        &mut self,
        d: &access_store::device::NewDeviceCode<'_>,
    ) -> Result<bool, Unavailable> {
        self.0.insert_device_code(d).await.map_err(down)
    }

    async fn device_code(
        &mut self,
        device_hash: &[u8; 32],
    ) -> Result<Option<access_store::device::DeviceCodeRow>, Unavailable> {
        self.0.device_code(device_hash).await.map_err(down)
    }

    async fn device_code_by_user(
        &mut self,
        user_hash: &[u8; 32],
    ) -> Result<Option<access_store::device::DeviceCodeRow>, Unavailable> {
        self.0.device_code_by_user(user_hash).await.map_err(down)
    }

    async fn poll_device_code(
        &mut self,
        device: [u8; 16],
        now_ms: u64,
        interval_s: u32,
    ) -> Result<(), Unavailable> {
        self.0
            .poll_device_code(device, now_ms, interval_s)
            .await
            .map_err(down)
    }

    async fn decide_device_code(
        &mut self,
        device: [u8; 16],
        approved: Option<([u8; 16], [u8; 16])>,
        now_ms: u64,
    ) -> Result<bool, Unavailable> {
        self.0
            .decide_device_code(device, approved, now_ms)
            .await
            .map_err(down)
    }

    async fn use_device_code(
        &mut self,
        device: [u8; 16],
        now_ms: u64,
    ) -> Result<bool, Unavailable> {
        self.0.use_device_code(device, now_ms).await.map_err(down)
    }

    async fn miss_device_code(
        &mut self,
        ip_prefix: &str,
        subject: [u8; 16],
        now_ms: u64,
    ) -> Result<(), Unavailable> {
        self.0
            .miss_device_code(ip_prefix, subject, now_ms)
            .await
            .map_err(down)
    }

    async fn device_misses(
        &mut self,
        ip_prefix: &str,
        ip_since_ms: u64,
        subject: [u8; 16],
        subject_since_ms: u64,
    ) -> Result<(u64, u64), Unavailable> {
        self.0
            .device_misses(ip_prefix, ip_since_ms, subject, subject_since_ms)
            .await
            .map_err(down)
    }

    async fn dcr_policy(&mut self) -> Result<access_store::dcr::DcrPolicyRow, Unavailable> {
        self.0.dcr_policy().await.map_err(down)
    }

    async fn cross_app_connected(
        &mut self,
        client_id: &str,
        audience: &str,
        resource: &str,
    ) -> Result<bool, Unavailable> {
        self.0
            .cross_app_connected(client_id, audience, resource)
            .await
            .map_err(down)
    }

    async fn dcr_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<access_store::dcr::DcrClientRow>, Unavailable> {
        self.0.dcr_client(client_id).await.map_err(down)
    }

    async fn dcr_client_by_uuid(&mut self, uuid: [u8; 16]) -> Result<Option<String>, Unavailable> {
        self.0.dcr_client_by_uuid(uuid).await.map_err(down)
    }

    async fn dcr_counts(
        &mut self,
        ip_prefix: &str,
        since_ms: u64,
        day_ms: u64,
    ) -> Result<(u64, u64, u64), Unavailable> {
        self.0
            .dcr_counts(ip_prefix, since_ms, day_ms)
            .await
            .map_err(down)
    }

    async fn insert_dcr_client(
        &mut self,
        c: &access_store::dcr::NewDcrClient<'_>,
    ) -> Result<[u8; 16], Unavailable> {
        self.0.insert_dcr_client(c).await.map_err(down)
    }

    async fn touch_dcr_client(&mut self, uuid: [u8; 16], now_ms: u64) -> Result<(), Unavailable> {
        self.0.touch_dcr_client(uuid, now_ms).await.map_err(down)
    }

    async fn retire_dcr_client(
        &mut self,
        uuid: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<bool, Unavailable> {
        self.0
            .retire_dcr_client(uuid, reason, now_ms)
            .await
            .map_err(down)
    }

    async fn put_consent_record(
        &mut self,
        c: &access_store::clients::NewConsentRecord<'_>,
    ) -> Result<(), Unavailable> {
        self.0.put_consent_record(c).await.map_err(down)
    }

    async fn end_client_consents(
        &mut self,
        client: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<u64, Unavailable> {
        self.0
            .end_client_consents(client, reason, now_ms)
            .await
            .map_err(down)
    }

    async fn commit(self) -> Result<(), Unavailable> {
        self.0.commit().await.map_err(down)
    }
}

/// Names the identity signer's refusal of a token (OP-67); the code is the signer's stable one.
fn refused(code: &str, typ: &str) -> Unavailable {
    tracing::warn!(code, typ, "identity signer refused to sign");
    Unavailable
}

impl TokenSigner for SignerKeys {
    async fn sign(
        &self,
        realm: RealmId,
        alg: JwsAlg,
        typ: &str,
        payload: &[u8],
        at_ms: u64,
    ) -> Result<String, Unavailable> {
        let r = Realm(*realm.as_bytes());
        let request = Request::Sign {
            realm: r,
            typ: String::from(typ),
            payload: payload.to_vec(),
            at: at_ms,
        };
        match self.ask(&request).await? {
            Response::Signed { token, .. } => return Ok(token),
            Response::Error(code) if code == UNKNOWN_REALM => {}
            Response::Error(code) => return Err(refused(&code, typ)),
            _ => return Err(Unavailable),
        }
        if self.ask(&Request::Open { realm: r, alg }).await? != Response::Opened {
            return Err(refused("open", typ));
        }
        match self.ask(&request).await? {
            Response::Signed { token, .. } => Ok(token),
            Response::Error(code) => Err(refused(&code, typ)),
            _ => Err(Unavailable),
        }
    }

    async fn jwks(&self, realm: RealmId) -> Result<String, Unavailable> {
        Keys::jwks(self, realm).await
    }
}

/// The back-channel courier's outbox and cursor as `access_outbox_reader` (OP-131 m.3), its
/// records as `access_app` under the realm's scope (OP-12).
#[derive(Clone)]
pub struct PgLogoutQueue {
    /// Logged in as a member of `access_outbox_reader`.
    pub reader: Pool,
    /// Logged in as a member of `access_app`.
    pub app: Pool,
}

impl LogoutQueue for PgLogoutQueue {
    async fn cursor(&self) -> Result<Cursor, Unavailable> {
        identity::cursor(&self.reader, CONSUMER).await.map_err(down)
    }

    async fn poll(&self, after: Cursor, limit: u32) -> Result<Vec<OutboxEvent>, Unavailable> {
        identity::poll(&self.reader, after, limit)
            .await
            .map_err(down)
    }

    async fn ack(&self, at: Cursor) -> Result<(), Unavailable> {
        identity::ack(&self.reader, CONSUMER, at)
            .await
            .map_err(down)
    }

    async fn undelivered(
        &self,
        tenant: TenantId,
        realm: RealmId,
        record: &LogoutUndelivered,
    ) -> Result<(), Unavailable> {
        let mut tx = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(down)?;
        tx.backchannel_undelivered(record).await.map_err(down)?;
        tx.commit().await.map_err(down)
    }
}

/// The hosted login at fixed paths under the realm issuer: `/login`, `/sign-out` and
/// `/signed-out` (OP-146 I9).
#[derive(Clone, Copy, Debug, Default)]
pub struct HostedPages;

/// The `reason` parameter of the login page.
#[must_use]
pub const fn reason_name(reason: LoginReason) -> &'static str {
    match reason {
        LoginReason::SignIn => "sign_in",
        LoginReason::Reauthenticate => "reauthenticate",
        LoginReason::Create => "create",
        LoginReason::StepUp(_) => "step_up",
        LoginReason::Share => "share",
        LoginReason::Approve => "approve",
    }
}

impl LoginPages for HostedPages {
    fn login(&self, issuer: &Issuer, return_to: &str, reason: LoginReason) -> String {
        let mut out = issuer.endpoint("/login");
        out.push_str("?return_to=");
        form_encode(return_to, &mut out);
        out.push_str("&reason=");
        out.push_str(reason_name(reason));
        if let LoginReason::StepUp(aal) = reason {
            out.push_str("&acr=");
            form_encode(crate::domain::tokens::acr(aal), &mut out);
        }
        out
    }

    fn confirm_sign_out(&self, issuer: &Issuer) -> String {
        issuer.endpoint("/sign-out")
    }

    fn signed_out(&self, issuer: &Issuer) -> String {
        issuer.endpoint("/signed-out")
    }
}

/// The operating system's random source through aws-lc-rs.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        for chunk in out.chunks_mut(32) {
            let bytes = access_crypto::random::bytes::<32>().map_err(down)?;
            for (d, s) in chunk.iter_mut().zip(bytes) {
                *d = s;
            }
        }
        Ok(())
    }
}
