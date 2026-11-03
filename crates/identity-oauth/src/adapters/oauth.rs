//! Adapters of the authorization server ports: the realm's PostgreSQL rows, the identity
//! signer, the hosted login's paths and the operating system's randomness.

use access_crypto::jose::JwsAlg;
use access_identity_signer::protocol::{Realm, Request, Response};
use access_identity_signer::service::UNKNOWN_REALM;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{self, ClientRow};
use access_store::oauth::{
    CodeRow, GrantRow, NewCode, NewGrant, NewRequest, RefreshRow, RequestRow,
};
use access_store::sessions::SessionRow;

use crate::adapters::SignerKeys;
use crate::domain::issuer::{Issuer, form_encode};
use crate::domain::tokens::LoginReason;
use crate::ports::oauth::{LoginPages, OAuthDb, OAuthTx, Random, TokenSigner};
use crate::ports::{Keys, Unavailable};

/// The realm rows over the application pool.
#[derive(Clone)]
pub struct PgOAuth {
    pool: Pool,
}

impl PgOAuth {
    /// Over the application pool.
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self { pool }
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
}

impl OAuthTx for PgOAuthTx {
    async fn client(&mut self, client_id: &str) -> Result<Option<ClientRow>, Unavailable> {
        idp::client(&mut self.0, client_id).await.map_err(down)
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
        self.0.outbox(kind, payload).await.map_err(down)
    }

    async fn commit(self) -> Result<(), Unavailable> {
        self.0.commit().await.map_err(down)
    }
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
            _ => return Err(Unavailable),
        }
        if self.ask(&Request::Open { realm: r, alg }).await? != Response::Opened {
            return Err(Unavailable);
        }
        match self.ask(&request).await? {
            Response::Signed { token, .. } => Ok(token),
            _ => Err(Unavailable),
        }
    }

    async fn jwks(&self, realm: RealmId) -> Result<String, Unavailable> {
        Keys::jwks(self, realm).await
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
