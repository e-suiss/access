//! What the authorization server needs from outside (OP-63): one transaction over the realm's
//! clients, requests, codes, grants and sessions; the identity signer; the clients' published
//! keys; the hosted login; and fresh randomness. Any failure of these is [`Unavailable`]: the
//! caller answers `503 + Retry-After`, never `invalid_grant` (G50, EP-2).

use std::future::Future;

use access_crypto::jose::JwsAlg;
use access_store::identity::{RealmId, TenantId};
use access_store::idp::ClientRow;
use access_store::oauth::{
    CodeRow, GrantRow, NewCode, NewGrant, NewRequest, RefreshRow, RequestRow,
};
use access_store::sessions::SessionRow;

use crate::domain::issuer::Issuer;
use crate::domain::tokens::LoginReason;
use crate::ports::Unavailable;

/// One transaction in one realm.
pub trait OAuthTx: Send {
    /// The client with `client_id`, active or retired.
    fn client(
        &mut self,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<ClientRow>, Unavailable>> + Send;
    /// The client with internal id `uuid`, active or retired.
    fn client_by_uuid(
        &mut self,
        uuid: [u8; 16],
    ) -> impl Future<Output = Result<Option<ClientRow>, Unavailable>> + Send;
    /// The realm's JOSE algorithm (OP-146 m.8 (e)).
    fn jose_alg(&mut self) -> impl Future<Output = Result<JwsAlg, Unavailable>> + Send;
    /// Stores a pending request.
    fn insert_request(
        &mut self,
        r: &NewRequest<'_>,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
    /// A pending request, locked.
    fn request(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<RequestRow>, Unavailable>> + Send;
    /// Marks a request used; false when it was.
    fn use_request(
        &mut self,
        day: i32,
        hash: &[u8; 32],
        at_ms: i64,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// Stores a code.
    fn insert_code(
        &mut self,
        c: &NewCode<'_>,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
    /// A code, locked.
    fn code(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<CodeRow>, Unavailable>> + Send;
    /// Redeems a code by compare-and-set.
    fn redeem_code(
        &mut self,
        day: i32,
        hash: &[u8; 32],
        at_ms: i64,
        grant: [u8; 16],
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// Records a client assertion's replay key; `true` the first time.
    fn assertion_first_use(
        &mut self,
        day: i32,
        key: &[u8; 32],
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// The login session with `cookie_hash`, locked.
    fn session_by_cookie(
        &mut self,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<SessionRow>, Unavailable>> + Send;
    /// The login session with `id`, locked.
    fn session(
        &mut self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<SessionRow>, Unavailable>> + Send;
    /// Ends a login session; false when it already was.
    fn end_session(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
        reason: &str,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// Raises the subject's `session_epoch`: every session and grant of the subject ends
    /// (TN-50).
    fn end_sessions(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
    /// Stores a grant.
    fn insert_grant(
        &mut self,
        g: &NewGrant<'_>,
    ) -> impl Future<Output = Result<[u8; 16], Unavailable>> + Send;
    /// A grant, locked.
    fn grant(
        &mut self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<GrantRow>, Unavailable>> + Send;
    /// The grant of `sid`.
    fn grant_by_sid(
        &mut self,
        sid: &[u8; 16],
    ) -> impl Future<Output = Result<Option<GrantRow>, Unavailable>> + Send;
    /// The live grants of a session.
    fn session_grants(
        &mut self,
        session: [u8; 16],
    ) -> impl Future<Output = Result<Vec<GrantRow>, Unavailable>> + Send;
    /// Revokes a grant.
    fn revoke_grant(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
        reason: &str,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// Stores a refresh token digest.
    fn insert_refresh(
        &mut self,
        hash: &[u8; 32],
        grant: [u8; 16],
        at_ms: i64,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
    /// A refresh token, locked.
    fn refresh(
        &mut self,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<RefreshRow>, Unavailable>> + Send;
    /// Rotates a refresh token by compare-and-set.
    fn rotate_refresh(
        &mut self,
        hash: &[u8; 32],
        at_ms: i64,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// The subject's pairwise value for `sector`, stored on first use.
    fn pairwise(
        &mut self,
        subject: [u8; 16],
        sector: [u8; 16],
        candidate: &str,
    ) -> impl Future<Output = Result<String, Unavailable>> + Send;
    /// Queues an outbox event in this transaction.
    fn outbox(
        &mut self,
        kind: &str,
        payload: &[u8],
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
    /// Commits.
    fn commit(self) -> impl Future<Output = Result<(), Unavailable>> + Send;
}

/// Opens transactions in a realm.
pub trait OAuthDb: Send + Sync {
    /// The transaction type.
    type Tx: OAuthTx;
    /// Opens one.
    fn begin(
        &self,
        tenant: TenantId,
        realm: RealmId,
    ) -> impl Future<Output = Result<Self::Tx, Unavailable>> + Send;
}

/// The identity signer, for the realm's identity assertions (CMP-22b, TN-14).
pub trait TokenSigner: Send + Sync {
    /// Signs a JSON `payload` as a compact JWS of `typ` at `at_ms` with the realm's key,
    /// opening the realm's key set with `alg` on first use.
    fn sign(
        &self,
        realm: RealmId,
        alg: JwsAlg,
        typ: &str,
        payload: &[u8],
        at_ms: u64,
    ) -> impl Future<Output = Result<String, Unavailable>> + Send;
    /// The realm's JWKS, to read back its own tokens.
    fn jwks(&self, realm: RealmId) -> impl Future<Output = Result<String, Unavailable>> + Send;
}

/// The JWKS a `private_key_jwt` client publishes (RFC 7523, §11.3.6).
pub trait ClientKeys: Send + Sync {
    /// The document at `jwks_uri`.
    fn fetch(&self, jwks_uri: &str) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send;
}

/// The hosted login (I9) as `/authorize` and `/end-session` reach it.
pub trait LoginPages: Send + Sync {
    /// Where to send a browser that must sign in for `reason`; the login returns it to
    /// `return_to` (see [`crate::domain::login`]).
    fn login(&self, issuer: &Issuer, return_to: &str, reason: LoginReason) -> String;
    /// Where to send a browser whose sign-out could not be tied to its session by an
    /// `id_token_hint`: the hosted page asks the user before signing out.
    fn confirm_sign_out(&self, issuer: &Issuer) -> String;
    /// Where to send a browser after a sign-out without a client redirect.
    fn signed_out(&self, issuer: &Issuer) -> String;
}

/// Fresh randomness.
pub trait Random: Send + Sync {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable>;
}
