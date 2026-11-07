//! What the authorization server needs from outside (OP-63): one transaction over the realm's
//! clients, requests, codes, grants and sessions; the identity signer; the clients' published
//! keys; the hosted login; and fresh randomness. Any failure of these is [`Unavailable`]: the
//! caller answers `503 + Retry-After`, never `invalid_grant` (G50, EP-2).

use std::future::Future;

use access_crypto::jose::JwsAlg;
use access_crypto::opaque_id::IdKey;
use access_store::backchannel::LogoutUndelivered;
use access_store::identity::{Cursor, OutboxEvent, RealmId, TenantId};
use access_store::idp::{ClientRow, PlatformClient};
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
    /// The digest of the client's previous secret while its rotation overlap lasts (CR-38).
    fn previous_secret(
        &mut self,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<[u8; 32]>, Unavailable>> + Send;
    /// The client with internal id `uuid`, active or retired.
    fn client_by_uuid(
        &mut self,
        uuid: [u8; 16],
    ) -> impl Future<Output = Result<Option<ClientRow>, Unavailable>> + Send;
    /// The realm's JOSE algorithm (OP-146 m.8 (e)).
    fn jose_alg(&mut self) -> impl Future<Output = Result<JwsAlg, Unavailable>> + Send;
    /// The issuer stored on the realm's row (§17.9.6); `None` for a realm without one.
    fn issuer(&mut self) -> impl Future<Output = Result<Option<Issuer>, Unavailable>> + Send;
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
    /// The realm's governing authority domain (TN-4, OP-149 m.22 (g)).
    fn governing(&mut self) -> impl Future<Output = Result<Option<[u8; 32]>, Unavailable>> + Send;
    /// The service Party the platform client `client_id` holds in this realm, once it paired
    /// (OP-149 m.4, m.16 (a)).
    fn platform_party(
        &mut self,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<[u8; 16]>, Unavailable>> + Send;
    /// The pairwise value the client `sector` reads of the platform Party `party`, stored on
    /// first use (OP-149 m.31 (a), MD-10); `None` when `party` is not a platform Party here.
    fn platform_party_pairwise(
        &mut self,
        party: &[u8; 16],
        sector: [u8; 16],
        candidate: &str,
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send;
    /// The pairwise value the client `sector` reads of this realm's client `client`, stored on
    /// first use (OP-149 m.34 (b), MD-10); `None` when `client` is not a client here.
    fn client_pairwise(
        &mut self,
        client: [u8; 16],
        sector: [u8; 16],
        candidate: &str,
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send;
    /// Writes an identity audit row in this transaction (OP-10, OP-39): identifiers only.
    fn audit(
        &mut self,
        event_type: &str,
        actor: &str,
        target: &str,
        correlation: &str,
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
    /// The active platform product client `client_id`, in whichever tenant it is registered
    /// (OP-149 m.26 (a), m.34 (b)); `None` for any other client id.
    fn platform_product(
        &self,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<PlatformClient>, Unavailable>> + Send;
}

/// Type prefix of a tenant's opaque external id (OP-137, OP-149 m.15 (i)): every product-facing
/// surface names a tenant `tnt_…`, tokens and events as the tenant snapshot does.
pub const TENANT_PREFIX: &str = "tnt";

/// Names tenants outside by their opaque `tnt_` id (OP-137, OP-149 m.15 (i), m.19 (a)).
pub trait TenantIds: Send + Sync {
    /// The external id of `tenant`; `None` when the cell's id key cannot be used.
    fn external(&self, tenant: &[u8; 16]) -> Option<String>;

    /// The tenant an external id names; `None` for text that is not a `tnt_` id.
    fn internal(&self, text: &str) -> Option<[u8; 16]>;
}

impl TenantIds for IdKey {
    fn external(&self, tenant: &[u8; 16]) -> Option<String> {
        self.encode(TENANT_PREFIX, *tenant).ok()
    }

    fn internal(&self, text: &str) -> Option<[u8; 16]> {
        self.decode(TENANT_PREFIX, text).ok()
    }
}

impl<T: TenantIds + ?Sized> TenantIds for std::sync::Arc<T> {
    fn external(&self, tenant: &[u8; 16]) -> Option<String> {
        (**self).external(tenant)
    }

    fn internal(&self, text: &str) -> Option<[u8; 16]> {
        (**self).internal(text)
    }
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

/// Why a logout notice did not reach a client (OIDC Back-Channel Logout 1.0 §2.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostFailure {
    /// Worth trying again: no answer, `408`, `429` or a `5xx` other than `501`.
    Transient {
        /// The client's `Retry-After`, ms.
        retry_after_ms: Option<u64>,
    },
    /// The client answered with a status that will not change.
    Rejected {
        /// The status.
        status: u16,
    },
    /// Not sent: the endpoint is not one Access posts to (scheme, address, SSRF guard).
    Refused,
}

/// A client's back-channel logout endpoint (§10.4.6).
pub trait LogoutDelivery: Send + Sync {
    /// Posts `logout_token` to `uri` as `application/x-www-form-urlencoded`.
    fn post(
        &self,
        uri: &str,
        logout_token: &str,
    ) -> impl Future<Output = Result<(), PostFailure>> + Send;
}

/// The outbox as the back-channel courier reads it (OP-131): its own cursor, and the record of
/// what it passed without delivering (OP-73).
pub trait LogoutQueue: Send + Sync {
    /// The courier's cursor.
    fn cursor(&self) -> impl Future<Output = Result<Cursor, Unavailable>> + Send;
    /// Outbox events after `after`, in `(xid, id)` order.
    fn poll(
        &self,
        after: Cursor,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<OutboxEvent>, Unavailable>> + Send;
    /// Moves the cursor forward to `at`.
    fn ack(&self, at: Cursor) -> impl Future<Output = Result<(), Unavailable>> + Send;
    /// Records a grant whose notice was not delivered, once.
    fn undelivered(
        &self,
        tenant: TenantId,
        realm: RealmId,
        record: &LogoutUndelivered,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
}
