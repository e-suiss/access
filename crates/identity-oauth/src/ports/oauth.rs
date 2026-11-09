//! What the authorization server needs from outside (OP-63): one transaction over the realm's
//! clients, requests, codes, grants and sessions; the identity signer; the clients' published
//! keys; the hosted login; and fresh randomness. Any failure of these is [`Unavailable`]: the
//! caller answers `503 + Retry-After`, never `invalid_grant` (G50, EP-2).

use std::future::Future;

use access_crypto::jose::JwsAlg;
use access_crypto::opaque_id::IdKey;
use access_store::backchannel::LogoutUndelivered;
use access_store::identity::{Cursor, OutboxEvent, RealmId, TenantId};
use access_store::clients::{CimdRow, CimdSnapshot, ConsentRecordRow};
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
    /// The end of the subject's grace period after a recovery still running at `now_ms`
    /// (TN-56).
    fn recovery_grace_until(
        &mut self,
        subject: [u8; 16],
        now_ms: i64,
    ) -> impl Future<Output = Result<Option<i64>, Unavailable>> + Send;
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
    /// The claims `subject` shares with the third-party client `client` (OP-153 m.3 (z)),
    /// sorted; `None` without a live consent.
    fn consent(
        &mut self,
        subject: [u8; 16],
        client: [u8; 16],
    ) -> impl Future<Output = Result<Option<Vec<String>>, Unavailable>> + Send;
    /// Writes an identity audit row in this transaction (OP-10, OP-39): identifiers only.
    fn audit(
        &mut self,
        event_type: &str,
        actor: &str,
        target: &str,
        correlation: &str,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
    /// The realm's CIMD acceptance policy (`idp.client.cimd_policy`): whether CIMD clients are
    /// accepted, and from which domains.
    fn cimd_policy(
        &mut self,
    ) -> impl Future<Output = Result<(bool, Vec<String>), Unavailable>> + Send;
    /// The live CIMD client of `client_id`, locked.
    fn cimd_client(
        &mut self,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<CimdRow>, Unavailable>> + Send;
    /// Records a CIMD client seen for the first time.
    fn insert_cimd_client(
        &mut self,
        client_id: &str,
        s: &CimdSnapshot<'_>,
    ) -> impl Future<Output = Result<[u8; 16], Unavailable>> + Send;
    /// Replaces a live CIMD client's snapshot.
    fn refresh_cimd_client(
        &mut self,
        uuid: [u8; 16],
        s: &CimdSnapshot<'_>,
        visual_changed: bool,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// Retires a live CIMD client: its consent records end and its identity grants are revoked.
    fn retire_cimd_client(
        &mut self,
        uuid: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// Whether `resource` is a registered protected resource of the realm (AG-8).
    fn protected_resource(
        &mut self,
        resource: &str,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// The live consent record of `subject` for `client` at `resource` (P58).
    fn consent_record(
        &mut self,
        subject: [u8; 16],
        client: [u8; 16],
        resource: &str,
    ) -> impl Future<Output = Result<Option<ConsentRecordRow>, Unavailable>> + Send;
    /// Ends one consent record.
    fn end_consent_record(
        &mut self,
        consent: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
    /// The Party a subject's device Instances belong to (OP-149 m.16 (a)).
    fn subject_party(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Option<[u8; 16]>, Unavailable>> + Send;
    /// The live CIMD client with internal id `uuid`: its URL.
    fn cimd_client_by_uuid(
        &mut self,
        uuid: [u8; 16],
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send;
    /// Keeps a consent record (P58).
    fn put_consent_record(
        &mut self,
        c: &access_store::clients::NewConsentRecord<'_>,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
    /// Ends every live consent record of `client`.
    fn end_client_consents(
        &mut self,
        client: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> impl Future<Output = Result<u64, Unavailable>> + Send;
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

/// A pending answer of [`ManagementHolders`], boxed so the port stays object safe.
pub type Held<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, Unavailable>> + Send + 'a>>;

/// The authority plane's Instances, as a management read token exchange reads them (TN-130,
/// OP-151 m.3 (c)).
pub trait ManagementHolders: Send + Sync {
    /// The live key `kid` (RFC 7638 thumbprint) of an Instance of `domain` at the head; `None`
    /// when no live Instance of the domain holds it.
    fn instance_key(
        &self,
        domain: [u8; 32],
        kid: [u8; 32],
    ) -> Held<'_, Option<access_kernel::verify::cose::PublicKey>>;

    /// Whether `realm` is the platform's own realm, whose Instances may read the platform
    /// surface (OP-151 m.3 (a)).
    fn platform(&self, realm: &crate::ports::RealmEntry) -> Held<'_, bool>;
}

/// What an account holds to release as identity claims (§10.4.6, OP-153 m.3 (l)): its proven
/// address and profile fields, read under the realm's PII vault.
pub trait ClaimSource: Send + Sync {
    /// What `subject` of `realm` holds.
    fn held(
        &self,
        tenant: access_store::identity::TenantId,
        realm: access_store::identity::RealmId,
        subject: [u8; 16],
    ) -> Held<'_, crate::domain::claims_request::Held>;
}

/// Nothing to release: only `sub` and the protocol claims reach a client.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClaims;

impl ClaimSource for NoClaims {
    fn held(
        &self,
        _: access_store::identity::TenantId,
        _: access_store::identity::RealmId,
        _: [u8; 16],
    ) -> Held<'_, crate::domain::claims_request::Held> {
        Box::pin(async { Ok(crate::domain::claims_request::Held::default()) })
    }
}

/// No management holder: no key is live and no realm is the platform's; every exchange is
/// refused (MD-8).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoManagement;

impl ManagementHolders for NoManagement {
    fn instance_key(
        &self,
        _: [u8; 32],
        _: [u8; 32],
    ) -> Held<'_, Option<access_kernel::verify::cose::PublicKey>> {
        Box::pin(async { Ok(None) })
    }

    fn platform(&self, _: &crate::ports::RealmEntry) -> Held<'_, bool> {
        Box::pin(async { Ok(false) })
    }
}

/// What a Client ID Metadata Document fetch answered (§11.3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// Status; only `200` is a document.
    pub status: u16,
    /// `Cache-Control: max-age`, seconds.
    pub max_age_s: Option<u64>,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// The body, read up to the limit asked for.
    pub body: Vec<u8>,
}

/// Why a client's URL was not fetched or answered nothing usable; every case cancels the
/// authorization request (AG-4) and nothing is cached (§11.3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FetchRefused {
    /// Not an `https` URL Access requests.
    #[error("not an https URL Access requests")]
    Url,
    /// The host resolves to a special-purpose address (RFC 6890, §11.3.6).
    #[error("address refused")]
    Blocked,
    /// The per-URL or per-realm fetch rate is spent (OP-154 m.3 (i)).
    #[error("rate limited")]
    Limited,
    /// No answer in time.
    #[error("no answer")]
    Unreachable,
    /// Larger than the read limit or not HTTP/1.1.
    #[error("malformed or oversized answer")]
    Malformed,
}

/// A pending answer of [`ClientDocuments`].
pub type Fetch<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, FetchRefused>> + Send + 'a>>;

/// The URLs a CIMD client names, reached through the guarded outbound client only
/// (OP-154 m.1 (d), §11.3.6): no redirect followed, every address public, bounded reads.
pub trait ClientDocuments: Send + Sync {
    /// Checks that `url` is one Access requests and that every address its host resolves to is
    /// public, without connecting.
    fn vet<'a>(&'a self, url: &'a str) -> Fetch<'a, ()>;

    /// `GET url` for `realm` with `accept`, the body read up to `max_body` bytes.
    fn fetch<'a>(
        &'a self,
        realm: RealmId,
        url: &'a str,
        accept: &'a str,
        max_body: usize,
    ) -> Fetch<'a, Fetched>;
}

/// No outbound access: every CIMD client is refused (MD-8).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDocuments;

impl ClientDocuments for NoDocuments {
    fn vet<'a>(&'a self, _: &'a str) -> Fetch<'a, ()> {
        Box::pin(async { Err(FetchRefused::Unreachable) })
    }

    fn fetch<'a>(&'a self, _: RealmId, _: &'a str, _: &'a str, _: usize) -> Fetch<'a, Fetched> {
        Box::pin(async { Err(FetchRefused::Unreachable) })
    }
}

/// A Grant a `grant.issue` Exercise created, as its domain recorded it (EI-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuedGrant {
    /// The Grant.
    pub grant: [u8; 16],
    /// The Party that holds it.
    pub holder: [u8; 16],
    /// The Party whose Instance signed the Exercise.
    pub signer: [u8; 16],
}

/// The authority plane's Grants as consent reads them (§11.6 rule 1, P58, EI-18).
pub trait GrantStanding: Send + Sync {
    /// Whether Grant `grant` of `domain` is live now: issued, not revoked, not lapsed.
    fn live(&self, domain: [u8; 32], grant: [u8; 16]) -> Held<'_, bool>;

    /// The live Grant the ALLOWed `grant.issue` Exercise `exercise` of `domain` created; `None`
    /// for any other Exercise, a refused one, or a Grant that no longer stands.
    fn issued(&self, domain: [u8; 32], exercise: [u8; 32]) -> Held<'_, Option<IssuedGrant>>;
}

/// No authority plane: no Grant stands, so every consent is asked for again (MD-8).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoStanding;

impl GrantStanding for NoStanding {
    fn live(&self, _: [u8; 32], _: [u8; 16]) -> Held<'_, bool> {
        Box::pin(async { Ok(false) })
    }

    fn issued(&self, _: [u8; 32], _: [u8; 32]) -> Held<'_, Option<IssuedGrant>> {
        Box::pin(async { Ok(None) })
    }
}
