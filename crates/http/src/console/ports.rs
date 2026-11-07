//! What the console BFF needs from the outside world (OP-63). Every port fails closed:
//! [`Unavailable`] answers `503` and nothing is passed through (MD-8, Ek B "BFF session store
//! failure is fail-closed").

use std::future::Future;
use std::net::IpAddr;

use access_identity_session::domain::console::{Binding, BindingPolicy, ConsoleFacts, DbscKey};
use access_kernel::digest::Digest;
use access_kernel::verify::cose::PublicKey;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use suiss_crypto::secret::Secret;

pub use crate::api::ports::{Clock, Entropy, Unavailable};

/// The device Instance a console session registered (OP-149 m.6, OP-151 m.3 (e)): its key
/// lives in the browser, non-extractable; the BFF knows only the public half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInstance {
    /// RFC 7638 thumbprint of the key.
    pub kid: [u8; 32],
    /// The public key.
    pub key: PublicKey,
}

/// Who signed in, as the realm's hosted login answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedIn {
    /// The realm's slug.
    pub realm: String,
    /// The realm's governing domain.
    pub domain: Digest,
    /// The account's pseudonymous external id.
    pub account: String,
    /// The display name, tenant-controlled text (TN-131).
    pub display_name: String,
    /// The realm subject's internal id.
    pub subject: [u8; 16],
    /// The realm login session the sign-in authenticated with.
    pub login_session: [u8; 16],
    /// When the user authenticated, Unix milliseconds.
    pub auth_time_ms: u64,
}

/// A console session as stored. The cookie value itself is never stored, only its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleSession {
    /// Internal id.
    pub id: [u8; 16],
    /// Who signed in.
    pub who: SignedIn,
    /// The facts the policy checks.
    pub facts: ConsoleFacts,
    /// The session's device Instance, once registered.
    pub instance: Option<SessionInstance>,
    /// The DBSC key slot (TN-33); empty until DBSC lands.
    pub dbsc: Option<DbscKey>,
}

/// A session to open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewConsoleSession {
    /// Digest of the cookie value.
    pub cookie_digest: [u8; 32],
    /// Who signed in.
    pub who: SignedIn,
    /// The network binding.
    pub binding: Binding,
    /// Now, Unix milliseconds.
    pub now_ms: u64,
}

/// One row of the signed-in user's session list (S10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    /// Internal id.
    pub id: [u8; 16],
    /// `console` or `login`.
    pub kind: &'static str,
    /// Created, Unix milliseconds.
    pub created_ms: u64,
    /// Last use, Unix milliseconds.
    pub last_seen_ms: u64,
}

/// Console sessions (TN-128, TN-129): the identity plane's login session model with the
/// console policy.
pub trait ConsoleSessions: Send + Sync {
    /// Opens a session.
    fn open(
        &self,
        new: NewConsoleSession,
    ) -> impl Future<Output = Result<[u8; 16], Unavailable>> + Send;

    /// The session whose cookie has `cookie_digest`, ended or not.
    fn find(
        &self,
        cookie_digest: [u8; 32],
    ) -> impl Future<Output = Result<Option<ConsoleSession>, Unavailable>> + Send;

    /// Records a use.
    fn touch(
        &self,
        id: [u8; 16],
        now_ms: u64,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// Ends the session.
    fn end(
        &self,
        id: [u8; 16],
        now_ms: u64,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// Binds the session to the device Instance it registered (one per session, INV-13).
    fn attach(
        &self,
        id: [u8; 16],
        instance: SessionInstance,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// The live sessions of `session`'s account, console and login.
    fn list(
        &self,
        session: &ConsoleSession,
    ) -> impl Future<Output = Result<Vec<SessionSummary>, Unavailable>> + Send;

    /// Ends `target` when it is one of `session`'s account's own sessions; `false` otherwise.
    fn revoke(
        &self,
        session: &ConsoleSession,
        target: [u8; 16],
        now_ms: u64,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
}

/// The hand-off with a realm's hosted login: where the browser goes to sign in, and who came
/// back.
pub trait SignIn: Send + Sync {
    /// The hosted login URL for `realm` that returns to `callback` with `state`; `None` when
    /// the realm is unknown.
    fn start(
        &self,
        realm: &str,
        state: &str,
        callback: &str,
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send;

    /// Who signed in, from the callback's query; `None` when it does not complete a sign-in
    /// this BFF started for `realm` with `state`.
    fn finish(
        &self,
        realm: &str,
        state: &str,
        query: &str,
    ) -> impl Future<Output = Result<Option<SignedIn>, Unavailable>> + Send;
}

/// The network facts a session binding reads (TN-129, OP-151 m.1 (b)).
pub trait Network: Send + Sync {
    /// The ASN of `ip` from the configured `GeoResolver` source; `None` without a source or an answer.
    fn asn(&self, ip: IpAddr) -> Option<u32>;

    /// The realm session policy's binding settings; the default when the realm sets none.
    fn policy(
        &self,
        realm: &str,
    ) -> impl Future<Output = Result<BindingPolicy, Unavailable>> + Send;
}

/// The signed-in user's own profile (Ek B 3089): read only; edits go through the Frontend API.
pub trait Profiles: Send + Sync {
    /// The profile as JSON; `None` when the account is gone.
    fn profile(
        &self,
        session: &ConsoleSession,
    ) -> impl Future<Output = Result<Option<serde_json::Value>, Unavailable>> + Send;
}

/// What a device registration answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceAnswer {
    /// HTTP status.
    pub status: u16,
    /// JSON body.
    pub body: serde_json::Value,
    /// The Instance opened, when it was.
    pub instance: Option<SessionInstance>,
}

/// The session's device Instance (OP-149 m.6, OP-151 m.3 (e)): the existing challenge and
/// `instance_create` flow, run for the console session.
pub trait Devices: Send + Sync {
    /// A challenge for the device key the browser generated; `body` is `{"key": <COSE_Key,
    /// base64url>}`. The answer carries what the browser signs: the challenge, the governing
    /// domain, basis and PEP, the validity, and the canonical `instance_create` (and, for a
    /// user without a Party, `party_register`) intent envelopes, which the browser's Kernel
    /// decodes and shows before it signs (X11).
    fn challenge(
        &self,
        session: &ConsoleSession,
        body: Bytes,
    ) -> impl Future<Output = Result<DeviceAnswer, Unavailable>> + Send;

    /// Registers the device key; `body` is the Frontend API's `InstanceRegistration`.
    fn register(
        &self,
        session: &ConsoleSession,
        body: Bytes,
    ) -> impl Future<Output = Result<DeviceAnswer, Unavailable>> + Send;
}

/// A management read token issued to a session (TN-130): at most 60 minutes, bound to the
/// BFF's DPoP key of that session.
pub struct IssuedRead {
    /// The access token.
    pub token: Secret<Vec<u8>>,
    /// Its end, Unix milliseconds.
    pub expires_ms: u64,
}

/// Issues management read tokens to a session's device Instance, holder-bound to the session's
/// DPoP key `jkt` (TN-130, OP-151 m.3 (c)). Scope `realm.read` only: it authorises CT0 reads,
/// never a write.
pub trait ReadGrants: Send + Sync {
    /// A token for `session`, or `None` when the session may not have one.
    fn issue(
        &self,
        session: &ConsoleSession,
        instance: &SessionInstance,
        jkt: [u8; 32],
    ) -> impl Future<Output = Result<Option<IssuedRead>, Unavailable>> + Send;
}

/// The DPoP keys the BFF holds, one per session, server side (RFC 9449). The key proves the
/// BFF presents the token it was issued; it is not an authority holder's key.
pub trait DpopKeys: Send + Sync {
    /// The RFC 7638 thumbprint of `session`'s key, created on first use.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn jkt(&self, session: [u8; 16]) -> Result<[u8; 32], Unavailable>;

    /// A proof by `session`'s key for `method` and `htu`, bound to the token by `ath`.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn proof(
        &self,
        session: [u8; 16],
        method: &str,
        htu: &str,
        ath: &[u8; 32],
        now_ms: u64,
    ) -> Result<String, Unavailable>;

    /// Forgets `session`'s key.
    fn forget(&self, session: [u8; 16]);
}

/// A request the BFF passes on.
#[derive(Clone, Debug)]
pub struct Forward {
    /// Method.
    pub method: Method,
    /// Path and query, absolute.
    pub path_and_query: String,
    /// The headers passed on.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Body.
    pub body: Bytes,
}

/// An answer the BFF hands back.
#[derive(Clone, Debug)]
pub struct Forwarded {
    /// Status.
    pub status: u16,
    /// Headers.
    pub headers: HeaderMap,
    /// Body.
    pub body: Bytes,
}

/// The surfaces behind the BFF: the management API and ADP.
pub trait Upstream: Send + Sync {
    /// A request to `/admin/v1/…`.
    fn admin(
        &self,
        request: Forward,
    ) -> impl Future<Output = Result<Forwarded, Unavailable>> + Send;

    /// A request to `/access/v1/…`.
    fn adp(&self, request: Forward) -> impl Future<Output = Result<Forwarded, Unavailable>> + Send;
}

/// Every port of the console BFF.
pub trait ConsoleEnv: Send + Sync + 'static {
    /// Sessions.
    type Sessions: ConsoleSessions + 'static;
    /// Hosted login hand-off.
    type SignIn: SignIn + 'static;
    /// Network facts.
    type Network: Network + 'static;
    /// Profiles.
    type Profiles: Profiles + 'static;
    /// Device Instances.
    type Devices: Devices + 'static;
    /// Read tokens.
    type Grants: ReadGrants + 'static;
    /// DPoP keys.
    type Dpop: DpopKeys + 'static;
    /// Upstream surfaces.
    type Upstream: Upstream + 'static;

    /// Trusted time.
    fn clock(&self) -> &dyn Clock;
    /// Randomness.
    fn entropy(&self) -> &dyn Entropy;
    /// Sessions.
    fn sessions(&self) -> &Self::Sessions;
    /// Hosted login hand-off.
    fn sign_in(&self) -> &Self::SignIn;
    /// Network facts.
    fn network(&self) -> &Self::Network;
    /// Profiles.
    fn profiles(&self) -> &Self::Profiles;
    /// Device Instances.
    fn devices(&self) -> &Self::Devices;
    /// Read tokens.
    fn grants(&self) -> &Self::Grants;
    /// DPoP keys.
    fn dpop(&self) -> &Self::Dpop;
    /// Upstream surfaces.
    fn upstream(&self) -> &Self::Upstream;
    /// The management origin, `https://<host>[:port]`, from configuration only (TN-131).
    fn origin(&self) -> &str;
}
