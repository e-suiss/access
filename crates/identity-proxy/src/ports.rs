//! What forward-auth needs from the rest of the server (OP-63): the registry, the proxy
//! sessions, the realm's authorization server, the authority plane's decision, time and
//! randomness. Every port answers [`Unavailable`] rather than guess; the check then refuses.

use std::future::Future;

use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{ActionRef, Id};

use crate::domain::registration::Registration;

/// A dependency did not answer; nothing was decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unavailable")]
pub struct Unavailable;

/// A live registration as the check reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered<R> {
    /// The realm it is registered in.
    pub realm: R,
    /// The registration.
    pub registration: Registration,
    /// Whether `idp.proxy.plain_headers` is in force.
    pub plain_headers: bool,
}

/// A sign-in the browser has not come back from.
#[derive(Clone, PartialEq, Eq)]
pub struct Pending {
    /// The PKCE verifier (RFC 7636), never sent anywhere but the redemption.
    pub verifier: String,
    /// Where the browser goes once signed in.
    pub return_to: String,
}

impl core::fmt::Debug for Pending {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pending")
            .field("return_to", &self.return_to)
            .finish_non_exhaustive()
    }
}

/// A redeemed authorization code: the OAuth grant the proxy session rides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redeemed {
    /// The grant's session id.
    pub sid: [u8; 16],
    /// When its login session ends, ms.
    pub expires_ms: u64,
}

/// Who a live proxy session is, now; its `Debug` shows no identifier of the person (OP-64).
#[derive(Clone, PartialEq, Eq)]
pub struct Holder {
    /// The account.
    pub subject: [u8; 16],
    /// The Party the account is bound to, once bound.
    pub party: Option<Id>,
    /// The realm's governing domain.
    pub domain: Digest,
    /// When the login session ends, ms.
    pub expires_ms: u64,
    /// The `sub` the proxy's client reads (MD-10).
    pub user: String,
    /// The account's verified e-mail, when the client may read it.
    pub email: Option<String>,
}

impl core::fmt::Debug for Holder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Holder")
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

/// One basis the Party may act on, with when it ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Basis {
    /// The basis an eligibility check names.
    pub basis: ExerciseBasis,
    /// The end of the Grant's validity, ms: the decision's horizon.
    pub until_ms: u64,
}

/// What the check is asked by and for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked<'a> {
    /// The domain.
    pub domain: Digest,
    /// The Party.
    pub party: Id,
    /// The intent.
    pub intent: &'a IntentEnvelope,
    /// The basis.
    pub basis: &'a ExerciseBasis,
    /// The proxy, the PEP.
    pub pep: &'a str,
    /// The browser session it asks for: the rate bucket (OP-141 m.23 (a)).
    pub requester: String,
}

/// The ports of forward-auth.
pub trait Ports: Send + Sync {
    /// The realm a registration lives in.
    type Realm: Clone + Send + Sync;

    /// The live registration of transport identity `pep` for application host `host`.
    fn registered(
        &self,
        pep: &str,
        host: &str,
    ) -> impl Future<Output = Result<Option<Registered<Self::Realm>>, Unavailable>> + Send;

    /// Keeps a sign-in under the digest of its `state` until `expires_ms`.
    fn begin(
        &self,
        realm: &Self::Realm,
        proxy: &str,
        state: &[u8; 32],
        pending: &Pending,
        expires_ms: u64,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// Takes the sign-in of `state` once, before it expires.
    fn take(
        &self,
        realm: &Self::Realm,
        proxy: &str,
        state: &[u8; 32],
    ) -> impl Future<Output = Result<Option<Pending>, Unavailable>> + Send;

    /// Opens a proxy session under the digest of its cookie.
    fn open(
        &self,
        realm: &Self::Realm,
        proxy: &str,
        cookie: &[u8; 32],
        redeemed: &Redeemed,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// The grant behind a live proxy session.
    fn session(
        &self,
        realm: &Self::Realm,
        proxy: &str,
        cookie: &[u8; 32],
    ) -> impl Future<Output = Result<Option<[u8; 16]>, Unavailable>> + Send;

    /// The realm's authorization endpoint URL for a code + PKCE sign-in of `client_id`, with
    /// `sign_in` its `(state, nonce, code_challenge)`.
    fn authorize_url(
        &self,
        realm: &Self::Realm,
        client_id: &str,
        redirect_uri: &str,
        sign_in: (&str, &str, &str),
    ) -> impl Future<Output = Result<String, Unavailable>> + Send;

    /// Redeems `code`, `(code, verifier)`, for `client_id` once with its PKCE verifier; `None` when it is not a
    /// live code of this client and redirect URI.
    fn redeem(
        &self,
        realm: &Self::Realm,
        client_id: &str,
        redirect_uri: &str,
        code: (&str, &str),
    ) -> impl Future<Output = Result<Option<Redeemed>, Unavailable>> + Send;

    /// Who the grant `sid` of `client_id` is now; `None` once it or its session ended.
    fn holder(
        &self,
        realm: &Self::Realm,
        client_id: &str,
        sid: &[u8; 16],
    ) -> impl Future<Output = Result<Option<Holder>, Unavailable>> + Send;

    /// Signs the application token of `holder` for `token`, `(audience, decision)` (OP-156
    /// m.3 (l)).
    fn app_token(
        &self,
        realm: &Self::Realm,
        client_id: &str,
        holder: &Holder,
        token: (&str, &str),
    ) -> impl Future<Output = Result<String, Unavailable>> + Send;

    /// The live bases `party` holds in `domain` whose actions cover `action`.
    fn bases(
        &self,
        domain: Digest,
        party: Id,
        action: &ActionRef,
    ) -> impl Future<Output = Result<Vec<Basis>, Unavailable>> + Send;

    /// The domain's eligibility check (OP-149 m.10): whether the Party may act now.
    fn eligible(&self, asked: Asked<'_>) -> impl Future<Output = Result<bool, Unavailable>> + Send;

    /// The domain's head position.
    fn head(&self, domain: Digest) -> impl Future<Output = Result<u64, Unavailable>> + Send;

    /// Trusted time, ms.
    ///
    /// # Errors
    /// [`Unavailable`] without a trusted time.
    fn now_ms(&self) -> Result<u64, Unavailable>;

    /// Fills `out` from the RNG.
    ///
    /// # Errors
    /// [`Unavailable`] without randomness.
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable>;
}
