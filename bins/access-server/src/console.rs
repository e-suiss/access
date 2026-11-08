//! The console BFF's ports in this process (TN-128–TN-131, OP-151 m.2 M3, m.12): system time
//! and randomness, per-session DPoP keys held in memory, the session store in PostgreSQL, the
//! sign-in through the realm's own authorization server, the device Instance through the same
//! self-signed Exercises as the Frontend API, read tokens from the realm, and the management API
//! and ADP in process. ADP sees the console as its own PEP, [`CONSOLE_PEP`], and only for the
//! reads the BFF forwards. No `GeoResolver` source answers yet: sessions bind to the prefix, or
//! to the full address when the realm's session policy says `ip`.

pub(crate) mod devices;
pub(crate) mod sessions;
pub(crate) mod sign_in;

use std::collections::HashMap;
use std::sync::Mutex;

use access_crypto::jose::output;
use access_http::adp::adapters::{Pep, Requester};
use access_http::console::ports::{
    Clock, ConsoleEnv, DpopKeys, Entropy, Forward, Forwarded, Unavailable, Upstream,
};
use access_kernel::json::b64url_encode;
use access_kernel::verify::key_scope::thumbprint;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use suiss_crypto::signer::{Signer, SoftSigner};
use tower::ServiceExt;

use crate::admin::{OsEntropy, WallClock};

/// Most sessions holding a DPoP key in this process; past it new sessions are refused.
const MAX_KEYS: usize = 100_000;

/// Largest upstream answer passed back.
const MAX_ANSWER: usize = 4 * 1024 * 1024;

/// One P-256 DPoP key per console session, in memory only (RFC 9449): a restart loses them,
/// and the next read issues a new token to a new key.
#[derive(Default)]
pub(crate) struct MemoryDpop(Mutex<HashMap<[u8; 16], SoftSigner>>);

impl MemoryDpop {
    fn with<T>(
        &self,
        session: [u8; 16],
        f: impl FnOnce(&SoftSigner) -> Result<T, Unavailable>,
    ) -> Result<T, Unavailable> {
        let mut keys = self.0.lock().map_err(|_| Unavailable)?;
        if !keys.contains_key(&session) {
            if keys.len() >= MAX_KEYS {
                return Err(Unavailable);
            }
            let (signer, _) = SoftSigner::generate_p256().map_err(|_| Unavailable)?;
            keys.insert(session, signer);
        }
        f(keys.get(&session).ok_or(Unavailable)?)
    }
}

impl DpopKeys for MemoryDpop {
    fn jkt(&self, session: [u8; 16]) -> Result<[u8; 32], Unavailable> {
        self.with(session, |s| Ok(thumbprint(&s.public_key())))
    }

    fn proof(
        &self,
        session: [u8; 16],
        method: &str,
        htu: &str,
        ath: &[u8; 32],
        now_ms: u64,
    ) -> Result<String, Unavailable> {
        let jti = access_crypto::random::bytes::<16>().map_err(|_| Unavailable)?;
        self.with(session, |s| {
            let jwk =
                access_crypto::jose::confirmation_jwk(&s.public_key()).map_err(|_| Unavailable)?;
            let header = format!(
                r#"{{"alg":"ES256","jwk":{},"typ":"dpop+jwt"}}"#,
                output::to_string(&jwk)
            );
            let claims = serde_json::json!({
                "ath": b64url_encode(ath),
                "htm": method,
                "htu": htu,
                "iat": now_ms / 1000,
                "jti": b64url_encode(&jti),
            });
            let mut out = b64url_encode(header.as_bytes());
            out.push('.');
            out.push_str(&b64url_encode(claims.to_string().as_bytes()));
            let signature = s.sign(out.as_bytes()).map_err(|_| Unavailable)?;
            out.push('.');
            out.push_str(&b64url_encode(&signature));
            Ok(out)
        })
    }

    fn forget(&self, session: [u8; 16]) {
        if let Ok(mut keys) = self.0.lock() {
            keys.remove(&session);
        }
    }
}

/// The console's PEP name at ADP (OP-151 m.12 (e)): the management process's own, so its
/// forwarded reads are told apart from every product's.
pub(crate) const CONSOLE_PEP: &str = "access-console";

/// The management API and ADP in this process.
pub(crate) struct InProcess {
    admin: Router,
    adp: Router,
}

async fn call(
    router: &Router,
    request: Forward,
    pep: Option<(Pep, Requester)>,
) -> Result<Forwarded, Unavailable> {
    let mut builder = Request::builder()
        .method(request.method)
        .uri(request.path_and_query);
    for (name, value) in request.headers {
        builder = builder.header(name, value);
    }
    let mut request = builder
        .body(Body::from(request.body))
        .map_err(|_| Unavailable)?;
    if let Some((p, r)) = pep {
        request.extensions_mut().insert(p);
        request.extensions_mut().insert(r);
    }
    let response = router
        .clone()
        .oneshot(request)
        .await
        .map_err(|_| Unavailable)?;
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, MAX_ANSWER).await.map_err(|_| Unavailable)?;
    Ok(Forwarded {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    })
}

impl Upstream for InProcess {
    async fn admin(&self, request: Forward) -> Result<Forwarded, Unavailable> {
        call(&self.admin, request, None).await
    }

    // TN-128, OP-151 m.12 (e)
    async fn adp(&self, request: Forward, requester: String) -> Result<Forwarded, Unavailable> {
        let caller = (Pep(String::from(CONSOLE_PEP)), Requester(requester));
        call(&self.adp, request, Some(caller)).await
    }
}

/// The console BFF's ports in this process.
pub(crate) struct ServerConsole<P> {
    dpop: MemoryDpop,
    upstream: InProcess,
    sessions: sessions::PgConsoleSessions,
    network: sessions::RealmBinding,
    sign_in: sign_in::RealmSignIn,
    devices: devices::ConsoleDevices<P>,
    grants: crate::admin::tokens::ConsoleGrants<P>,
    accepted: P,
    origin: String,
}

/// What the console reaches in this process.
pub(crate) struct Parts<P> {
    /// The management API's routes.
    pub(crate) admin: Router,
    /// ADP's routes.
    pub(crate) adp: Router,
    /// The session store and profile source.
    pub(crate) sessions: sessions::PgConsoleSessions,
    /// The realms' session binding policies.
    pub(crate) network: sessions::RealmBinding,
    /// The realm sign-in.
    pub(crate) sign_in: sign_in::RealmSignIn,
    /// The device Instances.
    pub(crate) devices: devices::ConsoleDevices<P>,
    /// Read tokens.
    pub(crate) grants: crate::admin::tokens::ConsoleGrants<P>,
    /// The domains' accepted tenant actions (OP-151 m.20 (a)).
    pub(crate) accepted: P,
}

impl<P> ServerConsole<P> {
    /// The ports; `origin` is the configured `suiss.management_api` (TN-131: never from a
    /// request).
    pub(crate) fn new(parts: Parts<P>, origin: String) -> Self {
        Self {
            dpop: MemoryDpop::default(),
            upstream: InProcess {
                admin: parts.admin,
                adp: parts.adp,
            },
            sessions: parts.sessions,
            network: parts.network,
            sign_in: parts.sign_in,
            devices: parts.devices,
            grants: parts.grants,
            accepted: parts.accepted,
            origin,
        }
    }
}

impl<P> ConsoleEnv for ServerConsole<P>
where
    P: crate::admin::realm::LiveKeys
        + access_identity_ui::ports::DeviceInstances
        + access_http::console::ports::AcceptedActions
        + Send
        + Sync
        + 'static,
{
    type Sessions = sessions::PgConsoleSessions;
    type SignIn = sign_in::RealmSignIn;
    type Network = sessions::RealmBinding;
    type Profiles = sessions::PgConsoleSessions;
    type Devices = devices::ConsoleDevices<P>;
    type Grants = crate::admin::tokens::ConsoleGrants<P>;
    type Dpop = MemoryDpop;
    type Upstream = InProcess;

    fn clock(&self) -> &dyn Clock {
        &WallClock
    }

    fn entropy(&self) -> &dyn Entropy {
        &OsEntropy
    }

    fn sessions(&self) -> &sessions::PgConsoleSessions {
        &self.sessions
    }

    fn sign_in(&self) -> &sign_in::RealmSignIn {
        &self.sign_in
    }

    fn network(&self) -> &sessions::RealmBinding {
        &self.network
    }

    fn profiles(&self) -> &sessions::PgConsoleSessions {
        &self.sessions
    }

    fn devices(&self) -> &devices::ConsoleDevices<P> {
        &self.devices
    }

    fn grants(&self) -> &crate::admin::tokens::ConsoleGrants<P> {
        &self.grants
    }

    fn dpop(&self) -> &MemoryDpop {
        &self.dpop
    }

    fn upstream(&self) -> &InProcess {
        &self.upstream
    }

    fn origin(&self) -> &str {
        &self.origin
    }

    fn accepted(&self) -> &dyn access_http::console::ports::AcceptedActions {
        &self.accepted
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]

    use access_kernel::json::b64url_decode;

    use super::*;

    // RFC 9449, OP-151 m.3 (c)
    #[test]
    fn dpop_proofs_are_per_session_and_bound_to_the_request() {
        let keys = MemoryDpop::default();
        let (a, b) = ([1; 16], [2; 16]);
        assert_eq!(keys.jkt(a).unwrap(), keys.jkt(a).unwrap());
        assert_ne!(keys.jkt(a).unwrap(), keys.jkt(b).unwrap());
        let proof = keys
            .proof(
                a,
                "GET",
                "https://m.example/admin/v1/x",
                &[9; 32],
                1_000_000,
            )
            .unwrap();
        let mut parts = proof.split('.');
        let header: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts.next().unwrap()).unwrap()).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts.next().unwrap()).unwrap()).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert_eq!(claims["htm"], "GET");
        assert_eq!(claims["htu"], "https://m.example/admin/v1/x");
        assert_eq!(claims["iat"], 1_000);
        assert_eq!(claims["ath"], b64url_encode(&[9; 32]));
        assert_eq!(b64url_decode(parts.next().unwrap()).unwrap().len(), 64);
        let first = keys.jkt(a).unwrap();
        keys.forget(a);
        assert_ne!(keys.jkt(a).unwrap(), first);
    }
}
