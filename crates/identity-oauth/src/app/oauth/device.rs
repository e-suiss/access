//! The device authorization grant (RFC 8628, OP-154 m.3 (p), TN-35): off unless the realm
//! decided `idp.realm.device_code`. A registered client asks at `/device_authorization`; the
//! person enters the user code on the verification page, a trusted surface of its own that
//! shows the client, the scope and the IP prefix and country the request came from (the country
//! only when the operator supplied an IP-range list, never a placeholder), and
//! approves or declines while signed in. The device polls `/token`; its tokens are DPoP-bound.

use std::net::IpAddr;

use access_identity_session::domain::dbsc::split_cookie;
use access_identity_session::domain::session::cookie_digest;
use access_kernel::json::b64url_encode;
use access_store::device::NewDeviceCode;
use access_store::sessions::SessionRow;
use serde_json::json;

use super::dcr::ip_prefix;
use super::{Env, OAuth, Realm, Reply, TokenHttp, bound_live, decode32, session_live};
use crate::domain::client::TrustLevel;
use crate::domain::device::{
    self, INTERVAL_S, LIFETIME_MS, PERSON_MISSES, PERSON_WAIT_MS, PREFIX_MISSES_PER_HOUR,
    VERIFICATION_PATH,
};
use crate::domain::metadata::Endpoint;
use crate::ports::Unavailable;
use crate::ports::oauth::{OAuthDb, OAuthTx};

const HOUR_MS: u64 = 3_600_000;
const MAX_SCOPE: usize = 2048;

/// What the verification page shows for a user code (OP-154 m.3 (p)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceView {
    /// The client's name.
    pub client: String,
    /// The scopes asked for.
    pub scopes: Vec<String>,
    /// The IP prefix the request came from.
    pub ip_prefix: String,
    /// Its country, when known.
    pub country: Option<String>,
}

/// Why a user code is not shown or decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceRefused {
    /// No live session: the person signs in first.
    SignIn,
    /// Too many wrong codes: wait.
    Wait,
    /// No waiting device asks with that code; the same for every wrong code.
    NoCode,
    /// The realm does not offer the grant.
    Off,
}

const CSRF_CONTEXT: &str = "access/device-csrf/v1";

/// The verification page's CSRF token for the code `entered`, bound to the session cookie
/// `cookie` (§11.4.5 #28): only a page of this origin that read the session's own preview knows
/// it. `None` when either is malformed.
#[must_use]
pub fn device_csrf(cookie: &str, entered: &str) -> Option<String> {
    let value = decode32(split_cookie(cookie).0)?;
    let code = device::normalise(entered)?;
    let mut bound = Vec::with_capacity(64);
    bound.extend_from_slice(&value);
    bound.extend_from_slice(&device::user_hash(&code));
    Some(b64url_encode(&access_crypto::oauth::opaque_digest(
        CSRF_CONTEXT,
        &bound,
    )))
}

impl<E: Env> OAuth<E> {
    pub(super) async fn signed_in(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        cookie: Option<&str>,
        now: u64,
    ) -> Result<Option<SessionRow>, Unavailable> {
        match cookie.and_then(|c| decode32(split_cookie(c).0).map(|v| (c, v))) {
            Some((c, value)) => Ok(tx
                .session_by_cookie(&cookie_digest(&value))
                .await?
                .filter(|s| session_live(s, now) && bound_live(s, c, now))),
            None => Ok(None),
        }
    }

    /// `POST /device_authorization` (RFC 8628 §3.1) by a registered client from `peer`.
    pub async fn device_authorization(
        &self,
        realm: &Realm,
        params: &crate::domain::request::Params,
        http: TokenHttp<'_>,
        peer: Option<IpAddr>,
    ) -> Reply {
        match self.device_inner(realm, params, http, peer).await {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    async fn device_inner(
        &self,
        realm: &Realm,
        params: &crate::domain::request::Params,
        http: TokenHttp<'_>,
        peer: Option<IpAddr>,
    ) -> Result<Reply, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        // TN-35, OP-154 m.3 (p)
        if !tx.device_code_enabled().await? {
            return Ok(Reply::NotFound);
        }
        let mut req = http.client_request(params);
        req.endpoint = Endpoint::DeviceAuthorization.path();
        let client = match self.authenticate(&mut tx, realm, &req, now).await? {
            Ok(c) if c.trust == TrustLevel::Registered => c,
            _ => {
                return Ok(Reply::oauth_error(
                    401,
                    "invalid_client",
                    "client authentication failed",
                ));
            }
        };
        let scope = params.get("scope").unwrap_or_default();
        if scope.len() > MAX_SCOPE || scope.chars().any(char::is_control) {
            return Ok(Reply::oauth_error(
                400,
                "invalid_scope",
                "the scope is malformed",
            ));
        }
        let prefix = peer.map_or_else(|| String::from("unknown"), ip_prefix);
        // OP-155 m.3 (l), §10.4.1
        let country = peer
            .and_then(|ip| self.env.geo().country(ip))
            .and_then(|c| String::from_utf8(c.to_vec()).ok());
        let code = self.random::<32>()?;
        let mut user = None;
        for _ in 0..4 {
            let Some(u) = device::user_code(&self.random::<32>()?) else {
                continue;
            };
            let normal = device::normalise(&u).ok_or(Unavailable)?;
            let kept = tx
                .insert_device_code(&NewDeviceCode {
                    device_hash: device::device_hash(&code),
                    user_hash: device::user_hash(&normal),
                    client: client.uuid,
                    scope,
                    ip_prefix: &prefix,
                    country: country.as_deref(),
                    now_ms: now,
                    expires_ms: now.saturating_add(LIFETIME_MS),
                    interval_s: INTERVAL_S,
                })
                .await?;
            if kept {
                user = Some(u);
                break;
            }
        }
        let Some(user) = user else {
            return Err(Unavailable);
        };
        tx.commit().await?;
        let page = realm.issuer.endpoint(VERIFICATION_PATH);
        Ok(Reply::Json {
            status: 200,
            body: json!({
                "device_code": b64url_encode(&code),
                "user_code": user,
                "verification_uri": page,
                "verification_uri_complete": format!("{page}?user_code={user}"),
                "expires_in": LIFETIME_MS / 1000,
                "interval": INTERVAL_S,
            })
            .to_string(),
            dpop_nonce: None,
            challenge: None,
        })
    }

    async fn waiting_device(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        cookie: Option<&str>,
        entered: &str,
        peer: Option<IpAddr>,
        now: u64,
    ) -> Result<Result<(SessionRow, access_store::device::DeviceCodeRow), DeviceRefused>, Unavailable>
    {
        if !tx.device_code_enabled().await? {
            return Ok(Err(DeviceRefused::Off));
        }
        let Some(session) = self.signed_in(tx, cookie, now).await? else {
            return Ok(Err(DeviceRefused::SignIn));
        };
        let prefix = peer.map_or_else(|| String::from("unknown"), ip_prefix);
        // OP-154 m.3 (p), CR-39
        let (by_prefix, by_person) = tx
            .device_misses(
                &prefix,
                now.saturating_sub(HOUR_MS),
                session.subject,
                now.saturating_sub(PERSON_WAIT_MS),
            )
            .await?;
        if by_prefix >= PREFIX_MISSES_PER_HOUR || by_person >= PERSON_MISSES {
            return Ok(Err(DeviceRefused::Wait));
        }
        let found = match device::normalise(entered) {
            Some(n) => tx
                .device_code_by_user(&device::user_hash(&n))
                .await?
                .filter(|d| d.expires_ms > now),
            None => None,
        };
        let Some(found) = found else {
            tx.miss_device_code(&prefix, session.subject, now).await?;
            return Ok(Err(DeviceRefused::NoCode));
        };
        Ok(Ok((session, found)))
    }

    /// What a user code asks for, for the signed-in person (OP-154 m.3 (p)); a wrong code counts
    /// toward the entry limits.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn device_preview(
        &self,
        realm: &Realm,
        cookie: Option<&str>,
        entered: &str,
        peer: Option<IpAddr>,
    ) -> Result<Result<DeviceView, DeviceRefused>, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let (_, d) = match self
            .waiting_device(&mut tx, cookie, entered, peer, now)
            .await?
        {
            Ok(w) => w,
            Err(r) => {
                tx.commit().await?;
                return Ok(Err(r));
            }
        };
        let client = tx.client_by_uuid(d.client).await?;
        tx.commit().await?;
        Ok(Ok(DeviceView {
            client: client.map(|c| c.display_name).unwrap_or_default(),
            scopes: d
                .scope
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            ip_prefix: d.ip_prefix,
            country: d.country,
        }))
    }

    /// The signed-in person approves or declines a user code, once (RFC 8628 §3.3).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn device_decide(
        &self,
        realm: &Realm,
        cookie: Option<&str>,
        entered: &str,
        approve: bool,
        peer: Option<IpAddr>,
    ) -> Result<Result<(), DeviceRefused>, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let (session, d) = match self
            .waiting_device(&mut tx, cookie, entered, peer, now)
            .await?
        {
            Ok(w) => w,
            Err(r) => {
                tx.commit().await?;
                return Ok(Err(r));
            }
        };
        let approved = approve.then_some((session.subject, session.id));
        if !tx.decide_device_code(d.device_id, approved, now).await? {
            return Ok(Err(DeviceRefused::NoCode));
        }
        tx.commit().await?;
        Ok(Ok(()))
    }
}
