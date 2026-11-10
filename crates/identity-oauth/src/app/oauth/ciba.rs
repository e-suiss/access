//! CIBA as an invitation (OpenID CIBA Core 1.0 PROFILE, IDP-14, §10.5.3, §9.9.5, §9.14.5 k.2,
//! OP-155 m.3 (l)). A registered confidential client that received `REQUIRE_ACTION` names it at
//! `/bc-authorize` by its `exercise_ref` and the RAR `kind=intent` detail; the realm invites the
//! person through Relay `CibaInvite` to their Approval Surface, where the answer is their AAS and
//! the contribution it committed. The client polls `/token` (or is pinged first) and learns the
//! contribution, which it presents on its own commit of the same nonce: the CIBA answer is never
//! authority (PI-3). Push is never offered.

use access_crypto::AwsLcBackend;
use access_identity_session::domain::dbsc::split_cookie;
use access_kernel::aas::{Act, ApprovalAct};
use access_kernel::codec::Canonical as _;
use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use access_kernel::verify::jws::{MAX_PAYLOAD, Origin, verify_compact};
use access_store::ciba::{CibaRequestRow, NewCibaRequest};
use access_store::oauth::NewGrant;
use access_store::sessions::SessionRow;
use serde_json::{Value, json};

use super::{Env, OAuth, Realm, Reply, TokenHttp, decode32, session_live, signed, unsigned};
use crate::domain::ciba::{self, BackchannelRequest, CibaError, Hint, INTERVAL_S};
use crate::domain::client::{Client, ClientAuth, TrustLevel};
use crate::domain::dpop::{ClientType, Jkt};
use crate::domain::fapi::Binding;
use crate::domain::jwt::{parse_jwks, realm_key_set};
use crate::domain::metadata::Endpoint;
use crate::domain::request::Params;
use crate::domain::tokens::{GrantDetails, ID_TYP};
use crate::ports::Unavailable;
use crate::ports::oauth::{CibaInvite, ClientKeys, OAuthDb, OAuthTx, TokenSigner};

/// What the Approval Surface shows for a backchannel request (OP-155 m.3 (l)), and what it
/// pushes to the hosted approval: never more authority than the decision point rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CibaView {
    /// The client's name.
    pub client: String,
    /// The binding message, shown, not binding.
    pub binding_message: Option<String>,
    /// The scopes asked for.
    pub scopes: Vec<String>,
    /// When the request expires, Unix ms.
    pub expires_at_ms: u64,
    /// The typed authority request the surface pushes with the approver's contribution
    /// (OP-149 m.9): who asks, and the `REQUIRE_ACTION` it answers.
    pub request: Value,
    /// A return address the client registered, for the hosted approval's call contract.
    pub redirect_uri: String,
    /// The holding the person's device signs the contribution on; `None` when they hold none,
    /// so nothing can be approved here.
    pub contribution_basis: Option<access_kernel::meta::HoldingRef>,
    /// The governing domain the contribution is committed in.
    pub domain: [u8; 32],
    /// The `contribute` intent the person's device signs (§9.14.1 A step 4): an `approve` of
    /// this request's intent, valid while the request waits.
    pub contribution_intent: access_kernel::intent::IntentEnvelope,
}

/// Why a backchannel request is not shown or answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CibaRefused {
    /// No live session: the person signs in first.
    SignIn,
    /// No waiting request for this person; the same for every unknown request.
    NoRequest,
    /// The request expired.
    Expired,
    /// The approval named is not this person's finished AAS over this request's intent
    /// (IDI-9, §9.14.5 k.2), or the nonce was answered already (OP-154 m.13 (f)).
    NotApproved,
    /// The realm does not offer CIBA.
    Off,
}

const CSRF_CONTEXT: &str = "access/ciba-csrf/v1";

/// The Approval Surface's CIBA CSRF token for the request `request`, bound to the session cookie
/// `cookie` (§11.4.5 #28). `None` when either is malformed.
#[must_use]
pub fn ciba_csrf(cookie: &str, request: &str) -> Option<String> {
    let value = decode32(split_cookie(cookie).0)?;
    let id = request_id(request)?;
    let mut bound = Vec::with_capacity(48);
    bound.extend_from_slice(&value);
    bound.extend_from_slice(&id);
    Some(b64url_encode(&access_crypto::oauth::opaque_digest(
        CSRF_CONTEXT,
        &bound,
    )))
}

fn request_id(text: &str) -> Option<[u8; 16]> {
    b64url_decode(text)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
}

fn refused(e: CibaError, description: &str) -> Reply {
    Reply::oauth_error(e.status(), e.error(), description)
}

fn digest_text(d: &[u8; 32]) -> String {
    format!("sha-256:{}", b64url_encode(d))
}

/// The `exercise_ref` member (§9.9.5).
fn exercise_ref_json(row: &CibaRequestRow) -> Value {
    json!({ "domain": b64url_encode(&row.domain), "nonce": b64url_encode(&row.nonce) })
}

/// What the person's approval named, checked from the AAS the hosted approval committed and its
/// recorded contribution, never from the client or the token (§9.14.5 k.2, IDI-9, P54): a finished
/// approval by a session of the person the request names, of a contribution to this intent in
/// this domain, pushed for this `exercise_ref`.
fn approved_by(
    row: &CibaRequestRow,
    approval: &access_store::approvals::ApprovalRow,
    approver: Option<[u8; 16]>,
) -> Option<[u8; 32]> {
    let (Some(_), Some(contribution), Some(aas)) = (
        approval.finished_ms,
        approval.exercise,
        approval.aas.as_ref(),
    ) else {
        return None;
    };
    if approver.is_none() || approver != row.subject {
        return None;
    }
    let act = ApprovalAct::from_bytes(aas).ok()?;
    if !matches!(act.act, Act::Contribution(_))
        || act.target.0 != row.intent
        || act.domain.0 != row.domain
    {
        return None;
    }
    let pushed: Value = serde_json::from_slice(&approval.request).ok()?;
    let ra = pushed.get("require_action")?;
    let same = ra.get("domain").and_then(Value::as_str) == Some(&b64url_encode(&row.domain))
        && ra.get("nonce").and_then(Value::as_str) == Some(&b64url_encode(&row.nonce))
        && ra.get("intent").and_then(Value::as_str) == Some(&b64url_encode(&row.intent));
    same.then_some(contribution)
}

impl<E: Env> OAuth<E> {
    /// `POST /bc-authorize` (CIBA Core §7, OP-155 m.3 (l)).
    pub async fn backchannel_authentication(
        &self,
        realm: &Realm,
        params: &Params,
        http: TokenHttp<'_>,
    ) -> Reply {
        match self.backchannel_inner(realm, params, http).await {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    /// The person a hint names (OP-155 m.3 (l)): the pairwise `sub` of a `login_hint_token` the
    /// client signed or of an ID token this realm issued to it; a free `login_hint` through the
    /// realm's lookup, where nobody is no answer (enumeration-safe, §10.2.1).
    async fn hinted(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        hint: &Hint,
        now: u64,
    ) -> Result<Result<Option<[u8; 16]>, CibaError>, Unavailable> {
        let sub = match hint {
            Hint::LoginHint(h) => {
                return Ok(Ok(self
                    .env
                    .ciba()
                    .login_hint(realm.tenant, realm.realm, h.clone())
                    .await?));
            }
            Hint::LoginHintToken(t) => {
                let doc = match &client.auth {
                    ClientAuth::PrivateKeyJwt { jwks_uri } => {
                        self.env.client_keys().fetch(jwks_uri).await?
                    }
                    ClientAuth::PrivateKeyJwtKey { jwks } => jwks.clone().into_bytes(),
                    _ => match &client.profile.tls {
                        Some(crate::domain::fapi::TlsAuth::SelfSigned { jwks }) => {
                            jwks.clone().into_bytes()
                        }
                        _ => return Ok(Err(CibaError::HintToken)),
                    },
                };
                let Ok(keys) = parse_jwks(&doc) else {
                    return Ok(Err(CibaError::HintToken));
                };
                let rs256 = client.rs256 && !client.profile.fapi2;
                match ciba::login_hint_subject(
                    t,
                    &keys,
                    &client.id,
                    realm.issuer.as_str(),
                    rs256,
                    now,
                ) {
                    Ok(s) => s,
                    Err(e) => return Ok(Err(e)),
                }
            }
            Hint::IdTokenHint(t) => {
                let jwks = self.env.signer().jwks(realm.realm).await?;
                let keys = realm_key_set(jwks.as_bytes()).map_err(|_| Unavailable)?;
                let Ok(v) = verify_compact(&AwsLcBackend, t, &keys, ID_TYP, Origin::Native) else {
                    return Ok(Err(CibaError::HintToken));
                };
                let Ok(c) = json::parse(&v.payload, MAX_PAYLOAD) else {
                    return Ok(Err(CibaError::HintToken));
                };
                let text = |n: &str| c.get(n).and_then(Json::as_str).map(String::from);
                if text("iss").as_deref() != Some(realm.issuer.as_str())
                    || text("aud").as_deref() != Some(client.id.as_str())
                {
                    return Ok(Err(CibaError::HintToken));
                }
                match text("sub") {
                    Some(s) => s,
                    None => return Ok(Err(CibaError::HintToken)),
                }
            }
        };
        Ok(match tx.pairwise_subject(client.sector(), &sub).await? {
            Some(s) => Ok(Some(s)),
            None => Err(CibaError::UnknownUser),
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one backchannel request, its checks in order"
    )]
    async fn backchannel_inner(
        &self,
        realm: &Realm,
        outer: &Params,
        http: TokenHttp<'_>,
    ) -> Result<Reply, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let settings = tx.ciba_settings().await?;
        // OP-155 m.3 (l)
        if !settings.enabled {
            return Ok(Reply::NotFound);
        }
        let mut req = http.client_request(outer);
        req.endpoint = Endpoint::BackchannelAuthentication.path();
        let client = match self.authenticate(&mut tx, realm, &req, now).await? {
            Ok(c)
                if c.trust == TrustLevel::Registered
                    && c.client_type() == ClientType::Confidential =>
            {
                c
            }
            Ok(_) => {
                return Ok(refused(
                    CibaError::Client,
                    "CIBA needs a registered confidential client",
                ));
            }
            Err(_) => {
                return Ok(Reply::oauth_error(
                    401,
                    "invalid_client",
                    "client authentication failed",
                ));
            }
        };
        tx.commit().await?;
        // OP-155 m.3 (k), (l)
        let signed;
        let params = match outer.get("request") {
            Some(object) => match self
                .request_object(realm, &client, outer, object, now)
                .await?
            {
                Ok(p) => {
                    signed = p;
                    &signed
                }
                Err(e) => {
                    return Ok(Reply::oauth_error(
                        400,
                        "invalid_request_object",
                        e.description(),
                    ));
                }
            },
            None if client.profile.fapi2 => {
                return Ok(refused(
                    CibaError::Request,
                    "a FAPI client sends a signed authentication request",
                ));
            }
            None => outer,
        };
        let r: BackchannelRequest = match ciba::read(params, settings.login_hint) {
            Ok(r) => r,
            Err(e) => return Ok(refused(e, "the backchannel request is not valid")),
        };
        // IDP-14
        let ping = settings.ping.iter().any(|(c, _)| *c == client.uuid);
        if ping != r.notification_token.is_some() {
            return Ok(refused(
                CibaError::Request,
                "the delivery mode is not the client's",
            ));
        }
        let mut tx = self.begin(realm).await?;
        if tx.governing().await? != Some(r.exercise.domain) {
            return Ok(refused(CibaError::Request, "not this realm's domain"));
        }
        // §9.9.5, P54
        let Some(opening) = self.env.ciba().opening(r.exercise.domain, r.intent).await? else {
            return Ok(refused(
                CibaError::Request,
                "no approval waits on this intent",
            ));
        };
        let subject = match self.hinted(&mut tx, realm, &client, &r.hint, now).await? {
            Ok(s) => s,
            Err(e) => return Ok(refused(e, "the hint names no one")),
        };
        let until = opening.valid_until.unwrap_or(u64::MAX);
        let Some(life) = ciba::lifetime_ms(until, r.requested_ms, now) else {
            return Ok(refused(
                CibaError::Request,
                "the intent expires too soon to ask",
            ));
        };
        let handle = self.random::<32>()?;
        let auth_req_id = b64url_encode(&handle);
        let expires = now.saturating_add(life);
        let id = tx
            .insert_ciba(&NewCibaRequest {
                handle_hash: ciba::handle_hash(&handle),
                client: client.uuid,
                subject,
                domain: r.exercise.domain,
                nonce: &r.exercise.nonce,
                intent: r.intent,
                details: &r.details,
                scope: &r.scope,
                binding_message: r.binding_message.as_deref(),
                mode: if ping { "ping" } else { "poll" },
                notification_token: r.notification_token.as_deref(),
                ping_handle: ping.then_some(auth_req_id.as_str()),
                now_ms: now,
                expires_ms: expires,
                interval_s: INTERVAL_S,
            })
            .await?;
        tx.commit().await?;
        // OP-155 m.3 (l), E42
        if let Some(subject) = subject {
            let link = format!(
                "{}?reason=ciba&request={}",
                realm.issuer.endpoint(ciba::PAGE_PATH),
                b64url_encode(&id)
            );
            self.env
                .ciba()
                .invite(CibaInvite {
                    tenant: realm.tenant,
                    realm: realm.realm,
                    subject,
                    link,
                    client: client.name.clone(),
                    binding_message: r.binding_message.clone(),
                    expires_at_ms: expires,
                })
                .await?;
        }
        Ok(Reply::json(
            200,
            &json!({
                "auth_req_id": auth_req_id,
                "expires_in": life / 1000,
                "interval": INTERVAL_S,
            }),
        ))
    }

    /// The person's waiting request `request`: theirs, unanswered and not expired.
    async fn waiting_ciba(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        cookie: Option<&str>,
        request: &str,
        now: u64,
    ) -> Result<Result<(SessionRow, CibaRequestRow), CibaRefused>, Unavailable> {
        if !tx.ciba_settings().await?.enabled {
            return Ok(Err(CibaRefused::Off));
        }
        let Some(session) = self.signed_in(tx, cookie, now).await? else {
            return Ok(Err(CibaRefused::SignIn));
        };
        let Some(id) = request_id(request) else {
            return Ok(Err(CibaRefused::NoRequest));
        };
        let Some(row) = tx
            .ciba(id)
            .await?
            .filter(|r| r.subject == Some(session.subject) && r.decision.is_none())
        else {
            return Ok(Err(CibaRefused::NoRequest));
        };
        if row.expires_ms <= now {
            return Ok(Err(CibaRefused::Expired));
        }
        Ok(Ok((session, row)))
    }

    /// What the backchannel request `request` asks of the signed-in person (OP-155 m.3 (l)).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn ciba_preview(
        &self,
        realm: &Realm,
        cookie: Option<&str>,
        request: &str,
    ) -> Result<Result<CibaView, CibaRefused>, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let (session, row) = match self.waiting_ciba(&mut tx, cookie, request, now).await? {
            Ok(w) => w,
            Err(r) => return Ok(Err(r)),
        };
        let client = tx.client_by_uuid(row.client).await?;
        let party = tx.subject_party(session.subject).await?;
        tx.commit().await?;
        let contribution_basis = match party {
            Some(p) => self.env.standing().contribute_basis(row.domain, p).await?,
            None => None,
        };
        let Some(client) = client.filter(|c| c.active) else {
            return Ok(Err(CibaRefused::NoRequest));
        };
        let Some(redirect_uri) = client.redirect_uris.first().cloned() else {
            return Ok(Err(CibaRefused::NoRequest));
        };
        let validity = access_kernel::model::Window {
            from: now.saturating_sub(60_000),
            until: row.expires_ms,
        };
        let contribution_intent = access_kernel::contribution::contribute_intent(
            access_kernel::digest::Digest(row.intent),
            access_kernel::contribution::APPROVE,
            validity,
        )
        .ok_or(Unavailable)?;
        let detail: Value = serde_json::from_str::<Vec<Value>>(&row.details)
            .ok()
            .and_then(|d| d.into_iter().next())
            .unwrap_or(Value::Null);
        // OP-149 m.9, §9.14.5 k.2
        let pushed = json!({
            "requester": { "client_id": client.client_id, "name": client.display_name },
            "action": detail.get("type").cloned().unwrap_or(Value::Null),
            "resource": Value::Null,
            "params": {},
            "capacity": Value::Null,
            "reason": format!("{} asks for your approval", client.display_name),
            "require_action": {
                "domain": b64url_encode(&row.domain),
                "nonce": b64url_encode(&row.nonce),
                "intent": b64url_encode(&row.intent),
            },
            "expires_at": row.expires_ms,
        });
        Ok(Ok(CibaView {
            client: client.display_name,
            binding_message: row.binding_message,
            scopes: row
                .scope
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            expires_at_ms: row.expires_ms,
            request: pushed,
            redirect_uri,
            contribution_basis,
            domain: row.domain,
            contribution_intent,
        }))
    }

    /// The signed-in person answers the backchannel request `request` once (OP-155 m.3 (l)):
    /// declined, or approved by the hosted approval pushed under `approval`, whose finished AAS
    /// over this request's intent and recorded contribution are checked here (IDI-9). A client
    /// told by ping is pinged.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn ciba_decide(
        &self,
        realm: &Realm,
        cookie: Option<&str>,
        request: &str,
        approval: Option<&str>,
    ) -> Result<Result<(), CibaRefused>, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let (session, row) = match self.waiting_ciba(&mut tx, cookie, request, now).await? {
            Ok(w) => w,
            Err(r) => return Ok(Err(r)),
        };
        let approved = match approval {
            None => None,
            Some(uri) => {
                let found = tx.approval_by_uri(uri).await?;
                let approver = match found.as_ref().and_then(|a| a.session) {
                    Some(s) => tx.session(s).await?.map(|s| s.subject),
                    None => None,
                };
                let Some(contribution) =
                    found.as_ref().and_then(|a| approved_by(&row, a, approver))
                else {
                    return Ok(Err(CibaRefused::NotApproved));
                };
                // OP-154 m.13 (f)
                if tx
                    .ciba_answered(&row.domain, &row.nonce, &contribution)
                    .await?
                {
                    return Ok(Err(CibaRefused::NotApproved));
                }
                Some((session.id, contribution))
            }
        };
        if !tx.decide_ciba(row.id, approved, now).await? {
            return Ok(Err(CibaRefused::NoRequest));
        }
        let settings = tx.ciba_settings().await?;
        tx.commit().await?;
        // OP-155 m.3 (l)
        if let (Some(token), Some(handle), Some((_, endpoint))) = (
            row.notification_token.clone(),
            row.ping_handle.clone(),
            settings.ping.iter().find(|(c, _)| *c == row.client),
        ) && self
            .env
            .ciba()
            .ping(endpoint.clone(), token, handle)
            .await?
        {
            let mut tx = self.begin(realm).await?;
            tx.ping_ciba(row.id, now).await?;
            tx.commit().await?;
        }
        Ok(Ok(()))
    }

    /// CIBA Core §10.1, §11: the client polls with its `auth_req_id`. While the person has not
    /// answered it waits, too fast it slows down; declined, or no longer asked by the decision
    /// point (a DENY on the nonce), it is denied; once approved it is redeemed once into a
    /// DPoP-bound identity grant of the approving session with the contribution the AAS
    /// committed. No authority is in the tokens (PI-3).
    #[expect(
        clippy::too_many_lines,
        reason = "one poll, its answers in order, then one redemption"
    )]
    pub(crate) async fn ciba_token(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let invalid = || Reply::oauth_error(400, "invalid_grant", "the auth_req_id is not valid");
        let Some(handle) = params
            .get("auth_req_id")
            .and_then(|c| b64url_decode(c).ok())
        else {
            return Ok(invalid());
        };
        let Some(row) = tx.ciba_by_handle(&ciba::handle_hash(&handle)).await? else {
            return Ok(invalid());
        };
        if row.client != client.uuid || row.used_ms.is_some() {
            return Ok(invalid());
        }
        if row.expires_ms <= now {
            return Ok(Reply::oauth_error(
                400,
                "expired_token",
                "the request expired",
            ));
        }
        let denied = || Reply::oauth_error(403, "access_denied", "the request was not approved");
        match row.decision.as_deref() {
            Some("denied") => return Ok(denied()),
            Some("approved") => {}
            _ => {
                // C30, §9.9.5
                if self
                    .env
                    .ciba()
                    .opening(row.domain, row.intent)
                    .await?
                    .is_none()
                {
                    return Ok(denied());
                }
                let (interval, early) =
                    crate::domain::device::poll(row.polled_ms, row.interval_s, now);
                tx.poll_ciba(row.id, now, interval).await?;
                return Ok(if early {
                    Reply::oauth_error(400, "slow_down", "poll less often")
                } else {
                    Reply::oauth_error(400, "authorization_pending", "the person has not answered")
                });
            }
        }
        let (Some(subject), Some(session_id), Some(contribution)) =
            (row.subject, row.session, row.contribution)
        else {
            return Ok(invalid());
        };
        // G57
        let Some(session) = tx
            .session(session_id)
            .await?
            .filter(|s| session_live(s, now) && s.subject == subject)
        else {
            return Ok(invalid());
        };
        if !tx.use_ciba(row.id, now).await? {
            return Ok(invalid());
        }
        let details = GrantDetails {
            scope: row.scope.clone(),
            auth_time_ms: unsigned(session.auth_time_ms),
            aal: super::session_aal(&session)?,
            openid: true,
            authority: None,
            family: None,
            projection: None,
            resource: None,
            claims: None,
        };
        let sid = self.random::<16>()?;
        let encoded = serde_json::to_vec(&details).map_err(|_| Unavailable)?;
        let grant_id = tx
            .insert_grant(&NewGrant {
                sid,
                client: client.uuid,
                subject: session.subject,
                session: session.id,
                session_epoch: session.session_epoch,
                dpop_jkt: Some(&jkt.0),
                details: &encoded,
                created_ms: signed(now),
                expires_ms: session.expires_ms,
            })
            .await?;
        let grant = tx.grant(grant_id).await?.ok_or(Unavailable)?;
        let mut body = self
            .issue(
                tx,
                realm,
                client,
                &grant,
                &details,
                &Binding::Dpop(jkt),
                None,
                now,
            )
            .await?;
        // §9.14.5 k.2, P54
        if let Value::Object(m) = &mut body {
            m.insert(
                "access_approval".into(),
                json!({
                    "exercise_ref": exercise_ref_json(&row),
                    "intent": digest_text(&row.intent),
                    "contribution": b64url_encode(&contribution),
                }),
            );
        }
        Ok(Reply::json(200, &body))
    }
}
