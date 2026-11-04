//! The Frontend API for products (OP-149 m.6, m.8, m.9): device Instances from a stepped-up
//! session, the signed `auth_context` artifact and the approval call. A session that is not live
//! gets `401` and nothing else happens (G57).

use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::devices::DeviceRefusal;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::domain::auth_context::{CONTENT_TYPE, Content};
use access_identity_session::domain::device::{Assurance, KeyRejection};
use access_identity_session::domain::session::{SESSION_COOKIE, clear_cookie};
use access_identity_session::ports::Clock;
use access_internal_api::idp::Verdict;
use access_internal_api::instances::{Registrant, Registration, RegistrationVerdict, Termination};
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{Id, Window};
use access_store::identity::TenantTx;
use access_store::idp;
use serde_json::json;

use super::{Browser, Hosted, Reply, SESSION_REQUIRED, failed, signin};
use crate::domain::frontend::{
    ApproveQuery, ApproveRejection, AuthContextRequest, INSTANCE_PREFIX, InstanceRegistration,
    InstanceTermination, approval_request, rfc3339, unix_ms,
};
use crate::ports::{ArtifactSigner, DeviceInstances, Kits, Messages, RealmKit};

/// The ports the product-facing endpoints add to the hosted login.
pub struct Devices<A, I> {
    /// The identity signer.
    pub signer: A,
    /// The authority plane's device Instances.
    pub instances: I,
    /// The identity plane's PEP name in the governing domain.
    pub pep: String,
}

fn problem(status: u16, code: &'static str, title: &'static str) -> Reply {
    Reply::problem(Problem {
        status,
        code,
        title,
        retry_after_s: None,
    })
}

const INVALID: Problem = Problem {
    status: 400,
    code: "invalid-request",
    title: "The request is not valid",
    retry_after_s: None,
};

const UNAVAILABLE: Problem = Problem {
    status: 503,
    code: "unavailable",
    title: "Temporarily unavailable",
    retry_after_s: Some(1),
};

fn invalid() -> Reply {
    Reply::problem(INVALID)
}

fn unavailable() -> Reply {
    Reply::problem(UNAVAILABLE)
}

fn session_required() -> Reply {
    Reply::problem(SESSION_REQUIRED)
}

fn refused(r: &DeviceRefusal) -> Reply {
    match r {
        DeviceRefusal::Session(status) => ended(status),
        DeviceRefusal::Assurance(Assurance::TooWeak | Assurance::Stale | Assurance::Fresh) => {
            problem(403, "step-up-required", "Confirm it's you again first")
        }
        DeviceRefusal::Challenge => problem(400, "invalid-challenge", "Ask for a new challenge"),
        DeviceRefusal::Key(k @ (KeyRejection::Key | KeyRejection::Pop)) => {
            problem(400, k.code(), "The device key could not be verified")
        }
    }
}

fn ended(status: &SessionStatus) -> Reply {
    let mut r = session_required();
    if matches!(status, SessionStatus::Invalid(_)) {
        r.cookies.push(clear_cookie(SESSION_COOKIE));
    }
    r
}

fn bytes(text: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    b64url_decode(text)
        .ok()
        .filter(|b| (min..=max).contains(&b.len()))
}

/// The realm's governing domain.
async fn governing(db: &access_store::Pool, kit: &RealmKit) -> Result<Digest, Reply> {
    let mut t = TenantTx::begin(db, kit.tenant, kit.realm)
        .await
        .map_err(|_| unavailable())?;
    let g = idp::governance(&mut t).await.map_err(|_| unavailable())?;
    t.commit().await.map_err(|_| unavailable())?;
    g.map(|g| Digest(*g.domain.as_bytes()))
        .ok_or_else(unavailable)
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// `POST /v1/me/instances/challenges`.
    pub async fn instance_challenge(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return session_required();
        };
        match auth.instance_challenge(cookie).await {
            Ok(Ok(c)) => Reply::json(
                201,
                json!({ "challenge": c.challenge, "expires_at": rfc3339(c.expires_ms) }),
            ),
            Ok(Err(status)) => ended(&status),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/me/instances` (OP-149 m.6): the session's step-up and the proof first, then
    /// the authority plane opens the Instance through `internal-api`.
    pub async fn register_instance<A, I: DeviceInstances>(
        &self,
        devices: &Devices<A, I>,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &InstanceRegistration,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return session_required();
        };
        let (Some(key), Some(pop)) = (bytes(&body.key, 1, 256), bytes(&body.pop, 1, 1024)) else {
            return invalid();
        };
        let proven = match auth
            .prove_instance_key(cookie, &key, &pop, &kit.issuer, b.correlation)
            .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(r)) => return refused(&r),
            Err(e) => return failed(&e),
        };
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let verdict = devices
            .instances
            .register(Registration {
                tenant: *kit.tenant.as_bytes(),
                domain,
                registrant: Registrant::Device {
                    realm: *kit.realm.as_bytes(),
                    subject: proven.session.subject,
                },
                key: proven.key,
            })
            .await;
        match verdict {
            Ok(RegistrationVerdict::Registered(r)) => {
                match kit.ids.encode(INSTANCE_PREFIX, r.instance.0) {
                    Ok(instance) => Reply::json(
                        201,
                        json!({ "instance": instance, "kid": b64url_encode(&r.kid) }),
                    ),
                    Err(_) => unavailable(),
                }
            }
            Ok(RegistrationVerdict::Refused { code }) => {
                tracing::info!(%code, "device instance not registered");
                problem(
                    409,
                    "instance-not-registered",
                    "The device could not be registered",
                )
            }
            Err(_) => unavailable(),
        }
    }

    /// `DELETE /v1/me/instances/{instance}` (OP-149 m.6, OP-146 m.4 (i)): the user's own
    /// Instance signed the termination; Access checks the session's step-up and forwards it as
    /// PEP.
    pub async fn terminate_instance<A, I: DeviceInstances>(
        &self,
        devices: &Devices<A, I>,
        entry: &RealmEntry,
        b: &Browser<'_>,
        instance: &str,
        body: &InstanceTermination,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return session_required();
        };
        let Ok(instance) = kit.ids.decode(INSTANCE_PREFIX, instance) else {
            return invalid();
        };
        let (Some(nonce), Some(basis), Some(ais), Some(from), Some(until)) = (
            bytes(&body.nonce, 16, 64),
            bytes(&body.basis, 16, 16).and_then(|b| <[u8; 16]>::try_from(b).ok()),
            bytes(&body.ais, 1, 8192),
            unix_ms(&body.valid_from),
            unix_ms(&body.valid_until),
        ) else {
            return invalid();
        };
        if from > until {
            return invalid();
        }
        match auth.stepped_up_session(cookie).await {
            Ok(Ok(_)) => {}
            Ok(Err(r)) => return refused(&r),
            Err(e) => return failed(&e),
        }
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let verdict = devices
            .instances
            .terminate(Termination {
                domain,
                nonce,
                instance: Id(instance),
                validity: Window { from, until },
                basis: ExerciseBasis::Anchor(Id(basis)),
                ais,
                pep: devices.pep.clone(),
            })
            .await;
        match verdict {
            Ok(Verdict::Committed(c)) => {
                Reply::json(200, json!({ "exercise": b64url_encode(&c.exercise.0) }))
            }
            Ok(Verdict::NotAllowed { .. } | Verdict::Refused { .. }) => problem(
                409,
                "instance-not-terminated",
                "The device could not be removed",
            ),
            Err(_) => unavailable(),
        }
    }

    /// `POST /v1/me/auth-context` (OP-149 m.8): the artifact of this session, bound to the
    /// content when given, signed by the realm's identity signer key.
    pub async fn auth_context<A: ArtifactSigner, I>(
        &self,
        devices: &Devices<A, I>,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: Option<&AuthContextRequest>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return session_required();
        };
        let content = match body {
            None => None,
            Some(req) => {
                let digest =
                    bytes(&req.content_digest, 32, 32).and_then(|d| <[u8; 32]>::try_from(d).ok());
                match digest.and_then(|d| Content::new(&req.content_type, d).ok()) {
                    Some(c) => Some(c),
                    None => {
                        return problem(400, "invalid-content", "The content binding is not valid");
                    }
                }
            }
        };
        let artifact = match auth.auth_context(cookie, &kit.issuer, content).await {
            Ok(Ok(a)) => a,
            Ok(Err(status)) => return ended(&status),
            Err(e) => return failed(&e),
        };
        let (Ok(payload), Ok(digest)) = (artifact.encode(), artifact.digest()) else {
            return unavailable();
        };
        match devices
            .signer
            .sign_cose(kit.realm, CONTENT_TYPE, &payload, self.clock.now_ms())
            .await
        {
            Ok(sign1) => Reply::json(
                200,
                json!({
                    "auth_context": b64url_encode(&sign1),
                    "digest": b64url_encode(&digest.0),
                }),
            ),
            Err(_) => unavailable(),
        }
    }

    /// `GET /v1/approve` (OP-149 m.9): the call contract and its checks. `redirect_uri` must be
    /// exactly one an active client of the realm registered, and nothing redirects before that
    /// holds. The Approval Surface itself is a later feature: a valid call gets
    /// `approval-surface-unavailable`.
    pub async fn approve(&self, entry: &RealmEntry, query: &ApproveQuery) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        if let Err(e) = approval_request(query) {
            return problem(400, e.code(), "The approval call is not valid");
        }
        let clients = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let list = idp::clients_with_redirect(&mut t, &query.redirect_uri).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(list)
        };
        match clients.await {
            Ok(list) if list.is_empty() => problem(
                400,
                ApproveRejection::RedirectUri.code(),
                "The approval call is not valid",
            ),
            Ok(_) => problem(
                501,
                "approval-surface-unavailable",
                "Approvals are not available yet",
            ),
            Err(_) => unavailable(),
        }
    }
}
