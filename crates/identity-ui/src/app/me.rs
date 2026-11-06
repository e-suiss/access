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
use access_internal_api::instances::{
    Registrant, Registration, RegistrationVerdict, SelfSigned, Termination, bootstrap_basis,
    register_nonce,
};
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{Id, Window};
use access_store::identity::TenantTx;
use access_store::idp;
use serde_json::json;

use super::{Browser, Hosted, Reply, SESSION_REQUIRED, failed, signin};
use crate::domain::frontend::{
    AuthContextRequest, InstanceRegistration, InstanceTermination, rfc3339, unix_ms,
};
use crate::ports::{ArtifactSigner, DeviceInstances, Kits, Messages, RealmKit};

/// The ports the product-facing endpoints add to the hosted login.
pub struct Devices<A, I, P, Q> {
    /// The identity signer.
    pub signer: A,
    /// The authority plane's device Instances.
    pub instances: I,
    /// The authority plane behind the Approval Surface (OP-150 L6).
    pub approvals: P,
    /// The realm's Claim courier, for approvals (SI-5).
    pub claims: Q,
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

pub(super) fn unavailable() -> Reply {
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

/// The answer to a forwarded registration.
fn registered(
    verdict: Result<RegistrationVerdict, access_internal_api::idp::Unavailable>,
) -> Reply {
    match verdict {
        // OP-149 m.16 (f)
        Ok(RegistrationVerdict::Registered(r)) => Reply::json(
            201,
            json!({
                "instance": b64url_encode(&r.instance.0),
                "kid": b64url_encode(&r.kid),
                "party": b64url_encode(&r.party.0),
            }),
        ),
        Ok(RegistrationVerdict::Refused { code }) if code.starts_with("ais-") => {
            tracing::info!(%code, "device instance not registered");
            problem(
                400,
                KeyRejection::Pop.code(),
                "The device key could not be verified",
            )
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

/// A registration body in bytes.
struct Parsed {
    key: Vec<u8>,
    challenge: [u8; 32],
    party: [u8; 16],
    ais: Vec<u8>,
    register_ais: Option<Vec<u8>>,
    validity: Window,
}

fn parsed(body: &InstanceRegistration) -> Option<Parsed> {
    let register_ais = match body.register_ais.as_deref() {
        None => None,
        Some(a) => Some(bytes(a, 1, 8192)?),
    };
    let (from, until) = (unix_ms(&body.valid_from)?, unix_ms(&body.valid_until)?);
    (from <= until).then_some(())?;
    Some(Parsed {
        key: bytes(&body.key, 1, 256)?,
        challenge: <[u8; 32]>::try_from(bytes(&body.challenge, 32, 32)?).ok()?,
        party: <[u8; 16]>::try_from(bytes(&body.party, 16, 16)?).ok()?,
        ais: bytes(&body.ais, 1, 8192)?,
        register_ais,
        validity: Window { from, until },
    })
}

/// The active device Instance `session` registered, if any (INV-13, §7.1, §12.12/7: at most one
/// per session and realm).
async fn session_instance(
    db: &access_store::Pool,
    kit: &RealmKit,
    session: &[u8; 16],
) -> Result<Option<[u8; 16]>, Reply> {
    let mut t = TenantTx::begin(db, kit.tenant, kit.realm)
        .await
        .map_err(|_| unavailable())?;
    let i = access_store::issuer::session_instance(&mut t, session)
        .await
        .map_err(|_| unavailable())?;
    t.commit().await.map_err(|_| unavailable())?;
    Ok(i)
}

/// The Party the subject's device Instances belong to (OP-149 m.16 (a)).
async fn bound_party(
    db: &access_store::Pool,
    kit: &RealmKit,
    subject: &[u8; 16],
) -> Result<Option<[u8; 16]>, Reply> {
    let mut t = TenantTx::begin(db, kit.tenant, kit.realm)
        .await
        .map_err(|_| unavailable())?;
    let p = idp::subject_party(&mut t, subject)
        .await
        .map_err(|_| unavailable())?;
    t.commit().await.map_err(|_| unavailable())?;
    Ok(p)
}

/// Records the Party the subject's first device registered and queues the
/// `identity_binding_person` Claim that binds the subject to it (§10.1.3 IDP-2, §10.1.5): its
/// proof, the Party's own `party_register`, enters by digest only.
async fn bind_party(
    db: &access_store::Pool,
    kit: &RealmKit,
    subject: &[u8; 16],
    party: &[u8; 16],
    proof: &[u8],
) -> Result<(), Reply> {
    use access_identity_account::app::claims::emit;
    use access_identity_account::domain::claims::identity_binding;
    use access_kernel::claim::body::BindingKind;
    let mut tx = access_identity_account::adapters::pg::PgTx(
        TenantTx::begin(db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?,
    );
    if idp::bind_subject_party(&mut tx.0, subject, party)
        .await
        .map_err(|_| unavailable())?
    {
        let at = tx.0.server_time().await.map_err(|_| unavailable())?;
        let order = identity_binding(*subject, BindingKind::Person, proof, at);
        emit(&mut tx, &order).await.map_err(|_| unavailable())?;
    } else {
        tracing::warn!("device party already bound");
    }
    tx.0.commit().await.map_err(|_| unavailable())
}

/// Records a registered device key (§10.1.3 "Cihaz anahtarı kaydı") and queues its Claims: the
/// `authenticator_binding` of the key, bound to its Instance, and the `authentication` of the
/// session that proved the key, now bound to that Instance (§10.1.5, OP-150 L2).
async fn device_registered(
    db: &access_store::Pool,
    kit: &RealmKit,
    proven: &access_identity_session::app::devices::ProvenKey,
    instance: [u8; 16],
) -> Result<(), Reply> {
    use access_identity_account::app::claims::emit;
    use access_identity_account::domain::claims::{self, AuthFacts, Bind};
    use access_kernel::verify::cose::PublicKey;
    let (key, kty, alg, cose) = match &proven.key {
        PublicKey::Ed25519(k) => (k.to_vec(), "OKP", "Ed25519", -8),
        PublicKey::P256(k) => (k.clone(), "EC2", "ES256", -7),
        PublicKey::MlDsa(..) => return Err(invalid()),
    };
    let s = &proven.session;
    let mut tx = access_identity_account::adapters::pg::PgTx(
        TenantTx::begin(db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?,
    );
    let row = access_store::issuer::NewDeviceKey {
        subject: s.subject,
        public_key: &key,
        key_type: kty,
        algorithm: alg,
        instance,
        session: Some(s.id),
    };
    let fresh = access_store::issuer::insert_device_key(&mut tx.0, &row)
        .await
        .map_err(|_| unavailable())?
        .is_some();
    if fresh {
        let at = tx.0.server_time().await.map_err(|_| unavailable())?;
        let binding = claims::device_key_binding(s.subject, &key, cose, instance, at);
        let login = claims::authentication(AuthFacts {
            subject: s.subject,
            method: access_kernel::claim::body::AuthMethod::DeviceKey,
            auth_time: s.auth_time_ms,
            assurance: access_identity_session::app::claims::levels(&s.assurance),
            webauthn: None,
            evidence: None,
            bind: Bind::Instance(instance),
        });
        for order in [binding, login] {
            emit(&mut tx, &order).await.map_err(|_| unavailable())?;
        }
    }
    tx.0.commit().await.map_err(|_| unavailable())
}

/// Retires the device key of a terminated Instance (§10.1.3 `status`) and ends its binding line
/// (IDP-2); the Instance itself was ended by `instance.terminate`.
async fn device_retired(
    db: &access_store::Pool,
    kit: &RealmKit,
    subject: [u8; 16],
    instance: [u8; 16],
) -> Result<(), Reply> {
    use access_identity_account::app::claims::emit;
    use access_identity_account::domain::claims::authenticator_removed;
    use access_kernel::claim::body::AuthenticatorKind;
    let mut tx = access_identity_account::adapters::pg::PgTx(
        TenantTx::begin(db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?,
    );
    if access_store::issuer::retire_device_key(&mut tx.0, &subject, &instance)
        .await
        .map_err(|_| unavailable())?
    {
        let at = tx.0.server_time().await.map_err(|_| unavailable())?;
        let order = authenticator_removed(subject, AuthenticatorKind::DeviceKey, &instance, at);
        emit(&mut tx, &order).await.map_err(|_| unavailable())?;
    }
    tx.0.commit().await.map_err(|_| unavailable())
}

/// The realm's governing domain.
pub(super) async fn governing(db: &access_store::Pool, kit: &RealmKit) -> Result<Digest, Reply> {
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
    /// `POST /v1/me/instances/challenges` (OP-149 m.6, m.16 (a)): the challenge, and what the
    /// device's Exercises name: the governing domain, the bootstrap basis, the PEP and the
    /// user's Party once there is one.
    pub async fn instance_challenge<A, I, P, Q>(
        &self,
        devices: &Devices<A, I, P, Q>,
        entry: &RealmEntry,
        b: &Browser<'_>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return session_required();
        };
        let c = match auth.instance_challenge(cookie).await {
            Ok(Ok(c)) => c,
            Ok(Err(status)) => return ended(&status),
            Err(e) => return failed(&e),
        };
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let party = match bound_party(&self.db, &kit, &c.subject).await {
            Ok(p) => p,
            Err(r) => return r,
        };
        let ExerciseBasis::Public(grant) = bootstrap_basis(&domain) else {
            return unavailable();
        };
        let mut out = json!({
            "challenge": c.challenge,
            "expires_at": rfc3339(c.expires_ms),
            "domain": b64url_encode(&domain.0),
            "basis": b64url_encode(&grant.0),
            "pep": devices.pep,
        });
        if let (Some(p), Some(m)) = (party, out.as_object_mut()) {
            m.insert("party".into(), b64url_encode(&p).into());
        }
        Reply::json(201, out)
    }

    /// `POST /v1/me/instances` (OP-149 m.6, m.16 (a)): the session's step-up and its challenge
    /// first; the Party must be the user's, or a new one the device registers when the user has
    /// none; then the device's own Exercises go to the authority plane through `internal-api`,
    /// which binds the key to that Party for their commit (L0-META-7).
    pub async fn register_instance<A, I: DeviceInstances, P, Q>(
        &self,
        devices: &Devices<A, I, P, Q>,
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
        let Some(Parsed {
            key,
            challenge,
            party,
            ais,
            register_ais,
            validity,
        }) = parsed(body)
        else {
            return invalid();
        };
        let proven = match auth
            .claim_instance_challenge(cookie, &key, &challenge, b.correlation)
            .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(r)) => return refused(&r),
            Err(e) => return failed(&e),
        };
        let subject = proven.session.subject;
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let bound = match bound_party(&self.db, &kit, &subject).await {
            Ok(p) => p,
            Err(r) => return r,
        };
        let fits = match (bound, &register_ais) {
            (Some(p), None) => p == party,
            (None, Some(_)) => true,
            _ => false,
        };
        if !fits {
            return problem(400, "invalid-party", "The Party is not this user's");
        }
        // INV-13, §7.1, §12.12/7: one human Instance per session and realm; renewing the
        // session is not a new Instance
        match session_instance(&self.db, &kit, &proven.session.id).await {
            Ok(None) => {}
            Ok(Some(_)) => {
                return problem(
                    409,
                    "instance-exists",
                    "This sign-in already has a device; remove it first",
                );
            }
            Err(r) => return r,
        }
        let verdict = devices
            .instances
            .register(Registration {
                tenant: *kit.tenant.as_bytes(),
                domain,
                registrant: Registrant::Device {
                    realm: *kit.realm.as_bytes(),
                    subject,
                },
                party: Id(party),
                key: proven.key.clone(),
                register: register_ais.as_ref().map(|ais| SelfSigned {
                    nonce: register_nonce(&challenge),
                    validity,
                    ais: ais.clone(),
                }),
                create: SelfSigned {
                    nonce: challenge.to_vec(),
                    validity,
                    ais,
                },
                pep: devices.pep.clone(),
            })
            .await;
        if let (Ok(RegistrationVerdict::Registered(_)), None, Some(proof)) =
            (&verdict, bound, &register_ais)
            && let Err(r) = bind_party(&self.db, &kit, &subject, &party, proof).await
        {
            return r;
        }
        // §10.1.3 device key, OP-150 L2
        if let Ok(RegistrationVerdict::Registered(r)) = &verdict
            && let Err(reply) = device_registered(&self.db, &kit, &proven, r.instance.0).await
        {
            return reply;
        }
        registered(verdict)
    }

    /// `DELETE /v1/me/instances/{instance}` (OP-149 m.6, OP-146 m.4 (i)): the user's own
    /// Instance signed the termination; Access checks the session's step-up and forwards it as
    /// PEP.
    pub async fn terminate_instance<A, I: DeviceInstances, P, Q>(
        &self,
        devices: &Devices<A, I, P, Q>,
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
        // OP-149 m.16 (f)
        let Some(instance) = bytes(instance, 16, 16).and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
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
        let session = match auth.stepped_up_session(cookie).await {
            Ok(Ok(s)) => s,
            Ok(Err(r)) => return refused(&r),
            Err(e) => return failed(&e),
        };
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
                // IDP-2, §10.1.3, OP-150 L2
                if let Err(r) = device_retired(&self.db, &kit, session.subject, instance).await {
                    return r;
                }
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
    pub async fn auth_context<A: ArtifactSigner, I, P, Q>(
        &self,
        devices: &Devices<A, I, P, Q>,
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
}
