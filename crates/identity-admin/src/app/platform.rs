//! The platform product API (OP-149 m.4, m.16 (a), m.17 (e), (g)): a platform client,
//! authenticated by `private_key_jwt` (RFC 7523), pairs with a tenant's realms by signing its own
//! `party_register` and `instance_create` (L0-META-7), and manages its event streams.
//!
//! Pairing has two steps. A challenge request returns, for every realm asked for, what the
//! product's Exercises name: the governing domain, the bootstrap basis, the identity plane's
//! PEP, the product's Party there, the nonces (the challenge, and for a new Party the challenge
//! followed by `0x01`), the validity window and the intent digests. The product signs the AIS
//! of each with its service key and posts them; the identity plane checks the challenge, binds
//! the key to the Party for the commit and forwards the Exercises through `internal-api`.
//! Access never holds the product's private key.

use std::collections::BTreeSet;

use access_identity_events::app::streams::{StreamError, Streams};
use access_identity_events::domain::control::parse_status;
use access_identity_events::domain::stream::parse_stream;
use access_identity_events::ports::{Clock, Random, Sealer, TenantIds};
use access_identity_oauth::app::resolve;
use access_identity_oauth::domain::client::{Client as OAuthClient, ClientAuth};
use access_identity_oauth::domain::issuer::{Issuer, PATH_PREFIX};
use access_identity_oauth::domain::jwt::{
    AssertionRules, assertion_audience, assertion_subject, parse_jwks, verify_assertion,
};
use access_identity_oauth::ports::Directory;
use access_identity_oauth::ports::oauth::ClientKeys;
use access_internal_api::context::RateContext;
use access_internal_api::instances::{
    PlatformProduct, Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis,
    register_nonce, self_signed_intent,
};
use access_kernel::digest::Digest;
use access_kernel::intent::intent_digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{self, ActorKind, ExerciseBasis, Payload};
use access_kernel::model::{Id, Window};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::platform::PairingRow;
use access_store::{idp, tenancy};
use serde_json::{Map, Value, json};

use crate::domain::from_cose_key;
use crate::ports::Instances;

/// How long a pairing challenge and the intents it names stay valid, ms (PD).
pub const PAIRING_TTL_MS: u64 = 10 * 60 * 1000;

/// Most realms one pairing request names (PD).
pub const MAX_TARGETS: usize = 64;

/// Longest AIS accepted, bytes.
const MAX_AIS: usize = 8192;

/// One day in milliseconds; the client assertion replay key lives on its `exp` day.
const DAY_MS: u64 = 86_400_000;

/// Why a platform request was not served: an RFC 9457 status and stable code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    /// No valid client assertion of an active platform client.
    #[error("unauthenticated")]
    Unauthenticated,
    /// The request is not valid; the code says why.
    #[error("invalid: {0}")]
    Invalid(&'static str),
    /// No such tenant, realm or stream.
    #[error("not found: {0}")]
    NotFound(&'static str),
    /// The state does not allow it.
    #[error("conflict: {0}")]
    Conflict(&'static str),
    /// Storage, keys or the authority plane did not answer.
    #[error("unavailable")]
    Unavailable,
}

impl PlatformError {
    /// HTTP status and stable reason code.
    #[must_use]
    pub const fn problem(self) -> (u16, &'static str) {
        match self {
            Self::Unauthenticated => (401, "client-unauthenticated"),
            Self::Invalid(c) => (400, c),
            Self::NotFound(c) => (404, c),
            Self::Conflict(c) => (409, c),
            Self::Unavailable => (503, "temporarily-unavailable"),
        }
    }
}

impl From<access_store::StoreError> for PlatformError {
    fn from(_: access_store::StoreError) -> Self {
        Self::Unavailable
    }
}

impl From<StreamError> for PlatformError {
    fn from(e: StreamError) -> Self {
        match e {
            StreamError::Invalid(i) => Self::Invalid(i.0),
            StreamError::NotFound => Self::NotFound("no-such-stream"),
            StreamError::Exists => Self::Conflict("stream-exists"),
            StreamError::UnsupportedAlg => Self::Invalid("unsupported_alg"),
            StreamError::Unavailable => Self::Unavailable,
        }
    }
}

/// An authenticated platform client: its realm in the platform tenant and what it registered.
#[derive(Clone)]
pub struct Caller {
    /// The platform tenant.
    pub tenant: TenantId,
    /// The client's realm.
    pub realm: RealmId,
    /// The `client_id`.
    pub client_id: String,
    /// The product.
    pub product: PlatformProduct,
    /// The service Instance key the product signs its Exercises with.
    pub service_key: PublicKey,
    /// Where it receives events by SSF push.
    pub event_receiver: Option<String>,
}

/// The platform product API over the identity plane's stores and ports.
pub struct PlatformApi<D, C, I, K, R, T> {
    /// `access_app`.
    pub app: Pool,
    /// `access_router`, for a tenant's live realms.
    pub router: Pool,
    /// The realm directory: a client is found in the realm its assertion's `aud` names.
    pub directory: D,
    /// Client JWKS documents.
    pub client_keys: C,
    /// The authority plane.
    pub instances: I,
    /// Event streams.
    pub streams: Streams<K, R>,
    /// Tenants' `tnt_` ids.
    pub ids: std::sync::Arc<dyn TenantIds>,
    /// The identity plane's PEP name in governing domains.
    pub pep: String,
    /// The identity plane's clock: assertion lifetimes and the intents' validity.
    pub clock: T,
}

fn day(ms: u64) -> i32 {
    i32::try_from(ms / DAY_MS).unwrap_or(i32::MAX)
}

fn uuid_text(b: &[u8; 16]) -> String {
    access_identity_events::domain::catalog::uuid(b)
}

fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if text.len() != 36 || hex.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let pair = hex.get(i.checked_mul(2)?..i.checked_mul(2)?.checked_add(2)?)?;
        *o = u8::from_str_radix(pair, 16).ok()?;
    }
    (uuid_text(&out) == text).then_some(out)
}

fn rfc3339(ms: u64) -> Result<String, PlatformError> {
    access_identity_account::notify::message::rfc3339(ms).map_err(|_| PlatformError::Unavailable)
}

fn b64(text: Option<&Value>, min: usize, max: usize) -> Result<Vec<u8>, PlatformError> {
    text.and_then(Value::as_str)
        .and_then(|t| b64url_decode(t).ok())
        .filter(|b| (min..=max).contains(&b.len()))
        .ok_or(PlatformError::Invalid("invalid-request"))
}

/// The realm, Party and Instance of a paired target.
fn paired_json(realm: &[u8; 16], party: &[u8; 16], instance: &[u8; 16], kid: &[u8; 32]) -> Value {
    json!({
        "realm": uuid_text(realm),
        "status": "paired",
        "party": b64url_encode(party),
        "instance": b64url_encode(instance),
        "kid": b64url_encode(kid),
    })
}

/// The payloads and intents a pairing's Exercises sign over.
struct Signed {
    register: Payload,
    create: Payload,
}

impl Signed {
    fn of(party: Id, key: &PublicKey) -> Self {
        Self {
            register: Payload::PartyRegister {
                party,
                root: meta::Root::Sole(party),
                actor_kind: ActorKind::System,
            },
            create: Payload::InstanceCreate {
                party,
                key: key.clone(),
                mandate: None,
            },
        }
    }
}

fn intent_of(payload: &Payload, party: Id, validity: Window) -> Result<Digest, PlatformError> {
    let intent = self_signed_intent(payload, party, validity).ok_or(PlatformError::Unavailable)?;
    intent_digest(&intent).map_err(|_| PlatformError::Unavailable)
}

impl<D, C, I, K, R, T> PlatformApi<D, C, I, K, R, T>
where
    D: Directory,
    C: ClientKeys,
    I: Instances,
    K: Sealer,
    R: Random,
    T: Clock,
{
    fn now(&self) -> Result<u64, PlatformError> {
        self.clock.now().map_err(|_| PlatformError::Unavailable)
    }

    /// RFC 7523 for a platform client outside the realm's own endpoints: the realm is the one
    /// whose issuer the assertion's single `aud` names; the client must be an active
    /// `private_key_jwt` platform client of it; `aud` must be that issuer or `endpoint`; the
    /// `jti` is recorded once.
    ///
    /// # Errors
    /// [`PlatformError::Unauthenticated`] for anything that does not authenticate.
    pub async fn authenticate(
        &self,
        assertion: &str,
        endpoint: &str,
    ) -> Result<Caller, PlatformError> {
        const NO: PlatformError = PlatformError::Unauthenticated;
        let aud = assertion_audience(assertion).map_err(|_| NO)?;
        let issuer = Issuer::parse(&aud).map_err(|_| NO)?;
        let slug = issuer.path().strip_prefix(PATH_PREFIX);
        if slug.is_none() && !issuer.path().is_empty() {
            return Err(NO);
        }
        let realm = resolve(&self.directory, issuer.authority(), slug)
            .await
            .map_err(|_| PlatformError::Unavailable)?
            .filter(|r| r.issuer.as_str() == aud)
            .ok_or(NO)?;
        let client_id = assertion_subject(assertion).map_err(|_| NO)?;
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm).await?;
        let row = idp::client(&mut t, &client_id).await?;
        t.commit().await?;
        let row = row.filter(|r| r.active).ok_or(NO)?;
        let product = row
            .platform_product
            .as_deref()
            .and_then(PlatformProduct::parse)
            .ok_or(NO)?;
        let service_key = row
            .service_key
            .as_deref()
            .and_then(from_cose_key)
            .ok_or(PlatformError::Unavailable)?;
        let event_receiver = row.event_receiver.clone();
        let client = OAuthClient::from_row(row).ok_or(NO)?;
        let doc = match &client.auth {
            ClientAuth::PrivateKeyJwt { jwks_uri } => self
                .client_keys
                .fetch(jwks_uri)
                .await
                .map_err(|_| PlatformError::Unavailable)?,
            ClientAuth::PrivateKeyJwtKey { jwks } => jwks.clone().into_bytes(),
            ClientAuth::None | ClientAuth::SecretBasic { .. } => return Err(NO),
        };
        let keys = parse_jwks(&doc).map_err(|_| NO)?;
        let now = self.now()?;
        let verified = verify_assertion(
            assertion,
            &keys,
            &AssertionRules {
                client_id: &client.id,
                issuer: realm.issuer.as_str(),
                endpoint,
                now_ms: now,
            },
        )
        .map_err(|_| NO)?;
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm).await?;
        let first = t
            .assertion_first_use(day(verified.exp_ms), &verified.replay_key)
            .await?;
        t.commit().await?;
        if !first {
            return Err(NO);
        }
        Ok(Caller {
            tenant: realm.tenant,
            realm: realm.realm,
            client_id,
            product,
            service_key,
            event_receiver,
        })
    }

    /// The tenant an external id names, if it exists.
    async fn tenant(&self, text: &str) -> Result<TenantId, PlatformError> {
        let id = self
            .ids
            .internal(text)
            .map(TenantId::from_bytes)
            .ok_or(PlatformError::NotFound("tenant-unknown"))?;
        tenancy::tenant(&self.router, id)
            .await?
            .filter(|t| t.status == "active")
            .map(|t| t.tenant)
            .ok_or(PlatformError::NotFound("tenant-unknown"))
    }

    /// The live realms of `tenant` a request names; all of them when it names none.
    async fn targets(
        &self,
        tenant: TenantId,
        named: Option<BTreeSet<[u8; 16]>>,
    ) -> Result<Vec<RealmId>, PlatformError> {
        let live: Vec<RealmId> = tenancy::tenant_routes(&self.router, &[tenant])
            .await?
            .into_iter()
            .map(|r| r.realm)
            .collect();
        match named {
            None => Ok(live),
            Some(set) => {
                let mut out = Vec::with_capacity(set.len());
                for r in set {
                    let realm = live
                        .iter()
                        .copied()
                        .find(|l| *l.as_bytes() == r)
                        .ok_or(PlatformError::NotFound("realm-unknown"))?;
                    out.push(realm);
                }
                Ok(out)
            }
        }
    }

    async fn domain(&self, tenant: TenantId, realm: RealmId) -> Result<Digest, PlatformError> {
        let mut t = TenantTx::begin(&self.app, tenant, realm).await?;
        let g = idp::governance(&mut t).await?;
        t.commit().await?;
        g.map(|g| Digest(*g.domain.as_bytes()))
            .ok_or(PlatformError::NotFound("realm-unknown"))
    }

    /// `POST /access/v1/tenants/{tenant}/pairing/challenges` (OP-149 m.4, m.16 (a), (d)): for
    /// every realm named, or every live realm of the tenant when `body` names none, either the
    /// Instance an earlier pairing with the current service key opened, or a challenge and what
    /// the product's two Exercises name. A challenge still valid is handed out again.
    ///
    /// # Errors
    /// [`PlatformError`].
    pub async fn challenges(
        &self,
        caller: &Caller,
        tenant_text: &str,
        body: &[u8],
    ) -> Result<Value, PlatformError> {
        let tenant = self.tenant(tenant_text).await?;
        let named = if body.is_empty() {
            None
        } else {
            let v: Value = serde_json::from_slice(body)
                .map_err(|_| PlatformError::Invalid("invalid-request"))?;
            let o = v
                .as_object()
                .ok_or(PlatformError::Invalid("invalid-request"))?;
            if o.keys().any(|k| k != "realms") {
                return Err(PlatformError::Invalid("unknown-member"));
            }
            match o.get("realms") {
                None => None,
                Some(Value::Array(list)) if !list.is_empty() && list.len() <= MAX_TARGETS => {
                    let mut set = BTreeSet::new();
                    for r in list {
                        let id = r
                            .as_str()
                            .and_then(parse_uuid)
                            .ok_or(PlatformError::Invalid("realms"))?;
                        set.insert(id);
                    }
                    Some(set)
                }
                Some(_) => return Err(PlatformError::Invalid("realms")),
            }
        };
        let kid = thumbprint(&caller.service_key);
        let now = self.now()?;
        let mut targets = Vec::new();
        for realm in self.targets(tenant, named).await? {
            let domain = self.domain(tenant, realm).await?;
            let mut t = TenantTx::begin(&self.app, tenant, realm).await?;
            let current = t.current_pairing(&caller.client_id, &kid, now).await?;
            let row = if let Some(row) = current {
                row
            } else {
                let bound = t.platform_party(&caller.client_id).await?;
                let party = match bound {
                    Some(p) => p,
                    None => access_crypto::random::bytes::<16>()
                        .map_err(|_| PlatformError::Unavailable)?,
                };
                let row = PairingRow {
                    challenge: access_crypto::random::bytes::<32>()
                        .map_err(|_| PlatformError::Unavailable)?,
                    client_id: caller.client_id.clone(),
                    kid,
                    party,
                    register: bound.is_none(),
                    valid_from_ms: now,
                    valid_until_ms: now.saturating_add(PAIRING_TTL_MS),
                    instance: None,
                };
                t.insert_pairing(&row).await?;
                row
            };
            t.commit().await?;
            targets.push(self.target_json(caller, realm, &domain, &row)?);
        }
        Ok(json!({
            "tenant": tenant_text,
            "targets": targets,
        }))
    }

    fn target_json(
        &self,
        caller: &Caller,
        realm: RealmId,
        domain: &Digest,
        row: &PairingRow,
    ) -> Result<Value, PlatformError> {
        if let Some(instance) = &row.instance {
            return Ok(paired_json(
                realm.as_bytes(),
                &row.party,
                instance,
                &row.kid,
            ));
        }
        let ExerciseBasis::Public(grant) = bootstrap_basis(domain) else {
            return Err(PlatformError::Unavailable);
        };
        let party = Id(row.party);
        let validity = Window {
            from: row.valid_from_ms,
            until: row.valid_until_ms,
        };
        let signed = Signed::of(party, &caller.service_key);
        let mut m = Map::new();
        m.insert("realm".into(), uuid_text(realm.as_bytes()).into());
        m.insert("status".into(), "unpaired".into());
        m.insert("domain".into(), b64url_encode(&domain.0).into());
        m.insert("basis".into(), b64url_encode(&grant.0).into());
        m.insert("pep".into(), self.pep.clone().into());
        m.insert("party".into(), b64url_encode(&row.party).into());
        m.insert("kid".into(), b64url_encode(&row.kid).into());
        m.insert("challenge".into(), b64url_encode(&row.challenge).into());
        m.insert("valid_from".into(), rfc3339(row.valid_from_ms)?.into());
        m.insert("valid_until".into(), rfc3339(row.valid_until_ms)?.into());
        m.insert(
            "instance_create".into(),
            json!({
                "nonce": b64url_encode(&row.challenge),
                "intent": b64url_encode(&intent_of(&signed.create, party, validity)?.0),
            }),
        );
        if row.register {
            m.insert(
                "party_register".into(),
                json!({
                    "nonce": b64url_encode(&register_nonce(&row.challenge)),
                    "intent": b64url_encode(&intent_of(&signed.register, party, validity)?.0),
                }),
            );
        }
        Ok(Value::Object(m))
    }

    /// `POST /access/v1/tenants/{tenant}/pairing` (OP-149 m.4, m.16 (a), L0-META-7): each
    /// target answers one challenge of this client with the AIS of `instance_create` and, for
    /// a new Party, of `party_register`, both by the service key. A target the authority plane
    /// refuses is reported, not retried. Once any target is paired and the client named a
    /// `suiss_event_receiver`, its one SSF push stream is opened (OP-149 m.17 (e)).
    ///
    /// # Errors
    /// [`PlatformError`].
    pub async fn pair(
        &self,
        caller: &Caller,
        tenant_text: &str,
        body: &[u8],
    ) -> Result<Value, PlatformError> {
        let tenant = self.tenant(tenant_text).await?;
        let v: Value =
            serde_json::from_slice(body).map_err(|_| PlatformError::Invalid("invalid-request"))?;
        let o = v
            .as_object()
            .ok_or(PlatformError::Invalid("invalid-request"))?;
        if o.keys().any(|k| k != "targets") {
            return Err(PlatformError::Invalid("unknown-member"));
        }
        let list = o
            .get("targets")
            .and_then(Value::as_array)
            .filter(|l| !l.is_empty() && l.len() <= MAX_TARGETS)
            .ok_or(PlatformError::Invalid("targets"))?;
        let live = self.targets(tenant, None).await?;
        let mut out = Vec::with_capacity(list.len());
        let mut any = false;
        for item in list {
            let o = item.as_object().ok_or(PlatformError::Invalid("targets"))?;
            if o.keys()
                .any(|k| !matches!(k.as_str(), "realm" | "challenge" | "ais" | "register_ais"))
            {
                return Err(PlatformError::Invalid("unknown-member"));
            }
            let realm = o
                .get("realm")
                .and_then(Value::as_str)
                .and_then(parse_uuid)
                .and_then(|r| live.iter().copied().find(|l| *l.as_bytes() == r))
                .ok_or(PlatformError::NotFound("realm-unknown"))?;
            let challenge = <[u8; 32]>::try_from(b64(o.get("challenge"), 32, 32)?)
                .map_err(|_| PlatformError::Invalid("invalid-request"))?;
            let ais = b64(o.get("ais"), 1, MAX_AIS)?;
            let register_ais = match o.get("register_ais") {
                None => None,
                v => Some(b64(v, 1, MAX_AIS)?),
            };
            let answer = self
                .pair_one(caller, tenant, realm, &challenge, ais, register_ais)
                .await?;
            any |= answer.get("status").and_then(Value::as_str) == Some("paired");
            out.push(answer);
        }
        let mut body = json!({ "tenant": tenant_text, "targets": out });
        if let (true, Some(receiver), Some(m)) =
            (any, caller.event_receiver.as_deref(), body.as_object_mut())
        {
            let id = self
                .streams
                .ensure_platform_push(caller.tenant, caller.realm, &caller.client_id, receiver)
                .await?;
            m.insert("event_stream".into(), uuid_text(&id).into());
        }
        Ok(body)
    }

    async fn pair_one(
        &self,
        caller: &Caller,
        tenant: TenantId,
        realm: RealmId,
        challenge: &[u8; 32],
        ais: Vec<u8>,
        register_ais: Option<Vec<u8>>,
    ) -> Result<Value, PlatformError> {
        let kid = thumbprint(&caller.service_key);
        let domain = self.domain(tenant, realm).await?;
        let now = self.now()?;
        let mut t = TenantTx::begin(&self.app, tenant, realm).await?;
        let row = t.pairing(challenge).await?;
        let bound = t.platform_party(&caller.client_id).await?;
        t.commit().await?;
        let row = row
            .filter(|r| r.client_id == caller.client_id && r.kid == kid)
            .ok_or(PlatformError::Invalid("invalid-challenge"))?;
        if let Some(instance) = &row.instance {
            return Ok(paired_json(realm.as_bytes(), &row.party, instance, &kid));
        }
        if now > row.valid_until_ms {
            return Err(PlatformError::Invalid("invalid-challenge"));
        }
        let fits = match (bound, &register_ais) {
            (Some(p), None) => p == row.party && !row.register,
            (None, Some(_)) => row.register,
            _ => false,
        };
        if !fits {
            return Err(PlatformError::Invalid("invalid-party"));
        }
        let validity = Window {
            from: row.valid_from_ms,
            until: row.valid_until_ms,
        };
        let verdict = self
            .instances
            .register(Registration {
                tenant: *tenant.as_bytes(),
                domain,
                registrant: Registrant::Service {
                    product: caller.product.clone(),
                    client: caller.client_id.clone(),
                },
                party: Id(row.party),
                key: caller.service_key.clone(),
                register: register_ais.map(|ais| SelfSigned {
                    nonce: register_nonce(challenge),
                    validity,
                    ais,
                }),
                create: SelfSigned {
                    nonce: challenge.to_vec(),
                    validity,
                    ais,
                },
                pep: self.pep.clone(),
                // OP-152 m.5 (b)
                context: RateContext::attestation(&format!("product.{}", caller.product.name())),
            })
            .await
            .map_err(|_| PlatformError::Unavailable)?;
        match verdict {
            RegistrationVerdict::Registered(r) => {
                let mut t = TenantTx::begin(&self.app, tenant, realm).await?;
                if row.register && !t.bind_platform_party(&caller.client_id, &r.party.0).await? {
                    tracing::warn!("platform party already bound");
                }
                t.record_pairing(challenge, &r.instance.0).await?;
                t.commit().await?;
                Ok(paired_json(
                    realm.as_bytes(),
                    &r.party.0,
                    &r.instance.0,
                    &r.kid,
                ))
            }
            RegistrationVerdict::Refused { code } => {
                tracing::info!(%code, "platform pairing refused");
                Ok(json!({
                    "realm": uuid_text(realm.as_bytes()),
                    "status": "refused",
                    "code": code,
                }))
            }
        }
    }

    /// `POST /access/v1/platform/streams` (OP-149 m.17 (e), (g)): a stream the client owns in
    /// its realm, from an SSF stream request; it receives every tenant's events. A webhook
    /// secret or poll credential is shown once.
    ///
    /// # Errors
    /// [`PlatformError`].
    pub async fn create_stream(
        &self,
        caller: &Caller,
        body: &[u8],
    ) -> Result<Value, PlatformError> {
        let req = parse_stream(body).map_err(|e| PlatformError::Invalid(e.0))?;
        let created = self
            .streams
            .create_for_platform(caller.tenant, caller.realm, &req, &caller.client_id)
            .await?;
        let mut out = created.stream.clone();
        if let Some(m) = out.as_object_mut() {
            if let Some(s) = &created.secret {
                m.insert("secret".into(), s.as_str().into());
            }
            if let Some(t) = &created.token {
                m.insert("access_token".into(), t.as_str().into());
            }
        }
        Ok(out)
    }

    /// `GET /access/v1/platform/streams`: the client's streams, live first.
    ///
    /// # Errors
    /// [`PlatformError`].
    pub async fn streams(&self, caller: &Caller) -> Result<Value, PlatformError> {
        let list = self
            .streams
            .owned(caller.tenant, caller.realm, &caller.client_id)
            .await?;
        Ok(json!({ "streams": list }))
    }

    /// `GET /access/v1/platform/streams/{id}`: one stream the client owns.
    ///
    /// # Errors
    /// [`PlatformError`].
    pub async fn stream(&self, caller: &Caller, id: &str) -> Result<Value, PlatformError> {
        let id = parse_uuid(id).ok_or(PlatformError::NotFound("no-such-stream"))?;
        Ok(self
            .streams
            .get_owned(caller.tenant, caller.realm, &caller.client_id, id)
            .await?)
    }

    /// `DELETE /access/v1/platform/streams/{id}`: disables a stream the client owns; nothing is
    /// deleted (OP-73).
    ///
    /// # Errors
    /// [`PlatformError`].
    pub async fn close_stream(&self, caller: &Caller, id: &str) -> Result<(), PlatformError> {
        let id = parse_uuid(id).ok_or(PlatformError::NotFound("no-such-stream"))?;
        Ok(self
            .streams
            .disable_owned(caller.tenant, caller.realm, &caller.client_id, id)
            .await?)
    }

    /// `GET /access/v1/platform/streams/{id}/status` (SSF 1.0 §8.1.2.1, OP-149 m.26 (c)): the
    /// status of a stream the client owns.
    ///
    /// # Errors
    /// [`PlatformError`].
    pub async fn stream_status(&self, caller: &Caller, id: &str) -> Result<Value, PlatformError> {
        let id = parse_uuid(id).ok_or(PlatformError::NotFound("no-such-stream"))?;
        Ok(self
            .streams
            .status_owned(caller.tenant, caller.realm, &caller.client_id, id)
            .await?)
    }

    /// `POST /access/v1/platform/streams/{id}/status` (SSF 1.0 §8.1.2.2, OP-149 m.26 (c)): sets
    /// the status of a stream the client owns, with the rules of a stream's own `/ssf/status`;
    /// the body's `stream_id` must be the path's.
    ///
    /// # Errors
    /// [`PlatformError`].
    pub async fn set_stream_status(
        &self,
        caller: &Caller,
        id: &str,
        body: &[u8],
    ) -> Result<Value, PlatformError> {
        let parsed = parse_uuid(id).ok_or(PlatformError::NotFound("no-such-stream"))?;
        let update = parse_status(body).map_err(|e| PlatformError::Invalid(e.0))?;
        if update.stream_id != id {
            return Err(PlatformError::Invalid("stream_id"));
        }
        Ok(self
            .streams
            .set_status_owned(
                caller.tenant,
                caller.realm,
                &caller.client_id,
                parsed,
                &update,
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-149 m.15 (j), OP-65: realm and stream ids are canonical lower-case UUIDs
    #[test]
    fn uuids_round_trip_in_canonical_form() {
        let id = [0xab; 16];
        let text = uuid_text(&id);
        assert_eq!(parse_uuid(&text), Some(id));
        assert_eq!(parse_uuid(&text.to_uppercase()), None);
        assert_eq!(parse_uuid("abababab-abab-abab-abab-abababababa"), None);
        assert_eq!(parse_uuid(&text.replace('-', "")), None);
    }
}
