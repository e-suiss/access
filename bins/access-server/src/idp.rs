//! The in-process seam between the planes for `idp.*` (OP-62, MD-14, TN-111): the identity
//! plane's ports, served by the authority core of this process, the actor-binding of
//! self-signed registrations (OP-149 m.16 (a), L0-META-7), and the realm keys a new realm opens
//! (OP-146 m.16 (m)).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use access_authority_core::CoreError;
use access_authority_core::adapters::{Domains, OsSalts};
use access_authority_core::app::Incoming;
use access_authority_core::domain::Request;
use access_authority_core::genesis;
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_crypto::dpop::{Role as NonceRole, label as nonce_label};
use access_crypto::jose::JwsAlg;
use access_crypto::webauthn::decoy_label;
use access_identity_admin::domain::JoseAlg;
use access_identity_admin::ports::{
    Decider, Governance, Instances, OrgRegistered, OrgRegistration, PartyKind, RealmKeys,
};
use access_identity_oauth::adapters::SignerKeys;
use access_identity_ui::ports::{Approvals, DeviceInstances};
use access_internal_api::approvals::{
    Contribution, Opening, contribute_intent, contribute_payload,
};
use access_internal_api::context::RateContext;
use access_internal_api::instances::{
    Registered, Registration, RegistrationVerdict, SelfSigned, Termination, bootstrap_basis,
    self_signed_intent, terminate_intent, terminate_payload,
};
use access_kernel::combinator::Capacity;
use access_kernel::meta::Payload;
use access_kernel::model::{ActionRef, Id};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use access_store::identity::RealmId;
use suiss_crypto::pkcs11::{HsmError, KeyStore};

use crate::login::{kek_label, pepper_label};
use crate::oauth::NONCE_GENERATION;
use access_internal_api::idp::{
    ACTOR_BINDING, Committed, GenesisOpened, GenesisOrder, Submission, Unavailable, Verdict,
};
use access_kernel::combinator::{Mode, Outcome};
use access_kernel::digest::Digest;
use access_store::Pool;
use access_store::authority::find_nonce;
use access_store::scope::DomainId;

/// The actor-binding of self-signed registrations (§7.9.2.3, OP-149 m.16 (a)): while the
/// identity plane forwards a `party_register` or `instance_create`, the new key's `kid` is bound
/// to the Party the identity plane checked, so the core verifies the Exercise's AIS with that key
/// and L0-META-7 holds the actor to that Party. Nothing else is bound; an unbound key is
/// anonymous.
#[derive(Clone, Default)]
pub(crate) struct ActorBindings(Arc<Mutex<HashMap<[u8; 32], Held>>>);

struct Held {
    party: Id,
    key: PublicKey,
    holds: usize,
}

/// One forwarded registration's hold on a binding; dropping it releases the binding.
pub(crate) struct Hold {
    bindings: ActorBindings,
    kid: [u8; 32],
}

impl ActorBindings {
    /// Binds `key` to `party` until the hold is dropped. `None` when the key is bound to
    /// another Party at the moment.
    pub(crate) fn hold(&self, party: Id, key: &PublicKey) -> Option<Hold> {
        let kid = thumbprint(key);
        let mut map = self.0.lock().ok()?;
        let held = map.entry(kid).or_insert_with(|| Held {
            party,
            key: key.clone(),
            holds: 0,
        });
        if held.party != party || held.key != *key {
            return None;
        }
        held.holds = held.holds.saturating_add(1);
        Some(Hold {
            bindings: self.clone(),
            kid,
        })
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        if let Ok(mut map) = self.bindings.0.lock()
            && let Some(held) = map.get_mut(&self.kid)
        {
            held.holds = held.holds.saturating_sub(1);
            if held.holds == 0 {
                map.remove(&self.kid);
            }
        }
    }
}

impl Binding for ActorBindings {
    fn bound(&self, kid: &[u8; 32]) -> Option<(Id, PublicKey)> {
        let map = self.0.lock().ok()?;
        map.get(kid).map(|h| (h.party, h.key.clone()))
    }
}

/// The authority plane as the identity plane's [`Decider`] and [`Governance`].
pub(crate) struct Plane<K, B: Binding, S: Salts, C> {
    domains: Arc<Domains<K, B, S, C>>,
    app: Pool,
    clock: C,
    actors: ActorBindings,
}

impl<K, B: Binding + Clone, S: Salts, C: Clone> Clone for Plane<K, B, S, C> {
    fn clone(&self) -> Self {
        Self {
            domains: Arc::clone(&self.domains),
            app: self.app.clone(),
            clock: self.clock.clone(),
            actors: self.actors.clone(),
        }
    }
}

impl<K, B: Binding, S: Salts, C> Plane<K, B, S, C> {
    /// Over the domains this process leads; `actors` is the binding those domains read.
    pub(crate) const fn new(
        domains: Arc<Domains<K, B, S, C>>,
        app: Pool,
        clock: C,
        actors: ActorBindings,
    ) -> Self {
        Self {
            domains,
            app,
            clock,
            actors,
        }
    }
}

fn refused(e: &CoreError) -> Verdict {
    // OP-149 m.12, m.30 (b)
    Verdict::Refused {
        code: String::from(e.reason().unwrap_or_else(|| e.code())),
        errors: e.expected(),
    }
}

/// The authority plane could not serve the request; the stable reason travels with it, so a
/// one-shot job can say why (OP-149 m.28 (a)).
fn unavailable(e: &CoreError) -> Unavailable {
    Unavailable(String::from(match e {
        CoreError::Unavailable(reason) => reason,
        CoreError::Store(_) => "store",
        CoreError::Sequencer(_) => "sequencer",
        other => other.code(),
    }))
}

/// A core error as the identity plane's verdict: a refusal with the core's stable code, or
/// `Err` when the plane could not serve the request at all.
fn verdict(e: &CoreError) -> Result<Verdict, Unavailable> {
    match e {
        CoreError::Unavailable(_) | CoreError::Store(_) | CoreError::Sequencer(_) => {
            Err(unavailable(e))
        }
        other => Ok(refused(other)),
    }
}

// OP-151 m.6 (e)
// OP-151 m.20 (a)
impl<K, B, S, C> access_http::console::ports::AcceptedActions for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    fn action<'a>(
        &'a self,
        domain: Digest,
        namespace: &'a str,
        name: &'a str,
        major: u64,
    ) -> access_http::console::ports::Accepted<'a> {
        Box::pin(async move {
            self.domains
                .accepted_action(domain, namespace, name, major)
                .await
                .map_err(|e| {
                    tracing::warn!(event = "console.accepted.unavailable", outcome = "error", error = %e, "accepted actions unavailable");
                    access_http::api::ports::Unavailable
                })
        })
    }
}

impl<K, B, S, C> crate::admin::realm::LiveKeys for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn live_key(
        &self,
        domain: Digest,
        kid: [u8; 32],
    ) -> Result<Option<PublicKey>, access_http::api::ports::Unavailable> {
        use access_authority_core::keys::{AsOf, KeyState};
        match self
            .domains
            .lookup_keys(domain, &[kid], AsOf::Head, false)
            .await
        {
            Ok(answer) => Ok(answer
                .lookup
                .keys
                .into_iter()
                .find(|e| e.kid == kid && e.state == KeyState::Active)
                .map(|e| e.key)),
            Err(CoreError::Protocol(_)) => Ok(None),
            Err(_) => Err(access_http::api::ports::Unavailable),
        }
    }
}

impl<K, B, S, C> Decider for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn decide(&self, s: Submission) -> Result<Verdict, Unavailable> {
        // §13.4 G54, OP-149 m.16 (a)
        if let Some(party) = s.actor {
            match self.domains.signer_party(s.domain, &s.ais).await {
                Ok(Some(p)) if p == party => {}
                Ok(_) => {
                    return Ok(Verdict::Refused {
                        code: String::from(ACTOR_BINDING),
                        errors: Vec::new(),
                    });
                }
                Err(e) => return verdict(&e),
            }
        }
        let request = Request {
            domain: s.domain,
            mode: Mode::Commit,
            nonce: s.nonce,
            intent: s.intent,
            payload: s.payload.map(|p| *p),
            basis: s.basis,
            capacity: s.capacity,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        };
        self.commit(request, s.ais, (s.pep, None)).await
    }

    async fn signer(&self, domain: Digest, ais: &[u8]) -> Result<Option<Id>, Unavailable> {
        match self.domains.signer_party(domain, ais).await {
            Ok(party) => Ok(party),
            Err(e) => match verdict(&e) {
                Err(u) => Err(u),
                Ok(_) => Ok(None),
            },
        }
    }
}

impl<K, B, S, C> Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    /// Commits `request` with the actor's `ais` as the identity plane's PEP and reads the
    /// recorded ALLOW back (EI-25).
    async fn commit(
        &self,
        request: Request,
        ais: Vec<u8>,
        (pep, context): (String, Option<RateContext>),
    ) -> Result<Verdict, Unavailable> {
        let domain = request.domain;
        let nonce = request.nonce.clone();
        let inc = Incoming {
            request,
            ais: Some(ais),
            pep,
            requester: None,
            explain: false,
            status: None,
            context,
        };
        let r = match self.domains.exercise(&inc).await {
            Ok(r) => r,
            Err(e) => return verdict(&e),
        };
        if r.decision.outcome != Outcome::Allow {
            return Ok(Verdict::NotAllowed {
                decision: r.decision,
                position: r.record,
            });
        }
        let (Some(exercise), Some(_)) = (r.exercise, r.record) else {
            return Err(Unavailable(String::from("allow-without-record")));
        };
        // EI-25
        let row = find_nonce(&self.app, &DomainId::from_bytes(domain.0), &nonce)
            .await
            .map_err(|e| Unavailable(e.to_string()))?
            .filter(|n| n.outcome == "allow")
            .ok_or_else(|| Unavailable(String::from("allow-not-recorded")))?;
        Ok(Verdict::Committed(Committed {
            domain,
            nonce,
            position: row.decision_pos,
            intent: Digest(row.intent_digest),
            exercise,
            replayed: r.replayed,
        }))
    }
}

/// A key bound to another Party while this registration was forwarded.
pub(crate) const BINDING_BUSY: &str = "actor-binding-busy";

/// Why a registration's Exercise was not recorded: the core's stable code, or `denied`.
fn not_registered(v: Verdict) -> Result<RegistrationVerdict, Unavailable> {
    match v {
        Verdict::Committed(_) => Err(Unavailable(String::from("committed"))),
        Verdict::Refused { code, .. } => Ok(RegistrationVerdict::Refused { code }),
        Verdict::NotAllowed { .. } => Ok(RegistrationVerdict::Refused {
            code: String::from("denied"),
        }),
    }
}

impl<K, B, S, C> Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    /// Commits one self-signed `payload` of `party` in `domain` under the bootstrap basis.
    async fn self_signed_in(
        &self,
        (domain, party): (Digest, Id),
        e: &SelfSigned,
        payload: Payload,
        (pep, context): (String, Option<RateContext>),
    ) -> Result<Verdict, Unavailable> {
        let Some(intent) = self_signed_intent(&payload, party, e.validity) else {
            return Ok(Verdict::Refused {
                code: String::from("protocol"),
                errors: Vec::new(),
            });
        };
        let request = Request {
            domain,
            mode: Mode::Commit,
            nonce: e.nonce.clone(),
            intent,
            payload: Some(payload),
            basis: bootstrap_basis(&domain),
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        };
        // OP-152 m.5 (b)
        self.commit(request, e.ais.clone(), (pep, context)).await
    }

    /// OP-149 m.16 (a), L0-META-7: binds the new key to the checked Party, commits
    /// `party_register` when the Party is new and then `instance_create`, both signed by that
    /// key, and releases the binding.
    async fn register_signed(&self, r: Registration) -> Result<RegistrationVerdict, Unavailable> {
        let Some(_hold) = self.actors.hold(r.party, &r.key) else {
            return Ok(RegistrationVerdict::Refused {
                code: String::from(BINDING_BUSY),
            });
        };
        if let Some(e) = &r.register {
            match self
                .self_signed_in(
                    (r.domain, r.party),
                    e,
                    r.register_payload(),
                    (r.pep.clone(), r.context.clone()),
                )
                .await?
            {
                Verdict::Committed(_) => {}
                other => return not_registered(other),
            }
        }
        let created = match self
            .self_signed_in(
                (r.domain, r.party),
                &r.create,
                r.create_payload(),
                (r.pep.clone(), r.context.clone()),
            )
            .await?
        {
            Verdict::Committed(c) => c,
            other => return not_registered(other),
        };
        let instance = r
            .instance()
            .ok_or_else(|| Unavailable(String::from("nonce")))?;
        Ok(RegistrationVerdict::Registered(Registered {
            party: r.party,
            instance,
            kid: thumbprint(&r.key),
            replayed: created.replayed,
        }))
    }
}

impl<K, B, S, C> Instances for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, Unavailable> {
        self.register_signed(r).await
    }

    async fn now(&self) -> Result<u64, Unavailable> {
        // OP-129 m.1
        self.clock
            .clone()
            .now()
            .await
            .map_err(|e| Unavailable(e.to_string()))
    }

    async fn party(&self, domain: Digest, party: Id) -> Result<Option<PartyKind>, Unavailable> {
        // OP-153 m.10 (e), OP-149 m.28 (c)
        let answer = self
            .domains
            .lookup_parties(
                domain,
                &[party],
                access_authority_core::keys::AsOf::Head,
                false,
            )
            .await
            .map_err(|e| unavailable(&e))?;
        Ok(answer.lookup.parties.first().map(|p| PartyKind {
            actor_kind: p.actor_kind,
            ended: p.ended.is_some(),
        }))
    }

    async fn register_organization(
        &self,
        r: OrgRegistration,
    ) -> Result<OrgRegistered, Unavailable> {
        // OP-153 m.3 (b), L0-META-7, C6
        let Some(_hold) = self.actors.hold(r.party, &r.key) else {
            return Ok(OrgRegistered::Refused {
                code: String::from(BINDING_BUSY),
            });
        };
        let verdict = self
            .self_signed_in((r.domain, r.party), &r.register, r.payload(), (r.pep, None))
            .await?;
        Ok(match verdict {
            Verdict::Committed(c) => OrgRegistered::Registered {
                replayed: c.replayed,
            },
            Verdict::Refused { code, .. } => OrgRegistered::Refused { code },
            Verdict::NotAllowed { .. } => OrgRegistered::Refused {
                code: String::from("denied"),
            },
        })
    }
}

impl<K, B, S, C> crate::bootstrap::MetaExercises for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn meta(
        &self,
        request: Request,
        ais: Vec<u8>,
        pep: String,
    ) -> Result<Verdict, Unavailable> {
        self.commit(request, ais, (pep, None)).await
    }

    async fn lead(&self, domain: Digest) -> Result<(), Unavailable> {
        // OP-149 m.28 (a)
        self.domains
            .take_over(domain)
            .await
            .map_err(|e| unavailable(&e))
    }

    async fn accepts(&self, domain: Digest, action: ActionRef) -> Result<bool, Unavailable> {
        let found = self
            .domains
            .accepted_action(domain, &action.namespace, &action.name, action.major)
            .await
            .map_err(|e| unavailable(&e))?;
        Ok(found.is_some_and(|a| a == action))
    }
}

impl<K, B, S, C> DeviceInstances for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, Unavailable> {
        self.register_signed(r).await
    }

    async fn terminate(&self, t: Termination) -> Result<Verdict, Unavailable> {
        // OP-149 m.6, OP-146 m.4 (i)
        let Some(intent) = terminate_intent(t.instance, t.validity) else {
            return Ok(Verdict::Refused {
                code: String::from("protocol"),
                errors: Vec::new(),
            });
        };
        let request = Request {
            domain: t.domain,
            mode: Mode::Commit,
            nonce: t.nonce,
            intent,
            payload: Some(terminate_payload(t.instance)),
            basis: t.basis,
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        };
        self.commit(request, t.ais, (t.pep, None)).await
    }
}

impl<K, B, S, C> Approvals for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn opening(
        &self,
        domain: Digest,
        intent: Digest,
    ) -> Result<Option<Opening>, Unavailable> {
        // §9.14.1 step 1, §9.14.5
        match self.domains.asked(domain, &intent).await {
            Ok(Some(a)) => Ok(Some(Opening {
                render_digest: a.render,
                render: a.render_bytes,
                tier: access_authority_core::app::approval::tier_code(a.tier),
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(Unavailable(e.to_string())),
        }
    }

    async fn contribute(&self, c: Contribution) -> Result<Verdict, Unavailable> {
        // §9.14.1 step 4
        let Some(intent) = contribute_intent(c.target, &c.class, c.validity) else {
            return Ok(Verdict::Refused {
                code: String::from("protocol"),
                errors: Vec::new(),
            });
        };
        let request = Request {
            domain: c.domain,
            mode: Mode::Commit,
            nonce: c.nonce,
            intent,
            payload: Some(contribute_payload(c.target, &c.class)),
            basis: c.basis,
            capacity: c.capacity,
            proofs: vec![
                access_authority_core::domain::ProofRef::Aas(c.aas),
                access_authority_core::domain::ProofRef::ClaimRef(c.claim),
            ],
            exercise: None,
            consistency: None,
        };
        self.commit(request, c.ais, (c.pep, None)).await
    }
}

impl<K, B, S, C> Governance for Plane<K, B, S, C>
where
    K: Keys + Send + Sync,
    B: Binding + Send + Sync,
    S: Salts + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    async fn open(&self, order: GenesisOrder) -> Result<GenesisOpened, Unavailable> {
        let fields =
            genesis::realm(&order, &mut OsSalts).map_err(|e| Unavailable(e.to_string()))?;
        // OP-129 m.1
        let now = self
            .clock
            .clone()
            .now()
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        // OP-149 m.22 (g)
        let domain = self
            .domains
            .create(order.tenant, fields, now)
            .await
            .map_err(|e| Unavailable(e.to_string()))?;
        Ok(GenesisOpened { domain })
    }
}

/// A realm's keys outside the database (OP-146 m.16 (m), m.15 (e), m.7 (b)): its JOSE key set
/// in the identity signer, and in the HSM its KEK, its WebAuthn decoy key and its DPoP nonce
/// keys for both roles. A key that exists is kept.
pub(crate) struct RealmKeyring {
    signer: SignerKeys,
    keys: Arc<KeyStore>,
}

impl RealmKeyring {
    pub(crate) const fn new(signer: SignerKeys, keys: Arc<KeyStore>) -> Self {
        Self { signer, keys }
    }

    /// Whether the identity signer answers (OP-148).
    pub(crate) async fn ping(&self) -> bool {
        access_identity_oauth::ports::Keys::ping(&self.signer)
            .await
            .is_ok()
    }

    fn hsm(&self, realm: &[u8; 16]) -> Result<(), HsmError> {
        let kek = kek_label(realm);
        if self.keys.kek(&kek).is_err() {
            self.keys.generate_kek(&kek)?;
        }
        // CR-37, OP-150 m.3 (f)
        let pepper = pepper_label(realm);
        if self.keys.aead(&pepper).is_err() {
            self.keys.generate_aead(&pepper)?;
        }
        let mut macs = vec![decoy_label(realm)];
        for role in [NonceRole::AuthorizationServer, NonceRole::ResourceServer] {
            macs.push(nonce_label(realm, role, NONCE_GENERATION));
        }
        for label in macs {
            if self.keys.mac(&label).is_err() {
                self.keys.generate_mac(&label)?;
            }
        }
        Ok(())
    }
}

impl RealmKeys for RealmKeyring {
    async fn open(&self, realm: RealmId, alg: JoseAlg) -> Result<(), Unavailable> {
        let alg = match alg {
            JoseAlg::Es256 => JwsAlg::Es256,
            JoseAlg::Ed25519 => JwsAlg::Ed25519,
        };
        self.signer
            .open(realm, alg)
            .await
            .map_err(|_| Unavailable(String::from("identity-signer")))?;
        self.hsm(realm.as_bytes())
            .map_err(|e| Unavailable(String::from(e.code())))
    }

    async fn jwks(&self, realm: RealmId) -> Result<String, Unavailable> {
        access_identity_oauth::ports::Keys::jwks(&self.signer, realm)
            .await
            .map_err(|_| Unavailable(String::from("identity-signer")))
    }

    async fn rotate(&self, realm: RealmId, retire: [u8; 32]) -> Result<(), Unavailable> {
        self.signer
            .rotate(realm, retire)
            .await
            .map_err(|_| Unavailable(String::from("identity-signer")))
    }

    async fn drop_key(&self, realm: RealmId, kid: [u8; 32]) -> Result<(), Unavailable> {
        self.signer
            .drop_key(realm, kid)
            .await
            .map_err(|_| Unavailable(String::from("identity-signer")))
    }

    async fn set_policy(
        &self,
        realm: RealmId,
        policy: suiss_crypto::rotation::Policy,
    ) -> Result<(), Unavailable> {
        self.signer
            .set_policy(realm, policy)
            .await
            .map_err(|_| Unavailable(String::from("identity-signer")))
    }

    async fn open_issuer(&self, realm: RealmId, party: [u8; 16]) -> Result<PublicKey, Unavailable> {
        self.signer
            .open_issuer(realm, party)
            .await
            .map(PublicKey::Ed25519)
            .map_err(|_| Unavailable(String::from("identity-signer")))
    }

    async fn sign_issuer_registration(
        &self,
        realm: RealmId,
        registration: access_identity_admin::ports::IssuerAis,
    ) -> Result<Vec<u8>, Unavailable> {
        self.signer
            .sign_issuer_registration(realm, registration)
            .await
            .map_err(|_| Unavailable(String::from("identity-signer")))
    }
}

mod projections;

#[cfg(test)]
mod tests;
