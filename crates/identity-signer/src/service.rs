//! The identity signer service: one key set per environment, the schedule for all of them, and the
//! requests of the protocol (CMP-22b, OP-143 m.9 (e)).

use std::collections::BTreeMap;

use access_crypto::jose::JwsAlg;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::rotation::{Key, Policy, State, Step};

use crate::SignerError;
use crate::app::{Keyring, Round, Saved};
use crate::cell::{CellError, CellKey};
use crate::issuer::{IssuerError, IssuerKey};
use crate::ports::{KeyFactory, Vault, VaultError};
use crate::protocol::{Environment, Request, Response, alg_of, policy_of, policy_value};

/// How far a requested signing time may be from the signer's clock (PD).
pub const MAX_SKEW_MS: u64 = 60_000;

/// The audit event of a key the schedule made the signing key: rotation inside the policy is
/// operational and writes no Exercise (§10.1.7, OP-157 m.3 (x)).
pub const AUDIT_EVENT_ROTATED: &str = "signer.rotated";

/// What one schedule round did across the environments (CR-23, CR-27).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Environments whose round failed or hit a key-generation outage.
    pub troubled: Vec<Environment>,
    /// Each applied step; each is an environment audit event (CR-27).
    pub transitions: Vec<(Environment, Step)>,
    /// Environments whose active key is past its rotation time after the round, and by how many
    /// milliseconds: the rotation delay alarm (CR-23).
    pub delayed: Vec<(Environment, u64)>,
}

impl Report {
    /// Each key the round made an environment's signing key: one [`AUDIT_EVENT_ROTATED`] event each.
    pub fn rotated(&self) -> impl Iterator<Item = (&Environment, &[u8; 32])> {
        self.transitions.iter().filter_map(|(d, step)| match step {
            Step::Activate(kid) => Some((d, kid)),
            _ => None,
        })
    }
}

/// The identity signer of one process.
pub struct Service<F, V> {
    rings: BTreeMap<Environment, (JwsAlg, Keyring)>,
    factory: F,
    vault: V,
    policy: Policy,
    cell: Option<CellKey>,
    issuers: BTreeMap<Environment, IssuerKey>,
    rsa_ids: BTreeMap<Environment, access_crypto::rsa_id::RsaIdKey>,
    federation: BTreeMap<Environment, Keyring>,
    saml: BTreeMap<Environment, crate::saml::Ring>,
    acme: Option<crate::acme::AcmeKey>,
    ssh: BTreeMap<Environment, crate::ssh::Ring>,
    pq: BTreeMap<Environment, Keyring>,
}

/// The JWS types only an environment's `federation` key signs, and the environment JOSE key never does
/// (OP-155 m.3 (j), MD-6).
pub const FEDERATION_TYPES: [&str; 4] = [
    "entity-statement+jwt",
    "trust-mark+jwt",
    "resolve-response+jwt",
    "trust-mark-status-response+jwt",
];

/// The purpose word of a `federation` key set's vault entry.
const FEDERATION: &str = "federation";

/// The purpose word of a post-quantum key set's vault entry (OP-159 m.3 (o)).
const PQ: &str = "environment-pq";

/// The vault slot of `environment`'s `federation` key set, apart from its JOSE key set.
fn federation_slot(environment: Environment) -> Environment {
    let d = suiss_crypto::digest::context_digest(
        "access/identity-signer/federation/v1",
        &environment.0,
    );
    let mut out = [0; 16];
    out.copy_from_slice(&d.0[..16]);
    Environment(out)
}

const STATES: [(&str, State); 5] = [
    ("pending", State::Pending),
    ("published", State::Published),
    ("active", State::Active),
    ("retiring", State::Retiring),
    ("dropped", State::Dropped),
];

fn map(entries: Vec<(&str, Option<Value>)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (Value::text(k), v)))
            .collect(),
    )
}

fn uint(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Unsigned(n)) => Some(*n),
        _ => None,
    }
}

fn bytes(v: Option<&Value>) -> Option<Vec<u8>> {
    match v {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    }
}

fn key_bytes(key: &PublicKey) -> Vec<u8> {
    match key {
        PublicKey::Ed25519(k) => k.to_vec(),
        PublicKey::P256(k) | PublicKey::MlDsa(_, k) => k.clone(),
    }
}

fn key_of(alg: JwsAlg, b: Vec<u8>) -> Option<PublicKey> {
    match alg {
        JwsAlg::Ed25519 => b.try_into().ok().map(PublicKey::Ed25519),
        JwsAlg::Es256 => Some(PublicKey::P256(b)),
        JwsAlg::MlDsa44 | JwsAlg::MlDsa65 | JwsAlg::MlDsa87 => {
            Some(PublicKey::MlDsa(alg.algorithm(), b))
        }
    }
}

fn saved_value(s: &Saved) -> Value {
    let r = &s.record;
    map(vec![
        ("kid", Some(Value::Bytes(r.kid.to_vec()))),
        (
            "state",
            STATES
                .iter()
                .find(|(_, x)| *x == r.state)
                .map(|(n, _)| Value::text(n)),
        ),
        ("published_at", r.published_at.map(Value::Unsigned)),
        ("valid_from", Some(Value::Unsigned(r.valid_from))),
        ("valid_until", Some(Value::Unsigned(r.valid_until))),
        ("activated_at", r.activated_at.map(Value::Unsigned)),
        ("jitter", Some(Value::int(i64::from(r.jitter_permille)))),
        ("signatures", Some(Value::Unsigned(r.signatures))),
        ("founding", Some(Value::Bool(r.founding))),
        ("alg", Some(Value::text(s.alg.name()))),
        ("key", Some(Value::Bytes(key_bytes(&s.key)))),
        ("sealed", s.sealed.clone().map(Value::Bytes)),
    ])
}

fn saved_of(v: &Value) -> Option<Saved> {
    let state = match v.get("state") {
        Some(Value::Text(t)) => STATES.iter().find(|(n, _)| n == t).map(|(_, s)| *s)?,
        _ => return None,
    };
    let alg = match v.get("alg") {
        Some(Value::Text(t)) => alg_of(t).or_else(|| JwsAlg::ml_dsa(t))?,
        _ => return None,
    };
    Some(Saved {
        record: Key {
            kid: bytes(v.get("kid"))?.try_into().ok()?,
            state,
            published_at: uint(v.get("published_at")),
            valid_from: uint(v.get("valid_from"))?,
            valid_until: uint(v.get("valid_until"))?,
            activated_at: uint(v.get("activated_at")),
            jitter_permille: i32::try_from(v.get("jitter")?.as_i64()?).ok()?,
            signatures: uint(v.get("signatures"))?,
            founding: matches!(v.get("founding"), Some(Value::Bool(true))),
        },
        alg,
        key: key_of(alg, bytes(v.get("key"))?)?,
        sealed: bytes(v.get("sealed")),
    })
}

/// An environment's vault entry: its identifier, the algorithm of its new keys, its rotation policy
/// and its keys.
fn stored(
    environment: Environment,
    alg: JwsAlg,
    policy: &Policy,
    saved: &[Saved],
) -> Option<Vec<u8>> {
    stored_as(None, environment, alg, policy, saved)
}

fn stored_as(
    purpose: Option<&str>,
    environment: Environment,
    alg: JwsAlg,
    policy: &Policy,
    saved: &[Saved],
) -> Option<Vec<u8>> {
    let v = map(vec![
        ("environment", Some(Value::Bytes(environment.0.to_vec()))),
        ("purpose", purpose.map(Value::text)),
        ("alg", Some(Value::text(alg.name()))),
        ("policy", Some(policy_value(policy))),
        (
            "keys",
            Some(Value::Array(saved.iter().map(saved_value).collect())),
        ),
    ]);
    dcbor::encode(&v, Limits::CEILING).ok()
}

/// Which key set of an environment a vault entry holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Jose,
    Federation,
    Pq,
}

type Restored = (Environment, JwsAlg, Option<Policy>, Vec<Saved>, Slot);

fn restored(b: &[u8]) -> Option<Restored> {
    let v = dcbor::decode(b, Limits::CEILING).ok()?;
    let slot = match v.get("purpose") {
        None => Slot::Jose,
        Some(Value::Text(t)) if t == FEDERATION => Slot::Federation,
        Some(Value::Text(t)) if t == PQ => Slot::Pq,
        Some(_) => return None,
    };
    let environment = Environment(bytes(v.get("environment"))?.try_into().ok()?);
    let alg = match (v.get("alg"), slot) {
        (Some(Value::Text(t)), Slot::Pq) => JwsAlg::ml_dsa(t)?,
        (Some(Value::Text(t)), _) => alg_of(t)?,
        _ => return None,
    };
    let Some(Value::Array(keys)) = v.get("keys") else {
        return None;
    };
    let policy = v.get("policy").and_then(|p| policy_of(p).ok());
    Some((
        environment,
        alg,
        policy,
        keys.iter().filter_map(saved_of).collect(),
        slot,
    ))
}

impl<F: KeyFactory, V: Vault> Service<F, V> {
    /// A service that restores every environment the vault holds (CR-23).
    ///
    /// # Errors
    /// The vault cannot be read, or an environment's open post-quantum key set cannot be loaded back:
    /// with the profile open and no key, the signer does not start (OP-159 m.3 (d)). Any other
    /// environment that cannot be restored is left closed.
    pub fn start(factory: F, mut vault: V, policy: Policy) -> Result<Self, VaultError> {
        let all = vault.all()?;
        let mut s = Self {
            rings: BTreeMap::new(),
            factory,
            vault,
            policy,
            cell: None,
            issuers: BTreeMap::new(),
            rsa_ids: BTreeMap::new(),
            federation: BTreeMap::new(),
            saml: BTreeMap::new(),
            acme: None,
            ssh: BTreeMap::new(),
            pq: BTreeMap::new(),
        };
        for (environment, alg, policy, saved, slot) in all.iter().filter_map(|b| restored(b)) {
            let policy = policy.unwrap_or(s.policy);
            let ring = Keyring::restore(alg, policy, saved, &mut s.factory);
            match (slot, ring) {
                (Slot::Federation, Ok(ring)) => {
                    s.federation.insert(environment, ring);
                }
                (Slot::Jose, Ok(ring)) => {
                    s.rings.insert(environment, (alg, ring));
                }
                // OP-159 m.3 (d)
                (Slot::Pq, Ok(ring))
                    if ring.live() && (ring.unloaded() || !s.factory.pq_ready(alg)) =>
                {
                    return Err(VaultError);
                }
                (Slot::Pq, Ok(ring)) if ring.live() => {
                    s.pq.insert(environment, ring);
                }
                (Slot::Pq, Err(_)) => return Err(VaultError),
                _ => {}
            }
        }
        Ok(s)
    }

    /// Opens the `audit-checkpoint` key of `cell`: the stored one, or a new one stored before
    /// it is used (OP-150 m.3 (h)). A vault holding another cell's key is refused.
    ///
    /// # Errors
    /// [`CellError`]; [`CellError::Stored`] also when the vault cannot be read or written.
    pub fn open_cell(&mut self, cell: &str) -> Result<(), CellError> {
        if let Some(stored) = self.vault.cell().map_err(|_| CellError::Stored)? {
            self.cell = Some(CellKey::restore(cell, &stored, &mut self.factory)?);
            return Ok(());
        }
        let key = CellKey::generate(cell, &mut self.factory)?;
        let stored = key.stored().ok_or(CellError::Stored)?;
        self.vault
            .put_cell(&stored)
            .map_err(|_| CellError::Stored)?;
        self.cell = Some(key);
        Ok(())
    }

    /// The environments whose key sets are open.
    #[must_use]
    pub fn environments(&self) -> Vec<Environment> {
        self.rings.keys().copied().collect()
    }

    fn persist(&mut self, environment: Environment) -> bool {
        let Some((alg, ring)) = self.rings.get(&environment) else {
            return false;
        };
        stored(environment, *alg, &ring.policy(), &ring.saved())
            .is_some_and(|b| self.vault.put(&environment, &b).is_ok())
    }

    fn tick_one(&mut self, environment: Environment, now: u64, draw: u64) -> bool {
        let mut report = Report::default();
        self.round_one(environment, now, draw, &mut report);
        report.troubled.is_empty()
    }

    fn round_one(&mut self, environment: Environment, now: u64, draw: u64, report: &mut Report) {
        let round = self
            .rings
            .get_mut(&environment)
            .map(|(_, ring)| ring.tick(&mut self.factory, now, draw));
        let ok = round.as_ref().is_some_and(|r| !r.outage);
        if !(self.persist(environment) && ok) {
            report.troubled.push(environment);
        }
        for step in round.map(|r| r.applied).unwrap_or_default() {
            report.transitions.push((environment, step));
        }
        if let Some(late) = self
            .rings
            .get(&environment)
            .and_then(|(_, r)| r.overdue(now))
        {
            report.delayed.push((environment, late));
        }
    }

    /// Runs the schedule of every environment at `now` and keeps the vault current; returns the
    /// environments whose round failed or hit a key-generation outage (CR-23).
    pub fn tick(&mut self, now: u64, draw: u64) -> Vec<Environment> {
        self.round(now, draw).troubled
    }

    /// [`Self::tick`], reporting every applied step and every delayed rotation (CR-23, CR-27).
    pub fn round(&mut self, now: u64, draw: u64) -> Report {
        let mut report = Report::default();
        for environment in self.environments() {
            self.round_one(environment, now, draw, &mut report);
        }
        let federated: Vec<Environment> = self.federation.keys().copied().collect();
        for environment in federated {
            if !self.federation_round(environment, now, draw) {
                report.troubled.push(environment);
            }
        }
        let pq: Vec<Environment> = self.pq.keys().copied().collect();
        for environment in pq {
            if !self.pq_round(environment, now, draw, &mut report) {
                report.troubled.push(environment);
            }
        }
        report
    }

    fn persist_pq(&mut self, environment: Environment) -> bool {
        let Some(ring) = self.pq.get(&environment) else {
            return false;
        };
        stored_as(
            Some(PQ),
            environment,
            ring.alg(),
            &ring.policy(),
            &ring.saved(),
        )
        .is_some_and(|b| self.vault.put(&crate::pq::slot(environment), &b).is_ok())
    }

    fn pq_round(
        &mut self,
        environment: Environment,
        now: u64,
        draw: u64,
        report: &mut Report,
    ) -> bool {
        let round = self
            .pq
            .get_mut(&environment)
            .map(|ring| ring.tick(&mut self.factory, now, draw));
        let ok = round.as_ref().is_some_and(|r| !r.outage);
        for step in round.map(|r| r.applied).unwrap_or_default() {
            report.transitions.push((environment, step));
        }
        self.persist_pq(environment) && ok
    }

    /// Answers a request about an environment's post-quantum key set (CR-41, OP-159 m.3 (o), (d)).
    fn handle_pq(&mut self, request: crate::pq::PqRequest, now: u64, draw: u64) -> Response {
        use crate::pq::{NO_PQ, PQ_KEY_UNAVAILABLE, PqRequest};
        match request {
            PqRequest::Ready { alg } => {
                if alg.post_quantum() && self.factory.pq_ready(alg) {
                    Response::Opened
                } else {
                    Response::Error(String::from(PQ_KEY_UNAVAILABLE))
                }
            }
            PqRequest::Open { environment, alg } => {
                if self
                    .pq
                    .get(&environment)
                    .is_some_and(|r| r.alg() == alg && r.live())
                {
                    return Response::Opened;
                }
                // OP-159 m.3 (d)
                if !alg.post_quantum() || !self.factory.pq_ready(alg) {
                    return Response::Error(String::from(PQ_KEY_UNAVAILABLE));
                }
                if let Some(old) = self.pq.get_mut(&environment) {
                    old.close(now);
                    if !self.persist_pq(environment) {
                        return Response::Error(String::from("signer-outage"));
                    }
                }
                let policy = self
                    .rings
                    .get(&environment)
                    .map_or(self.policy, |(_, r)| r.policy());
                let Ok(ring) = Keyring::new(alg, policy) else {
                    return Response::Error(String::from("signer-policy"));
                };
                self.pq.insert(environment, ring);
                let mut report = Report::default();
                if !self.pq_round(environment, now, draw, &mut report) {
                    self.pq.remove(&environment);
                    return Response::Error(String::from(PQ_KEY_UNAVAILABLE));
                }
                Response::Opened
            }
            PqRequest::Close { environment } => {
                let Some(ring) = self.pq.get_mut(&environment) else {
                    return Response::Opened;
                };
                ring.close(now);
                if !self.persist_pq(environment) {
                    return Response::Error(String::from("signer-outage"));
                }
                self.pq.remove(&environment);
                Response::Opened
            }
            PqRequest::Sign {
                environment,
                typ,
                payload,
                at,
            } => {
                if at.abs_diff(now) > MAX_SKEW_MS {
                    return Response::Error(String::from("signer-time"));
                }
                if FEDERATION_TYPES.contains(&typ.as_str()) {
                    return Response::Error(String::from(crate::SignerError::Payload.code()));
                }
                let Some(ring) = self.pq.get_mut(&environment) else {
                    return Response::Error(String::from(NO_PQ));
                };
                let signed = ring.sign(&typ, &payload, at);
                let kept = self.persist_pq(environment);
                match signed {
                    Ok(s) if kept => Response::Signed {
                        token: s.token,
                        kid: s.kid,
                    },
                    Ok(_) => Response::Error(String::from("signer-outage")),
                    Err(e) => Response::Error(String::from(e.code())),
                }
            }
        }
    }

    fn persist_federation(&mut self, environment: Environment) -> bool {
        let Some(ring) = self.federation.get(&environment) else {
            return false;
        };
        stored_as(
            Some(FEDERATION),
            environment,
            JwsAlg::Es256,
            &ring.policy(),
            &ring.saved(),
        )
        .is_some_and(|b| self.vault.put(&federation_slot(environment), &b).is_ok())
    }

    fn federation_round(&mut self, environment: Environment, now: u64, draw: u64) -> bool {
        let ok = self
            .federation
            .get_mut(&environment)
            .map(|ring| ring.tick(&mut self.factory, now, draw))
            .is_some_and(|r| !r.outage);
        self.persist_federation(environment) && ok
    }

    /// Answers the `federation` key's requests (OP-155 m.3 (j)): its key set is made on the first
    /// request, P-256 only, and it signs only federation types.
    fn handle_federation(&mut self, request: Request, now: u64, draw: u64) -> Response {
        let environment = match &request {
            Request::FederationJwks(r) | Request::SignFederation { environment: r, .. } => *r,
            _ => return Response::Error(String::from("signer-frame")),
        };
        if !self.federation.contains_key(&environment) {
            let Ok(ring) = Keyring::new(JwsAlg::Es256, self.policy) else {
                return Response::Error(String::from("signer-policy"));
            };
            self.federation.insert(environment, ring);
            if !self.federation_round(environment, now, draw) {
                self.federation.remove(&environment);
                return Response::Error(String::from("signer-outage"));
            }
        }
        let Some(ring) = self.federation.get_mut(&environment) else {
            return Response::Error(String::from(UNKNOWN_ENVIRONMENT));
        };
        match request {
            Request::SignFederation {
                typ, payload, at, ..
            } => {
                if at.abs_diff(now) > MAX_SKEW_MS {
                    return Response::Error(String::from("signer-time"));
                }
                if !FEDERATION_TYPES.contains(&typ.as_str()) {
                    return Response::Error(String::from(crate::SignerError::Payload.code()));
                }
                match ring.sign(&typ, &payload, at) {
                    Ok(s) => Response::Signed {
                        token: s.token,
                        kid: s.kid,
                    },
                    Err(e) => Response::Error(String::from(e.code())),
                }
            }
            _ => Response::Jwks(ring.jwks().to_owned()),
        }
    }

    /// Changes `environment`'s key set outside the schedule and keeps the vault current (TN-118,
    /// §13.2); a change the vault cannot keep is an outage.
    fn rekey(
        &mut self,
        environment: Environment,
        change: impl FnOnce(&mut Keyring, &mut dyn KeyFactory) -> Result<Round, SignerError>,
    ) -> Response {
        let Some((_, ring)) = self.rings.get_mut(&environment) else {
            return Response::Error(String::from(UNKNOWN_ENVIRONMENT));
        };
        if let Err(e) = change(ring, &mut self.factory) {
            return Response::Error(String::from(e.code()));
        }
        let jwks = ring.jwks().to_owned();
        if !self.persist(environment) {
            return Response::Error(String::from("signer-outage"));
        }
        Response::Rekeyed(jwks)
    }

    /// Answers one request at `now`; `draw` is a random value for a new key's jitter.
    #[expect(clippy::too_many_lines, reason = "one arm per request of the protocol")]
    pub fn handle(&mut self, request: Request, now: u64, draw: u64) -> Response {
        match request {
            Request::Ping => Response::Pong,
            Request::Open { environment, alg } => {
                if let Some((current, ring)) = self.rings.get_mut(&environment)
                    && *current != alg
                {
                    *current = alg;
                    ring.set_alg(alg);
                    if !self.persist(environment) {
                        return Response::Error(String::from("signer-outage"));
                    }
                }
                if !self.rings.contains_key(&environment) {
                    let Ok(ring) = Keyring::new(alg, self.policy) else {
                        return Response::Error(String::from("signer-policy"));
                    };
                    self.rings.insert(environment, (alg, ring));
                    if !self.tick_one(environment, now, draw) {
                        return Response::Error(String::from("signer-outage"));
                    }
                }
                Response::Opened
            }
            Request::Jwks(environment) => self.jwks(environment),
            // MD-6, CR-2, OP-155 m.3 (k)
            Request::SignRs256 {
                environment,
                typ,
                payload,
                at,
            } => self.sign_rs256(environment, &typ, &payload, at, now),
            Request::Sign {
                environment,
                typ,
                payload,
                at,
            } => {
                if at.abs_diff(now) > MAX_SKEW_MS {
                    return Response::Error(String::from("signer-time"));
                }
                // OP-155 m.3 (j), MD-6
                if FEDERATION_TYPES.contains(&typ.as_str()) {
                    return Response::Error(String::from(crate::SignerError::Payload.code()));
                }
                let Some((_, ring)) = self.rings.get_mut(&environment) else {
                    return Response::Error(String::from(UNKNOWN_ENVIRONMENT));
                };
                match ring.sign(&typ, &payload, at) {
                    Ok(s) => Response::Signed {
                        token: s.token,
                        kid: s.kid,
                    },
                    Err(e) => Response::Error(String::from(e.code())),
                }
            }
            Request::SignCose {
                environment,
                content_type,
                payload,
                at,
            } => {
                if at.abs_diff(now) > MAX_SKEW_MS {
                    return Response::Error(String::from("signer-time"));
                }
                if PROTOCOL_TYPES.contains(&content_type.as_str()) {
                    return Response::Error(String::from(crate::SignerError::Payload.code()));
                }
                let Some((_, ring)) = self.rings.get_mut(&environment) else {
                    return Response::Error(String::from(UNKNOWN_ENVIRONMENT));
                };
                match ring.sign_cose(&content_type, &payload, at) {
                    Ok((sign1, kid)) => Response::SignedCose { sign1, kid },
                    Err(e) => Response::Error(String::from(e.code())),
                }
            }
            Request::Rotate {
                environment,
                retire,
            } => self.rekey(environment, |ring, f| ring.rotate(f, &retire, now, draw)),
            Request::DropKey { environment, kid } => {
                self.rekey(environment, |ring, f| ring.drop_key(f, &kid, now, draw))
            }
            Request::SetPolicy {
                environment,
                policy,
            } => self.rekey(environment, |ring, _| {
                ring.set_policy(policy)?;
                Ok(Round::default())
            }),
            Request::CellKey => self.cell.as_ref().map_or_else(
                || Response::Error(String::from(NO_CELL)),
                |c| Response::CellKey {
                    origin: c.origin().to_owned(),
                    vkey: c.vkey(),
                },
            ),
            Request::SignCheckpoint { body } => match self.cell.as_ref() {
                None => Response::Error(String::from(NO_CELL)),
                Some(c) => match c.sign(&body) {
                    Ok(line) => Response::Noted { line },
                    Err(e) => Response::Error(String::from(e.code())),
                },
            },
            r @ (Request::FederationJwks(_) | Request::SignFederation { .. }) => {
                self.handle_federation(r, now, draw)
            }
            Request::Saml(r) => self.handle_saml(&r, now),
            Request::Acme(r) => self.handle_acme(&r),
            Request::Ssh(r) => self.handle_ssh(&r, now),
            Request::Pq(r) => self.handle_pq(r, now, draw),
            other => self.handle_issuer(&other, now),
        }
    }

    /// Answers the cell ACME account key's requests (OP-156 m.3 (i)): the key is made on the
    /// first request and stored before it is used.
    fn handle_acme(&mut self, request: &crate::acme::AcmeRequest) -> Response {
        use crate::acme::{AcmeKey, AcmeKeyError, slot};
        if self.acme.is_none() {
            let key = match self.vault.issuer(&slot()) {
                Ok(Some(stored)) => AcmeKey::restore(&stored, &mut self.factory),
                Ok(None) => AcmeKey::generate(&mut self.factory).and_then(|k| {
                    let stored = k.stored().ok_or(AcmeKeyError::Stored)?;
                    self.vault
                        .put_issuer(&slot(), &stored)
                        .map_err(|_| AcmeKeyError::Stored)?;
                    Ok(k)
                }),
                Err(_) => Err(AcmeKeyError::Stored),
            };
            match key {
                Ok(k) => self.acme = Some(k),
                Err(e) => return Response::Error(String::from(e.code())),
            }
        }
        match self.acme.as_ref().map(|k| k.answer(request)) {
            Some(Ok(a)) => Response::Acme(a),
            Some(Err(e)) => Response::Error(String::from(e.code())),
            None => Response::Error(String::from(AcmeKeyError::Stored.code())),
        }
    }

    /// Answers the Claim issuer key's requests (§10.1.7).
    fn handle_issuer(&mut self, request: &Request, now: u64) -> Response {
        let (environment, at) = match request {
            Request::OpenIssuer { environment, party } => {
                return match self.open_issuer(*environment, *party) {
                    Ok(k) => Response::Issuer {
                        party: k.party(),
                        key: k.key(),
                        kid: k.kid(),
                    },
                    Err(e) => Response::Error(String::from(e.code())),
                };
            }
            Request::SignClaim {
                environment, at, ..
            } => (*environment, *at),
            Request::SignIssuerRegistration {
                environment,
                registration,
            } => (*environment, registration.iat),
            _ => return Response::Error(String::from("signer-frame")),
        };
        if at.abs_diff(now) > MAX_SKEW_MS {
            return Response::Error(String::from("signer-time"));
        }
        let Some(k) = self.issuer(environment) else {
            return Response::Error(String::from(NO_ISSUER));
        };
        let signed = match request {
            Request::SignClaim { payload, .. } => k.sign_claim(payload, at),
            Request::SignIssuerRegistration { registration, .. } => {
                k.sign_registration(registration)
            }
            _ => return Response::Error(String::from("signer-frame")),
        };
        match signed {
            Ok(sign1) => Response::SignedCose {
                sign1,
                kid: k.kid(),
            },
            Err(e) => Response::Error(String::from(e.code())),
        }
    }

    /// The Claim issuer key of `environment`: the open one, the stored one, or a new one stored before
    /// it is used, bound to `party` (§10.1.7). A key bound to another Party is refused.
    ///
    /// # Errors
    /// [`IssuerError`]; [`IssuerError::Stored`] also when the vault cannot be read or written.
    pub fn open_issuer(
        &mut self,
        environment: Environment,
        party: [u8; 16],
    ) -> Result<&IssuerKey, IssuerError> {
        if self.issuer(environment).is_none() {
            let key = IssuerKey::generate(environment.0, party, &mut self.factory)?;
            let stored = key.stored().ok_or(IssuerError::Stored)?;
            self.vault
                .put_issuer(&environment, &stored)
                .map_err(|_| IssuerError::Stored)?;
            self.issuers.insert(environment, key);
        }
        match self.issuers.get(&environment) {
            Some(k) if k.party() == party => Ok(k),
            Some(_) => Err(IssuerError::OtherIssuer),
            None => Err(IssuerError::Stored),
        }
    }

    /// The environment's JWKS, its `rsa-id` key after the JOSE keys when it has one.
    fn jwks(&mut self, environment: Environment) -> Response {
        let rsa = self
            .rsa_id(environment)
            .map(access_crypto::rsa_id::RsaIdKey::public_jwk);
        let pq = self.pq.get(&environment).map(|r| r.jwks().to_owned());
        self.rings.get(&environment).map_or_else(
            || Response::Error(String::from(UNKNOWN_ENVIRONMENT)),
            |(_, ring)| {
                // OP-159 m.3 (o)
                let jose = pq.as_deref().map_or_else(
                    || String::from(ring.jwks()),
                    |pq| crate::pq::merged(ring.jwks(), pq),
                );
                Response::Jwks(with_rsa(&jose, rsa.as_deref()))
            },
        )
    }

    /// Signs `payload` as an RS256 JWS of `typ` with the environment's `rsa-id` key (MD-6, CR-2).
    fn sign_rs256(
        &mut self,
        environment: Environment,
        typ: &str,
        payload: &[u8],
        at: u64,
        now: u64,
    ) -> Response {
        if at.abs_diff(now) > MAX_SKEW_MS {
            return Response::Error(String::from("signer-time"));
        }
        if !self.rings.contains_key(&environment) {
            return Response::Error(String::from(UNKNOWN_ENVIRONMENT));
        }
        let Some(key) = self.open_rsa_id(environment) else {
            return Response::Error(String::from("signer-outage"));
        };
        match key.sign_compact(typ, payload) {
            Ok(token) => Response::Signed {
                token,
                kid: *key.kid(),
            },
            Err(e) => Response::Error(String::from(e.code())),
        }
    }

    /// The environment's `rsa-id` key when one was made, loaded from the vault after a restart.
    fn rsa_id(&mut self, environment: Environment) -> Option<&access_crypto::rsa_id::RsaIdKey> {
        if !self.rsa_ids.contains_key(&environment) {
            let stored = self.vault.rsa_id(&environment).ok().flatten()?;
            let key = self.factory.load_rsa_id(&stored).ok()?;
            self.rsa_ids.insert(environment, key);
        }
        self.rsa_ids.get(&environment)
    }

    /// The environment's `rsa-id` key, made and stored before its first use (MD-6).
    fn open_rsa_id(
        &mut self,
        environment: Environment,
    ) -> Option<&access_crypto::rsa_id::RsaIdKey> {
        if self.rsa_id(environment).is_none() {
            let (key, sealed) = self.factory.generate_rsa_id().ok()?;
            self.vault.put_rsa_id(&environment, &sealed).ok()?;
            self.rsa_ids.insert(environment, key);
        }
        self.rsa_ids.get(&environment)
    }

    /// The environment's open Claim issuer key, loaded from the vault after a restart.
    fn issuer(&mut self, environment: Environment) -> Option<&IssuerKey> {
        if !self.issuers.contains_key(&environment) {
            let stored = self.vault.issuer(&environment).ok().flatten()?;
            let key = IssuerKey::restore(environment.0, &stored, &mut self.factory).ok()?;
            self.issuers.insert(environment, key);
        }
        self.issuers.get(&environment)
    }
}

/// The environment's JWKS with its `rsa-id` key appended after the JOSE keys, when it has one
/// (OP-155 m.3 (k)).
fn with_rsa(jwks: &str, rsa: Option<&str>) -> String {
    let Some(rsa) = rsa else {
        return String::from(jwks);
    };
    match jwks.strip_suffix("]}") {
        Some(head) if head.ends_with('[') => format!("{head}{rsa}]}}"),
        Some(head) => format!("{head},{rsa}]}}"),
        None => String::from(jwks),
    }
}

impl<F: KeyFactory, V: Vault> Service<F, V> {
    /// Answers a SAML key request (OP-155 m.3 (d)); a change the vault cannot keep is an
    /// outage and is not answered as done.
    fn handle_saml(&mut self, request: &crate::saml::SamlRequest, now: u64) -> Response {
        use crate::saml::{Ring, SamlKeyError, SamlRequest, SamlResponse};
        let environment = request.environment();
        if !self.saml.contains_key(&environment) {
            let ring = match self.vault.saml(&environment) {
                Ok(Some(stored)) => match Ring::restore(environment, &stored, &mut self.factory) {
                    Ok(r) => r,
                    Err(e) => return Response::Error(String::from(e.code())),
                },
                Ok(None) => Ring::new(environment),
                Err(_) => return Response::Error(String::from(SamlKeyError::Stored.code())),
            };
            self.saml.insert(environment, ring);
        }
        let Some(ring) = self.saml.get_mut(&environment) else {
            return Response::Error(String::from(SamlKeyError::Stored.code()));
        };
        let changed = match request {
            SamlRequest::Keys(_) => Ok(false),
            SamlRequest::Open { alg, .. } => ring.open(*alg, now, &mut self.factory),
            SamlRequest::Rotate { alg, step, .. } => ring
                .rotate(*alg, *step, now, &mut self.factory)
                .map(|()| true),
            SamlRequest::Sign { sig, data, .. } => {
                return match ring.sign(*sig, data) {
                    Ok((signature, info)) => Response::Saml(SamlResponse::Signed {
                        signature,
                        cert: info.cert.clone(),
                        kid: info.kid,
                    }),
                    Err(e) => Response::Error(String::from(e.code())),
                };
            }
        };
        match changed {
            Ok(true) => {
                let kept = ring
                    .stored()
                    .is_some_and(|b| self.vault.put_saml(&environment, &b).is_ok());
                if !kept {
                    self.saml.remove(&environment);
                    return Response::Error(String::from(SamlKeyError::Stored.code()));
                }
            }
            Ok(false) => {}
            Err(e) => return Response::Error(String::from(e.code())),
        }
        let keys = self
            .saml
            .get(&environment)
            .map(Ring::keys)
            .unwrap_or_default();
        Response::Saml(SamlResponse::Keys(keys))
    }
}

impl<F: KeyFactory, V: Vault> Service<F, V> {
    /// Answers an SSH CA key request (OP-156 m.3 (o)); a change the vault cannot keep is an
    /// outage and is not answered as done.
    fn handle_ssh(&mut self, request: &crate::ssh::SshRequest, now: u64) -> Response {
        use crate::ssh::{Ring, SshKeyError, SshRequest, SshResponse};
        let environment = request.environment();
        if !self.ssh.contains_key(&environment) {
            let ring = match self.vault.ssh(&environment) {
                Ok(Some(stored)) => match Ring::restore(environment, &stored, &mut self.factory) {
                    Ok(r) => r,
                    Err(e) => return Response::Error(String::from(e.code())),
                },
                Ok(None) => Ring::new(environment),
                Err(_) => return Response::Error(String::from(SshKeyError::Stored.code())),
            };
            self.ssh.insert(environment, ring);
        }
        let Some(ring) = self.ssh.get_mut(&environment) else {
            return Response::Error(String::from(SshKeyError::Stored.code()));
        };
        let changed = match request {
            SshRequest::Keys(_) => Ok(false),
            SshRequest::Open(_) => ring.open(now, &mut self.factory),
            SshRequest::Rotate { step, .. } => {
                ring.rotate(*step, now, &mut self.factory).map(|()| true)
            }
            SshRequest::Sign { key, data, .. } => {
                return match ring.sign(key, data) {
                    Ok(signature) => Response::Ssh(SshResponse::Signed(signature)),
                    Err(e) => Response::Error(String::from(e.code())),
                };
            }
        };
        match changed {
            Ok(true) => {
                let kept = ring
                    .stored()
                    .is_some_and(|b| self.vault.put_ssh(&environment, &b).is_ok());
                if !kept {
                    self.ssh.remove(&environment);
                    return Response::Error(String::from(SshKeyError::Stored.code()));
                }
            }
            Ok(false) => {}
            Err(e) => return Response::Error(String::from(e.code())),
        }
        let keys = self
            .ssh
            .get(&environment)
            .map(Ring::keys)
            .unwrap_or_default();
        Response::Ssh(SshResponse::Keys(keys))
    }
}

/// The refusal for an environment whose Claim issuer key was never opened.
pub const NO_ISSUER: &str = "signer-no-issuer";

/// The content types of Access protocol artefacts, which only their own keys sign: an environment's
/// token key never signs a Claim, an AIS, an AAS, a PAP or a receipt (§10.1.7, MD-6).
pub const PROTOCOL_TYPES: [&str; 5] = [
    access_kernel::claim::CONTENT_TYPE,
    access_kernel::ais::CONTENT_TYPE,
    access_kernel::aas::CONTENT_TYPE,
    access_kernel::pap::CONTENT_TYPE,
    access_kernel::receipt::CONTENT_TYPE,
];

/// The refusal when the cell's `audit-checkpoint` key is not open.
pub const NO_CELL: &str = "signer-no-cell";

/// The refusal for an environment whose key set is not open.
pub const UNKNOWN_ENVIRONMENT: &str = "signer-unknown-environment";

#[cfg(test)]
mod tests;
