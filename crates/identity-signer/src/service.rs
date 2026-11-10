//! The identity signer service: one key set per realm, the schedule for all of them, and the
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
use crate::protocol::{Realm, Request, Response, alg_of, policy_of, policy_value};

/// How far a requested signing time may be from the signer's clock (PD).
pub const MAX_SKEW_MS: u64 = 60_000;

/// What one schedule round did across the realms (CR-23, CR-27).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Realms whose round failed or hit a key-generation outage.
    pub troubled: Vec<Realm>,
    /// Each applied step; each is a realm audit event (CR-27).
    pub transitions: Vec<(Realm, Step)>,
    /// Realms whose active key is past its rotation time after the round, and by how many
    /// milliseconds: the rotation delay alarm (CR-23).
    pub delayed: Vec<(Realm, u64)>,
}

/// The identity signer of one process.
pub struct Service<F, V> {
    rings: BTreeMap<Realm, (JwsAlg, Keyring)>,
    factory: F,
    vault: V,
    policy: Policy,
    cell: Option<CellKey>,
    issuers: BTreeMap<Realm, IssuerKey>,
    rsa_ids: BTreeMap<Realm, access_crypto::rsa_id::RsaIdKey>,
    federation: BTreeMap<Realm, Keyring>,
    saml: BTreeMap<Realm, crate::saml::Ring>,
}

/// The JWS types only a realm's `federation` key signs, and the realm JOSE key never does
/// (OP-155 m.3 (j), MD-6).
pub const FEDERATION_TYPES: [&str; 4] = [
    "entity-statement+jwt",
    "trust-mark+jwt",
    "resolve-response+jwt",
    "trust-mark-status-response+jwt",
];

/// The purpose word of a `federation` key set's vault entry.
const FEDERATION: &str = "federation";

/// The vault slot of `realm`'s `federation` key set, apart from its JOSE key set.
fn federation_slot(realm: Realm) -> Realm {
    let d = suiss_crypto::digest::context_digest("access/identity-signer/federation/v1", &realm.0);
    let mut out = [0; 16];
    out.copy_from_slice(&d.0[..16]);
    Realm(out)
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

fn key_bytes(key: &PublicKey) -> Option<Vec<u8>> {
    match key {
        PublicKey::Ed25519(k) => Some(k.to_vec()),
        PublicKey::P256(k) => Some(k.clone()),
        PublicKey::MlDsa(..) => None,
    }
}

fn key_of(alg: JwsAlg, b: Vec<u8>) -> Option<PublicKey> {
    match alg {
        JwsAlg::Ed25519 => b.try_into().ok().map(PublicKey::Ed25519),
        JwsAlg::Es256 => Some(PublicKey::P256(b)),
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
        ("key", key_bytes(&s.key).map(Value::Bytes)),
        ("sealed", s.sealed.clone().map(Value::Bytes)),
    ])
}

fn saved_of(v: &Value) -> Option<Saved> {
    let state = match v.get("state") {
        Some(Value::Text(t)) => STATES.iter().find(|(n, _)| n == t).map(|(_, s)| *s)?,
        _ => return None,
    };
    let alg = match v.get("alg") {
        Some(Value::Text(t)) => alg_of(t)?,
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

/// A realm's vault entry: its identifier, the algorithm of its new keys, its rotation policy
/// and its keys.
fn stored(realm: Realm, alg: JwsAlg, policy: &Policy, saved: &[Saved]) -> Option<Vec<u8>> {
    stored_as(None, realm, alg, policy, saved)
}

fn stored_as(
    purpose: Option<&str>,
    realm: Realm,
    alg: JwsAlg,
    policy: &Policy,
    saved: &[Saved],
) -> Option<Vec<u8>> {
    let v = map(vec![
        ("realm", Some(Value::Bytes(realm.0.to_vec()))),
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

type Restored = (Realm, JwsAlg, Option<Policy>, Vec<Saved>, bool);

fn restored(b: &[u8]) -> Option<Restored> {
    let v = dcbor::decode(b, Limits::CEILING).ok()?;
    let federation = match v.get("purpose") {
        None => false,
        Some(Value::Text(t)) if t == FEDERATION => true,
        Some(_) => return None,
    };
    let realm = Realm(bytes(v.get("realm"))?.try_into().ok()?);
    let alg = match v.get("alg") {
        Some(Value::Text(t)) => alg_of(t)?,
        _ => return None,
    };
    let Some(Value::Array(keys)) = v.get("keys") else {
        return None;
    };
    let policy = v.get("policy").and_then(|p| policy_of(p).ok());
    Some((
        realm,
        alg,
        policy,
        keys.iter().filter_map(saved_of).collect(),
        federation,
    ))
}

impl<F: KeyFactory, V: Vault> Service<F, V> {
    /// A service that restores every realm the vault holds (CR-23).
    ///
    /// # Errors
    /// The vault cannot be read; a realm that cannot be restored is left closed.
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
        };
        for (realm, alg, policy, saved, federation) in all.iter().filter_map(|b| restored(b)) {
            let policy = policy.unwrap_or(s.policy);
            if let Ok(ring) = Keyring::restore(alg, policy, saved, &mut s.factory) {
                if federation {
                    s.federation.insert(realm, ring);
                } else {
                    s.rings.insert(realm, (alg, ring));
                }
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

    /// The realms whose key sets are open.
    #[must_use]
    pub fn realms(&self) -> Vec<Realm> {
        self.rings.keys().copied().collect()
    }

    fn persist(&mut self, realm: Realm) -> bool {
        let Some((alg, ring)) = self.rings.get(&realm) else {
            return false;
        };
        stored(realm, *alg, &ring.policy(), &ring.saved())
            .is_some_and(|b| self.vault.put(&realm, &b).is_ok())
    }

    fn tick_one(&mut self, realm: Realm, now: u64, draw: u64) -> bool {
        let mut report = Report::default();
        self.round_one(realm, now, draw, &mut report);
        report.troubled.is_empty()
    }

    fn round_one(&mut self, realm: Realm, now: u64, draw: u64, report: &mut Report) {
        let round = self
            .rings
            .get_mut(&realm)
            .map(|(_, ring)| ring.tick(&mut self.factory, now, draw));
        let ok = round.as_ref().is_some_and(|r| !r.outage);
        if !(self.persist(realm) && ok) {
            report.troubled.push(realm);
        }
        for step in round.map(|r| r.applied).unwrap_or_default() {
            report.transitions.push((realm, step));
        }
        if let Some(late) = self.rings.get(&realm).and_then(|(_, r)| r.overdue(now)) {
            report.delayed.push((realm, late));
        }
    }

    /// Runs the schedule of every realm at `now` and keeps the vault current; returns the
    /// realms whose round failed or hit a key-generation outage (CR-23).
    pub fn tick(&mut self, now: u64, draw: u64) -> Vec<Realm> {
        self.round(now, draw).troubled
    }

    /// [`Self::tick`], reporting every applied step and every delayed rotation (CR-23, CR-27).
    pub fn round(&mut self, now: u64, draw: u64) -> Report {
        let mut report = Report::default();
        for realm in self.realms() {
            self.round_one(realm, now, draw, &mut report);
        }
        let federated: Vec<Realm> = self.federation.keys().copied().collect();
        for realm in federated {
            if !self.federation_round(realm, now, draw) {
                report.troubled.push(realm);
            }
        }
        report
    }

    fn persist_federation(&mut self, realm: Realm) -> bool {
        let Some(ring) = self.federation.get(&realm) else {
            return false;
        };
        stored_as(
            Some(FEDERATION),
            realm,
            JwsAlg::Es256,
            &ring.policy(),
            &ring.saved(),
        )
        .is_some_and(|b| self.vault.put(&federation_slot(realm), &b).is_ok())
    }

    fn federation_round(&mut self, realm: Realm, now: u64, draw: u64) -> bool {
        let ok = self
            .federation
            .get_mut(&realm)
            .map(|ring| ring.tick(&mut self.factory, now, draw))
            .is_some_and(|r| !r.outage);
        self.persist_federation(realm) && ok
    }

    /// Answers the `federation` key's requests (OP-155 m.3 (j)): its key set is made on the first
    /// request, P-256 only, and it signs only federation types.
    fn handle_federation(&mut self, request: Request, now: u64, draw: u64) -> Response {
        let realm = match &request {
            Request::FederationJwks(r) | Request::SignFederation { realm: r, .. } => *r,
            _ => return Response::Error(String::from("signer-frame")),
        };
        if !self.federation.contains_key(&realm) {
            let Ok(ring) = Keyring::new(JwsAlg::Es256, self.policy) else {
                return Response::Error(String::from("signer-policy"));
            };
            self.federation.insert(realm, ring);
            if !self.federation_round(realm, now, draw) {
                self.federation.remove(&realm);
                return Response::Error(String::from("signer-outage"));
            }
        }
        let Some(ring) = self.federation.get_mut(&realm) else {
            return Response::Error(String::from(UNKNOWN_REALM));
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

    /// Changes `realm`'s key set outside the schedule and keeps the vault current (TN-118,
    /// §13.2); a change the vault cannot keep is an outage.
    fn rekey(
        &mut self,
        realm: Realm,
        change: impl FnOnce(&mut Keyring, &mut dyn KeyFactory) -> Result<Round, SignerError>,
    ) -> Response {
        let Some((_, ring)) = self.rings.get_mut(&realm) else {
            return Response::Error(String::from(UNKNOWN_REALM));
        };
        if let Err(e) = change(ring, &mut self.factory) {
            return Response::Error(String::from(e.code()));
        }
        let jwks = ring.jwks().to_owned();
        if !self.persist(realm) {
            return Response::Error(String::from("signer-outage"));
        }
        Response::Rekeyed(jwks)
    }

    /// Answers one request at `now`; `draw` is a random value for a new key's jitter.
    #[expect(clippy::too_many_lines, reason = "one arm per request of the protocol")]
    pub fn handle(&mut self, request: Request, now: u64, draw: u64) -> Response {
        match request {
            Request::Ping => Response::Pong,
            Request::Open { realm, alg } => {
                if let Some((current, ring)) = self.rings.get_mut(&realm)
                    && *current != alg
                {
                    *current = alg;
                    ring.set_alg(alg);
                    if !self.persist(realm) {
                        return Response::Error(String::from("signer-outage"));
                    }
                }
                if !self.rings.contains_key(&realm) {
                    let Ok(ring) = Keyring::new(alg, self.policy) else {
                        return Response::Error(String::from("signer-policy"));
                    };
                    self.rings.insert(realm, (alg, ring));
                    if !self.tick_one(realm, now, draw) {
                        return Response::Error(String::from("signer-outage"));
                    }
                }
                Response::Opened
            }
            Request::Jwks(realm) => self.jwks(realm),
            // MD-6, CR-2, OP-155 m.3 (k)
            Request::SignRs256 {
                realm,
                typ,
                payload,
                at,
            } => self.sign_rs256(realm, &typ, &payload, at, now),
            Request::Sign {
                realm,
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
                let Some((_, ring)) = self.rings.get_mut(&realm) else {
                    return Response::Error(String::from(UNKNOWN_REALM));
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
                realm,
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
                let Some((_, ring)) = self.rings.get_mut(&realm) else {
                    return Response::Error(String::from(UNKNOWN_REALM));
                };
                match ring.sign_cose(&content_type, &payload, at) {
                    Ok((sign1, kid)) => Response::SignedCose { sign1, kid },
                    Err(e) => Response::Error(String::from(e.code())),
                }
            }
            Request::Rotate { realm, retire } => {
                self.rekey(realm, |ring, f| ring.rotate(f, &retire, now, draw))
            }
            Request::DropKey { realm, kid } => {
                self.rekey(realm, |ring, f| ring.drop_key(f, &kid, now, draw))
            }
            Request::SetPolicy { realm, policy } => self.rekey(realm, |ring, _| {
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
            other => self.handle_issuer(&other, now),
        }
    }

    /// Answers the Claim issuer key's requests (§10.1.7).
    fn handle_issuer(&mut self, request: &Request, now: u64) -> Response {
        let (realm, at) = match request {
            Request::OpenIssuer { realm, party } => {
                return match self.open_issuer(*realm, *party) {
                    Ok(k) => Response::Issuer {
                        party: k.party(),
                        key: k.key(),
                        kid: k.kid(),
                    },
                    Err(e) => Response::Error(String::from(e.code())),
                };
            }
            Request::SignClaim { realm, at, .. } => (*realm, *at),
            Request::SignIssuerRegistration {
                realm,
                registration,
            } => (*realm, registration.iat),
            _ => return Response::Error(String::from("signer-frame")),
        };
        if at.abs_diff(now) > MAX_SKEW_MS {
            return Response::Error(String::from("signer-time"));
        }
        let Some(k) = self.issuer(realm) else {
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

    /// The Claim issuer key of `realm`: the open one, the stored one, or a new one stored before
    /// it is used, bound to `party` (§10.1.7). A key bound to another Party is refused.
    ///
    /// # Errors
    /// [`IssuerError`]; [`IssuerError::Stored`] also when the vault cannot be read or written.
    pub fn open_issuer(
        &mut self,
        realm: Realm,
        party: [u8; 16],
    ) -> Result<&IssuerKey, IssuerError> {
        if self.issuer(realm).is_none() {
            let key = IssuerKey::generate(realm.0, party, &mut self.factory)?;
            let stored = key.stored().ok_or(IssuerError::Stored)?;
            self.vault
                .put_issuer(&realm, &stored)
                .map_err(|_| IssuerError::Stored)?;
            self.issuers.insert(realm, key);
        }
        match self.issuers.get(&realm) {
            Some(k) if k.party() == party => Ok(k),
            Some(_) => Err(IssuerError::OtherIssuer),
            None => Err(IssuerError::Stored),
        }
    }

    /// The realm's JWKS, its `rsa-id` key after the JOSE keys when it has one.
    fn jwks(&mut self, realm: Realm) -> Response {
        let rsa = self
            .rsa_id(realm)
            .map(access_crypto::rsa_id::RsaIdKey::public_jwk);
        self.rings.get(&realm).map_or_else(
            || Response::Error(String::from(UNKNOWN_REALM)),
            |(_, ring)| Response::Jwks(with_rsa(ring.jwks(), rsa.as_deref())),
        )
    }

    /// Signs `payload` as an RS256 JWS of `typ` with the realm's `rsa-id` key (MD-6, CR-2).
    fn sign_rs256(
        &mut self,
        realm: Realm,
        typ: &str,
        payload: &[u8],
        at: u64,
        now: u64,
    ) -> Response {
        if at.abs_diff(now) > MAX_SKEW_MS {
            return Response::Error(String::from("signer-time"));
        }
        if !self.rings.contains_key(&realm) {
            return Response::Error(String::from(UNKNOWN_REALM));
        }
        let Some(key) = self.open_rsa_id(realm) else {
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

    /// The realm's `rsa-id` key when one was made, loaded from the vault after a restart.
    fn rsa_id(&mut self, realm: Realm) -> Option<&access_crypto::rsa_id::RsaIdKey> {
        if !self.rsa_ids.contains_key(&realm) {
            let stored = self.vault.rsa_id(&realm).ok().flatten()?;
            let key = self.factory.load_rsa_id(&stored).ok()?;
            self.rsa_ids.insert(realm, key);
        }
        self.rsa_ids.get(&realm)
    }

    /// The realm's `rsa-id` key, made and stored before its first use (MD-6).
    fn open_rsa_id(&mut self, realm: Realm) -> Option<&access_crypto::rsa_id::RsaIdKey> {
        if self.rsa_id(realm).is_none() {
            let (key, sealed) = self.factory.generate_rsa_id().ok()?;
            self.vault.put_rsa_id(&realm, &sealed).ok()?;
            self.rsa_ids.insert(realm, key);
        }
        self.rsa_ids.get(&realm)
    }

    /// The realm's open Claim issuer key, loaded from the vault after a restart.
    fn issuer(&mut self, realm: Realm) -> Option<&IssuerKey> {
        if !self.issuers.contains_key(&realm) {
            let stored = self.vault.issuer(&realm).ok().flatten()?;
            let key = IssuerKey::restore(realm.0, &stored, &mut self.factory).ok()?;
            self.issuers.insert(realm, key);
        }
        self.issuers.get(&realm)
    }
}

/// The realm's JWKS with its `rsa-id` key appended after the JOSE keys, when it has one
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
        let realm = request.realm();
        if !self.saml.contains_key(&realm) {
            let ring = match self.vault.saml(&realm) {
                Ok(Some(stored)) => match Ring::restore(realm, &stored, &mut self.factory) {
                    Ok(r) => r,
                    Err(e) => return Response::Error(String::from(e.code())),
                },
                Ok(None) => Ring::new(realm),
                Err(_) => return Response::Error(String::from(SamlKeyError::Stored.code())),
            };
            self.saml.insert(realm, ring);
        }
        let Some(ring) = self.saml.get_mut(&realm) else {
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
                    .is_some_and(|b| self.vault.put_saml(&realm, &b).is_ok());
                if !kept {
                    self.saml.remove(&realm);
                    return Response::Error(String::from(SamlKeyError::Stored.code()));
                }
            }
            Ok(false) => {}
            Err(e) => return Response::Error(String::from(e.code())),
        }
        let keys = self.saml.get(&realm).map(Ring::keys).unwrap_or_default();
        Response::Saml(SamlResponse::Keys(keys))
    }
}

/// The refusal for a realm whose Claim issuer key was never opened.
pub const NO_ISSUER: &str = "signer-no-issuer";

/// The content types of Access protocol artefacts, which only their own keys sign: a realm's
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

/// The refusal for a realm whose key set is not open.
pub const UNKNOWN_REALM: &str = "signer-unknown-realm";

#[cfg(test)]
mod tests;
