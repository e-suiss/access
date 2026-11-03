//! The identity signer service: one key set per realm, the schedule for all of them, and the
//! requests of the protocol (CMP-22b, OP-143 m.9 (e)).

use std::collections::BTreeMap;

use access_crypto::jose::JwsAlg;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::rotation::{Key, Policy, State};

use crate::app::{Keyring, Saved};
use crate::ports::{KeyFactory, Vault, VaultError};
use crate::protocol::{Realm, Request, Response, alg_of};

/// How far a requested signing time may be from the signer's clock (PD).
pub const MAX_SKEW_MS: u64 = 60_000;

/// The identity signer of one process.
pub struct Service<F, V> {
    rings: BTreeMap<Realm, (JwsAlg, Keyring)>,
    factory: F,
    vault: V,
    policy: Policy,
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
        },
        alg,
        key: key_of(alg, bytes(v.get("key"))?)?,
        sealed: bytes(v.get("sealed")),
    })
}

/// A realm's vault entry: its identifier, the algorithm of its new keys and its keys.
fn stored(realm: Realm, alg: JwsAlg, saved: &[Saved]) -> Option<Vec<u8>> {
    let v = map(vec![
        ("realm", Some(Value::Bytes(realm.0.to_vec()))),
        ("alg", Some(Value::text(alg.name()))),
        (
            "keys",
            Some(Value::Array(saved.iter().map(saved_value).collect())),
        ),
    ]);
    dcbor::encode(&v, Limits::CEILING).ok()
}

fn restored(b: &[u8]) -> Option<(Realm, JwsAlg, Vec<Saved>)> {
    let v = dcbor::decode(b, Limits::CEILING).ok()?;
    let realm = Realm(bytes(v.get("realm"))?.try_into().ok()?);
    let alg = match v.get("alg") {
        Some(Value::Text(t)) => alg_of(t)?,
        _ => return None,
    };
    let Some(Value::Array(keys)) = v.get("keys") else {
        return None;
    };
    Some((realm, alg, keys.iter().filter_map(saved_of).collect()))
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
        };
        for (realm, alg, saved) in all.iter().filter_map(|b| restored(b)) {
            if let Ok(ring) = Keyring::restore(alg, s.policy, saved, &mut s.factory) {
                s.rings.insert(realm, (alg, ring));
            }
        }
        Ok(s)
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
        stored(realm, *alg, &ring.saved()).is_some_and(|b| self.vault.put(&realm, &b).is_ok())
    }

    fn tick_one(&mut self, realm: Realm, now: u64, draw: u64) -> bool {
        let ok = self
            .rings
            .get_mut(&realm)
            .is_some_and(|(_, ring)| !ring.tick(&mut self.factory, now, draw).outage);
        self.persist(realm) && ok
    }

    /// Runs the schedule of every realm at `now` and keeps the vault current; returns the
    /// realms whose round failed or hit a key-generation outage (CR-23).
    pub fn tick(&mut self, now: u64, draw: u64) -> Vec<Realm> {
        let realms = self.realms();
        realms
            .into_iter()
            .filter(|r| !self.tick_one(*r, now, draw))
            .collect()
    }

    /// Answers one request at `now`; `draw` is a random value for a new key's jitter.
    pub fn handle(&mut self, request: Request, now: u64, draw: u64) -> Response {
        match request {
            Request::Ping => Response::Pong,
            Request::Open { realm, alg } => {
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
            Request::Jwks(realm) => self.rings.get(&realm).map_or_else(
                || Response::Error(String::from(UNKNOWN_REALM)),
                |(_, ring)| Response::Jwks(ring.jwks().to_owned()),
            ),
            Request::Sign {
                realm,
                typ,
                payload,
                at,
            } => {
                if at.abs_diff(now) > MAX_SKEW_MS {
                    return Response::Error(String::from("signer-time"));
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
        }
    }
}

/// The refusal for a realm whose key set is not open.
pub const UNKNOWN_REALM: &str = "signer-unknown-realm";

#[cfg(test)]
mod tests;
