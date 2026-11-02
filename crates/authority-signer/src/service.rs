//! The signer service: one keyring per domain, the schedule for all of them, and the requests
//! of the protocol (OP-143 m.4).

use std::collections::BTreeMap;

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::OperationalKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::rotation::{Key, Policy, State};

use crate::app::{Keyring, Saved};
use crate::domain::Template;
use crate::ports::{Bindings, KeyFactory, Vault};
use crate::protocol::{Request, Response};

/// How far a requested signing time may be from the signer's clock (PD).
pub const MAX_SKEW_MS: u64 = 60_000;

/// The signer of one process.
pub struct Service<F, B, V> {
    rings: BTreeMap<Digest, (Template, Keyring)>,
    factory: F,
    bindings: B,
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
        ("declared", Some(s.declared.to_value())),
        ("excerpt", s.excerpt.clone().map(Value::Bytes)),
        ("sealed", s.sealed.clone().map(Value::Bytes)),
    ])
}

fn saved_of(v: &Value) -> Option<Saved> {
    let state = match v.get("state") {
        Some(Value::Text(t)) => STATES.iter().find(|(n, _)| n == t).map(|(_, s)| *s)?,
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
        declared: OperationalKey::from_value(v.get("declared")?).ok()?,
        excerpt: bytes(v.get("excerpt")),
        sealed: bytes(v.get("sealed")),
    })
}

/// A domain's vault entry: its template (as an `open` request), its keys and its signed
/// Genesis statement.
fn stored(template: &Template, saved: &[Saved], genesis: Option<&[u8]>) -> Option<Vec<u8>> {
    let open = crate::protocol::encode_request(&Request::Open(Box::new(template.clone()))).ok()?;
    let v = map(vec![
        ("open", Some(Value::Bytes(open.get(4..)?.to_vec()))),
        (
            "keys",
            Some(Value::Array(saved.iter().map(saved_value).collect())),
        ),
        ("genesis", genesis.map(|g| Value::Bytes(g.to_vec()))),
    ]);
    dcbor::encode(&v, Limits::CEILING).ok()
}

type Restored = (Template, Vec<Saved>, Option<Vec<u8>>);

fn restored(b: &[u8]) -> Option<Restored> {
    let v = dcbor::decode(b, Limits::CEILING).ok()?;
    let Request::Open(t) = crate::protocol::decode_request(&bytes(v.get("open"))?).ok()? else {
        return None;
    };
    let Some(Value::Array(keys)) = v.get("keys") else {
        return None;
    };
    Some((
        *t,
        keys.iter().filter_map(saved_of).collect(),
        bytes(v.get("genesis")),
    ))
}

impl<F: KeyFactory, B: Bindings, V: Vault> Service<F, B, V> {
    /// A service that restores every domain the vault holds at `now`.
    ///
    /// # Errors
    /// The vault cannot be read; a domain that cannot be restored is left closed.
    pub fn start(
        factory: F,
        bindings: B,
        mut vault: V,
        policy: Policy,
        now: u64,
    ) -> Result<Self, crate::ports::VaultError> {
        let all = vault.all()?;
        let mut s = Self {
            rings: BTreeMap::new(),
            factory,
            bindings,
            vault,
            policy,
        };
        for (template, saved, genesis) in all.iter().filter_map(|b| restored(b)) {
            let Ok(binding) = s.bindings.binding(&template.domain) else {
                continue;
            };
            if let Ok(mut ring) = Keyring::restore(
                template.clone(),
                binding,
                s.policy,
                saved,
                &mut s.factory,
                now,
            ) {
                match genesis {
                    Some(g) => ring.keep_genesis(g),
                    None => {
                        let _ = ring.genesis(now);
                    }
                }
                s.rings.insert(template.domain, (template, ring));
            }
        }
        Ok(s)
    }

    fn persist(&mut self, domain: &Digest) -> bool {
        let Some((t, ring)) = self.rings.get(domain) else {
            return false;
        };
        stored(t, &ring.saved(), ring.genesis_signed())
            .is_some_and(|b| self.vault.put(domain, &b).is_ok())
    }

    /// Runs the schedule of every domain at `now` and keeps the vault current; returns the
    /// domains whose round failed or hit a key-generation outage.
    pub fn tick(&mut self, now: u64, draw: u64) -> Vec<Digest> {
        let mut troubled = Vec::new();
        let domains: Vec<Digest> = self.rings.keys().copied().collect();
        for d in domains {
            let ok = self
                .rings
                .get_mut(&d)
                .map(|(_, ring)| ring.tick(&mut self.factory, now, draw))
                .is_some_and(|r| r.is_ok_and(|round| !round.outage));
            if !self.persist(&d) || !ok {
                troubled.push(d);
            }
        }
        troubled
    }

    /// Answers one request at `now`.
    pub fn handle(&mut self, request: Request, now: u64) -> Response {
        match request {
            Request::Open(template) => {
                let template = *template;
                let domain = template.domain;
                if !self.rings.contains_key(&domain) {
                    let Ok(binding) = self.bindings.binding(&domain) else {
                        return Response::Error(String::from("signer-binding"));
                    };
                    let mut ring = Keyring::new(template.clone(), binding, self.policy);
                    if ring.genesis(now).is_err() {
                        return Response::Error(String::from("signer-binding"));
                    }
                    self.rings.insert(domain, (template, ring));
                    let _ = self.tick_one(&domain, now);
                }
                Response::Opened
            }
            Request::Genesis(domain) => self
                .rings
                .get(&domain)
                .and_then(|(_, r)| r.genesis_signed())
                .map_or_else(
                    || Response::Error(String::from("signer-unknown-domain")),
                    |g| Response::Genesis(g.to_vec()),
                ),
            Request::SignNote { domain, body, at } => {
                if at.abs_diff(now) > MAX_SKEW_MS {
                    return Response::Error(String::from("signer-time"));
                }
                let Some((_, ring)) = self.rings.get_mut(&domain) else {
                    return Response::Error(String::from("signer-unknown-domain"));
                };
                match ring.sign_note(&body, at) {
                    Ok(n) => Response::Noted {
                        line: n.line,
                        excerpt: n.excerpt,
                    },
                    Err(e) => Response::Error(String::from(e.code())),
                }
            }
            Request::Metadata(domain) => self
                .rings
                .get(&domain)
                .and_then(|(_, r)| r.metadata())
                .map_or_else(
                    || Response::Error(String::from("signer-unknown-domain")),
                    |m| Response::Metadata(m.to_vec()),
                ),
            Request::Sign {
                domain,
                usage,
                content_type,
                payload,
                at,
            } => {
                if at.abs_diff(now) > MAX_SKEW_MS {
                    return Response::Error(String::from("signer-time"));
                }
                let Some((_, ring)) = self.rings.get_mut(&domain) else {
                    return Response::Error(String::from("signer-unknown-domain"));
                };
                match ring.sign(usage, &content_type, &payload, at) {
                    Ok(s) => Response::Signed {
                        sign1: s.sign1,
                        excerpt: s.excerpt,
                    },
                    Err(e) => Response::Error(String::from(e.code())),
                }
            }
        }
    }

    fn tick_one(&mut self, domain: &Digest, now: u64) -> bool {
        let ok = self
            .rings
            .get_mut(domain)
            .is_some_and(|(_, ring)| ring.tick(&mut self.factory, now, now).is_ok());
        self.persist(domain) && ok
    }
}

#[cfg(test)]
mod tests;
