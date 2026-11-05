//! The key set of one realm: it follows the rotation schedule, keeps the JWKS current and signs
//! tokens with the key that may sign now (CR-23, CR-25, CR-27, SAI-46).

use access_crypto::jose::{JwsAlg, sign_compact};
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::rotation::{self, Key, Policy, State, Step};
use suiss_crypto::signer::Signer;

use crate::SignerError;
use crate::domain::{self, PolicyError};
use crate::ports::KeyFactory;

struct Entry {
    record: Key,
    alg: JwsAlg,
    key: PublicKey,
    signer: Option<Box<dyn Signer + Send>>,
    sealed: Option<Vec<u8>>,
}

/// One realm key as a vault keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    /// Rotation record.
    pub record: Key,
    /// Algorithm.
    pub alg: JwsAlg,
    /// Public key.
    pub key: PublicKey,
    /// Sealed private material; gone once the key is dropped (crypto-shredding, OP-73).
    pub sealed: Option<Vec<u8>>,
}

/// A signed token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// Compact JWS.
    pub token: String,
    /// The key's `kid`, its RFC 7638 thumbprint (CR-24).
    pub kid: [u8; 32],
    /// The algorithm.
    pub alg: JwsAlg,
}

/// What a schedule round did; each applied step is a realm audit event (CR-27).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Round {
    /// Steps applied.
    pub applied: Vec<Step>,
    /// Keys the factory could not create (CR-23: signing goes on with the active key).
    pub outage: bool,
}

/// The key set of one realm: 1 active and at least 1 published backup (CR-27, MD-6).
pub struct Keyring {
    alg: JwsAlg,
    policy: Policy,
    entries: Vec<Entry>,
    jwks: String,
}

/// An `application/…+cbor` media type of the identity plane: lower case, no parameters.
fn content_type_ok(t: &str) -> bool {
    t.len() <= 127
        && t.strip_prefix("application/")
            .and_then(|s| s.strip_suffix("+cbor"))
            .is_some_and(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-.".contains(&c))
            })
}

const EMPTY_JWKS: &str = r#"{"keys":[]}"#;

/// Plan passes per round: rotate and generate, publish what was generated, settle.
const PASSES: usize = 3;

impl Keyring {
    /// An empty key set whose new keys use `alg`: ES256 by default, Ed25519 when the realm
    /// selects it (CR-2, MD-3).
    ///
    /// # Errors
    /// [`PolicyError`] for a policy the realm may not take.
    pub fn new(alg: JwsAlg, policy: Policy) -> Result<Self, PolicyError> {
        domain::check(&policy)?;
        Ok(Self {
            alg,
            policy,
            entries: Vec::new(),
            jwks: String::from(EMPTY_JWKS),
        })
    }

    /// The algorithm of the set's new keys.
    #[must_use]
    pub const fn alg(&self) -> JwsAlg {
        self.alg
    }

    /// Makes the set's next keys use `alg` (OP-146 m.8 (e)); the keys it holds keep theirs and
    /// rotate out on schedule, so a new key is still published before use (MD-6).
    pub const fn set_alg(&mut self, alg: JwsAlg) {
        self.alg = alg;
    }

    /// The set's rotation policy.
    #[must_use]
    pub const fn policy(&self) -> Policy {
        self.policy
    }

    /// Replaces the rotation policy (TN-118: an `idp.realm.key_policy` decision); the keys it
    /// holds keep their windows and follow the new policy from the next round.
    ///
    /// # Errors
    /// [`PolicyError`] for a policy the realm may not take (CR-26).
    pub fn set_policy(&mut self, policy: Policy) -> Result<(), PolicyError> {
        domain::check(&policy)?;
        self.policy = policy;
        Ok(())
    }

    fn step(&mut self, step: &Step, now: u64) {
        let mut records = self.records();
        rotation::apply(&mut records, step, now);
        for (e, r) in self.entries.iter_mut().zip(records) {
            e.record = r;
            // CR-27, CR-33
            if e.record.state == State::Dropped {
                e.signer = None;
                e.sealed = None;
            }
        }
    }

    /// Rotates now, outside the schedule (TN-118: an `idp.realm.key_rotate` decision): the
    /// published backup past its lead becomes the signing key, the active key retires and stays
    /// in the JWKS until its tokens expire, and a new backup is generated and published.
    /// Publish-before-use holds: only a key relying parties could already have seen signs
    /// (MD-6, CR-25, SAI-46). `retire` names the active key the decision rotates out; once it
    /// is no longer active, a repeat changes nothing.
    ///
    /// # Errors
    /// [`SignerError::UnknownKey`] when `retire` was never the set's active key;
    /// [`SignerError::NoBackup`] when no backup is past its lead. Nothing changed.
    pub fn rotate(
        &mut self,
        factory: &mut dyn KeyFactory,
        retire: &[u8; 32],
        now: u64,
        draw: u64,
    ) -> Result<Round, SignerError> {
        match self.entries.iter().find(|e| e.record.kid == *retire) {
            Some(e) if e.record.state == State::Active => {}
            Some(e) if matches!(e.record.state, State::Retiring | State::Dropped) => {
                return Ok(Round::default());
            }
            _ => return Err(SignerError::UnknownKey),
        }
        let lead = self.policy.publish_lead_ms;
        let backup = self
            .entries
            .iter()
            .filter(|e| {
                e.record.state == State::Published
                    && e.record.valid_from <= now
                    && now <= e.record.valid_until
                    && e.record
                        .published_at
                        .is_some_and(|p| p.saturating_add(lead) <= now)
                    && e.signer.is_some()
            })
            .min_by_key(|e| e.record.valid_from)
            .map(|e| e.record.kid)
            .ok_or(SignerError::NoBackup)?;
        let active: Vec<[u8; 32]> = self
            .entries
            .iter()
            .filter(|e| e.record.state == State::Active)
            .map(|e| e.record.kid)
            .collect();
        let mut applied = vec![Step::Activate(backup)];
        applied.extend(active.into_iter().map(Step::Retire));
        for step in &applied {
            self.step(step, now);
        }
        let mut round = self.tick(factory, now, draw);
        applied.append(&mut round.applied);
        round.applied = applied;
        self.rebuild();
        Ok(round)
    }

    /// Withdraws `kid` at once, outside the schedule, and destroys its private material: the
    /// emergency drop of a compromised key (§13.2, `idp.realm.key_drop`). It leaves the JWKS
    /// now, so nothing it signed verifies any more and its `key_epoch` window ends; when it was
    /// the signing key, the published backup past its lead takes over, and without one nothing
    /// is signed until one is (CR-23, fail closed). Dropping a dropped key changes nothing.
    ///
    /// # Errors
    /// [`SignerError::UnknownKey`] for a key the set does not hold.
    pub fn drop_key(
        &mut self,
        factory: &mut dyn KeyFactory,
        kid: &[u8; 32],
        now: u64,
        draw: u64,
    ) -> Result<Round, SignerError> {
        match self.entries.iter().find(|e| e.record.kid == *kid) {
            None => return Err(SignerError::UnknownKey),
            Some(e) if e.record.state == State::Dropped => return Ok(Round::default()),
            Some(_) => {}
        }
        let mut applied = vec![Step::Drop(*kid)];
        self.step(&Step::Drop(*kid), now);
        self.rebuild();
        let mut round = self.tick(factory, now, draw);
        applied.append(&mut round.applied);
        round.applied = applied;
        self.rebuild();
        Ok(round)
    }

    fn records(&self) -> Vec<Key> {
        self.entries.iter().map(|e| e.record.clone()).collect()
    }

    fn generate(&mut self, factory: &mut dyn KeyFactory, step: &Step) -> bool {
        let Step::Generate {
            valid_from,
            valid_until,
            jitter_permille,
        } = *step
        else {
            return true;
        };
        let Ok(generated) = factory.generate(self.alg) else {
            return false;
        };
        let key = generated.signer.public_key();
        if JwsAlg::of(&key) != Some(self.alg) {
            return false;
        }
        let kid = thumbprint(&key);
        if self.entries.iter().any(|e| e.record.kid == kid) {
            return false;
        }
        self.entries.push(Entry {
            record: Key {
                kid,
                state: State::Pending,
                published_at: None,
                valid_from,
                valid_until,
                activated_at: None,
                jitter_permille,
                signatures: 0,
            },
            alg: self.alg,
            key,
            signer: Some(generated.signer),
            sealed: Some(generated.sealed),
        });
        true
    }

    /// Brings the keys to the schedule at `now` and rebuilds the JWKS when the published set
    /// changed; `draw` is a random value for the jitter of a new key. A key generated in a
    /// round is published in the same round, so a backup is always in the JWKS.
    pub fn tick(&mut self, factory: &mut dyn KeyFactory, now: u64, draw: u64) -> Round {
        let mut round = Round::default();
        let mut changed = false;
        for _ in 0..PASSES {
            let mut progressed = false;
            for step in rotation::plan(&self.records(), &self.policy, now, draw) {
                if !self.generate(factory, &step) {
                    round.outage = true;
                    continue;
                }
                progressed = true;
                changed |= matches!(step, Step::Publish(_) | Step::Drop(_));
                self.step(&step, now);
                round.applied.push(step);
            }
            if !progressed {
                break;
            }
        }
        if changed {
            self.rebuild();
        }
        round
    }

    fn published(&self) -> Vec<&Entry> {
        let mut keys: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    e.record.state,
                    State::Published | State::Active | State::Retiring
                )
            })
            .collect();
        let rank = |s: State| match s {
            State::Active => 0_u8,
            State::Published => 1,
            _ => 2,
        };
        keys.sort_by_key(|e| (rank(e.record.state), e.record.valid_from));
        keys
    }

    fn rebuild(&mut self) {
        let doc = domain::jwks(
            self.published()
                .into_iter()
                .map(|e| (&e.record.kid, &e.key)),
        );
        // MD-3
        if let Ok(doc) = doc {
            self.jwks = doc;
        }
    }

    /// The realm's JWKS: published, active and retiring keys, the active one first (CR-25,
    /// CR-26). Served with [`domain::CACHE_CONTROL`].
    #[must_use]
    pub fn jwks(&self) -> &str {
        &self.jwks
    }

    /// How long the active key is past its rotation time at `now`, if it is (CR-23).
    #[must_use]
    pub fn overdue(&self, now: u64) -> Option<u64> {
        rotation::overdue(&self.records(), &self.policy, now)
    }

    /// The rotation records of every key, dropped ones included.
    #[must_use]
    pub fn keys(&self) -> Vec<Key> {
        self.records()
    }

    /// Signs a JSON object `payload` as a compact JWS of type `typ` at `now`, with the key
    /// that may sign now (SAI-46); without one, nothing is signed (CR-23, G42).
    ///
    /// # Errors
    /// [`SignerError::NoKey`] or [`SignerError::Jose`].
    pub fn sign(&mut self, typ: &str, payload: &[u8], now: u64) -> Result<Signed, SignerError> {
        let records = self.records();
        let kid = rotation::signing_key(&records, &self.policy, now)
            .map(|k| k.kid)
            .ok_or(SignerError::NoKey)?;
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record.kid == kid)
            .ok_or(SignerError::NoKey)?;
        let signer = entry.signer.as_deref().ok_or(SignerError::NoKey)?;
        let token = sign_compact(signer, &kid, typ, payload)?;
        entry.record.signatures = entry.record.signatures.saturating_add(1);
        Ok(Signed {
            token,
            kid,
            alg: entry.alg,
        })
    }

    /// Signs deterministic CBOR `payload` as a tagged `COSE_Sign1` of `content_type` at `now`
    /// with the key that may sign tokens now (OP-149 m.8): its `kid` is the key's in the JWKS.
    ///
    /// # Errors
    /// [`SignerError::NoKey`], [`SignerError::Payload`] or [`SignerError::Sign`].
    pub fn sign_cose(
        &mut self,
        content_type: &str,
        payload: &[u8],
        now: u64,
    ) -> Result<(Vec<u8>, [u8; 32]), SignerError> {
        if !content_type_ok(content_type)
            || suiss_crypto::dcbor::decode(payload, suiss_crypto::dcbor::Limits::CEILING).is_err()
        {
            return Err(SignerError::Payload);
        }
        let records = self.records();
        let kid = rotation::signing_key(&records, &self.policy, now)
            .map(|k| k.kid)
            .ok_or(SignerError::NoKey)?;
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record.kid == kid)
            .ok_or(SignerError::NoKey)?;
        let signer = entry.signer.as_deref().ok_or(SignerError::NoKey)?;
        let sign1 = suiss_crypto::signer::sign_sign1(signer, kid, content_type, payload)
            .map_err(|_| SignerError::Sign)?;
        entry.record.signatures = entry.record.signatures.saturating_add(1);
        Ok((sign1, kid))
    }

    /// The keys as a vault keeps them.
    #[must_use]
    pub fn saved(&self) -> Vec<Saved> {
        self.entries
            .iter()
            .map(|e| Saved {
                record: e.record.clone(),
                alg: e.alg,
                key: e.key.clone(),
                sealed: e.sealed.clone(),
            })
            .collect()
    }

    /// A key set restored after a restart: sealed keys are loaded back and the JWKS rebuilt
    /// (CR-23). A key that cannot be loaded, or whose `kid` does not match, no longer signs.
    ///
    /// # Errors
    /// [`PolicyError`] for a policy the realm may not take.
    pub fn restore(
        alg: JwsAlg,
        policy: Policy,
        saved: Vec<Saved>,
        factory: &mut dyn KeyFactory,
    ) -> Result<Self, PolicyError> {
        let mut ring = Self::new(alg, policy)?;
        for s in saved {
            if thumbprint(&s.key) != s.record.kid {
                continue;
            }
            let signer = s
                .sealed
                .as_deref()
                .filter(|_| s.record.state != State::Dropped)
                .and_then(|sealed| factory.load(s.alg, sealed).ok())
                .filter(|k| k.public_key() == s.key);
            ring.entries.push(Entry {
                record: s.record,
                alg: s.alg,
                key: s.key,
                signer,
                sealed: s.sealed,
            });
        }
        ring.rebuild();
        Ok(ring)
    }
}

#[cfg(test)]
mod tests;
