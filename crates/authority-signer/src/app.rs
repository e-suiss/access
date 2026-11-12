//! The keyring of one domain: it follows the rotation schedule, keeps the binding-signed
//! metadata and excerpts current, and signs with the key that may sign now (CR-23, CR-25,
//! CR-27, CR-59, SAI-46).

use access_kernel::codec::Canonical;
use access_kernel::verify::key_scope::{
    BindingKey, EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage, METADATA_CONTENT_TYPE, OperationalKey,
    thumbprint,
};
use suiss_crypto::note::Checkpoint;
use suiss_crypto::rotation::{self, Key, Policy, State, Step};
use suiss_crypto::signer::{SignError, Signer, sign_note, sign_sign1};

use crate::SignerError;
use crate::domain::{Template, binding, declaration, metadata};
use crate::ports::KeyFactory;
use access_kernel::verify::key_scope::Hybrid;
use access_kernel::verify::ml_dsa::is_ml_dsa;
use access_kernel::verify::reanchor::CHECKPOINT_CONTENT_TYPE as PQ_CHECKPOINT_CONTENT_TYPE;
use suiss_crypto::cose::Algorithm;

struct Entry {
    record: Key,
    declared: OperationalKey,
    signer: Option<Box<dyn Signer + Send>>,
    sealed: Option<Vec<u8>>,
    excerpt: Option<Vec<u8>>,
}

/// One operational key as the vault keeps it (OP-143 m.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    /// Rotation record.
    pub record: Key,
    /// Declaration.
    pub declared: OperationalKey,
    /// Binding-signed excerpt, once published.
    pub excerpt: Option<Vec<u8>>,
    /// Sealed private material; gone once the key is dropped (crypto-shredding, OP-73).
    pub sealed: Option<Vec<u8>>,
}

/// An artefact signature and the excerpt that declares its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// `COSE_Sign1` by the operational key.
    pub sign1: Vec<u8>,
    /// Binding-signed excerpt of the operational key (CR-58 m.1).
    pub excerpt: Vec<u8>,
    /// The key's `kid`.
    pub kid: [u8; 32],
    /// The ML-DSA component over the same payload while the domain signs both (CR-42 m.4,
    /// OP-159 m.3 (e)).
    pub pq: Option<Component>,
}

/// One more `COSE_Sign1` of a hybrid artefact and the excerpt of its key (CR-42 m.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    /// `COSE_Sign1` by the ML-DSA operational key.
    pub sign1: Vec<u8>,
    /// Binding-signed excerpt of that key.
    pub excerpt: Vec<u8>,
}

/// What a schedule round did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Round {
    /// Steps applied.
    pub applied: Vec<Step>,
    /// Keys the factory could not create (CR-23: signing goes on with the active key).
    pub outage: bool,
}

/// The keyring of one domain.
pub struct Keyring {
    template: Template,
    binding: Box<dyn Signer + Send>,
    declared_binding: BindingKey,
    policy: Policy,
    entries: Vec<Entry>,
    metadata: Option<Vec<u8>>,
    genesis: Option<Vec<u8>>,
    generation: u64,
    superseded: Vec<BindingKey>,
}

/// Plan passes per round: rotate and generate, publish what was generated, activate a founding
/// key and generate its backup (CR-59), publish that.
const PASSES: usize = 4;

impl Keyring {
    /// A keyring under `binding`, with no operational key yet.
    #[must_use]
    pub fn new(template: Template, binding_signer: Box<dyn Signer + Send>, policy: Policy) -> Self {
        let declared_binding = binding(binding_signer.algorithm(), binding_signer.public_key());
        Self {
            template,
            binding: binding_signer,
            declared_binding,
            policy,
            entries: Vec::new(),
            metadata: None,
            genesis: None,
            generation: 0,
            superseded: Vec::new(),
        }
    }

    /// This keyring under binding generation `generation`, with the `superseded` bindings of
    /// earlier handovers and re-anchors (OP-158 m.3 (l)).
    #[must_use]
    pub fn with_bindings(mut self, generation: u64, superseded: Vec<BindingKey>) -> Self {
        self.generation = generation;
        self.superseded = superseded;
        self
    }

    /// The binding generation that signs now.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The bindings earlier handovers and re-anchors superseded.
    #[must_use]
    pub fn superseded(&self) -> &[BindingKey] {
        &self.superseded
    }

    /// Signs a handover statement with the current binding (§16.6 HO-6, RB-4).
    ///
    /// # Errors
    /// [`SignerError::Usage`] for any other content type; the binding key's failure.
    pub fn sign_statement(
        &self,
        content_type: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        if !crate::handover::STATEMENTS.contains(&content_type) {
            return Err(SignerError::Usage);
        }
        self.binding_sign(content_type, payload)
    }

    /// RB-5, RB-6: the keyring of the next binding generation `next`, signed by
    /// `binding_signer`: this binding is superseded at `at`, the operational keys start anew
    /// under the new binding, its Genesis statement is signed at `now` and the metadata
    /// declares `transcript` as the re-anchor's ceremony transcript (OP-157 m.7 (i)). This
    /// keyring's keys sign nothing more.
    ///
    /// # Errors
    /// [`SignerError`] when the new binding cannot sign.
    pub fn rebound(
        &self,
        binding_signer: Box<dyn Signer + Send>,
        next: u64,
        at: access_kernel::verify::key_scope::Superseded,
        transcript: access_kernel::digest::Digest,
        factory: &mut dyn KeyFactory,
        now: u64,
    ) -> Result<Self, SignerError> {
        let mut template = self.template.clone();
        template.declared.ceremony_transcript = Some(transcript);
        let mut old = self.declared_binding.clone();
        old.superseded = Some(at);
        let mut superseded = self.superseded.clone();
        superseded.push(old);
        let mut ring =
            Self::new(template, binding_signer, self.policy).with_bindings(next, superseded);
        if ring.declared_binding.kid == self.declared_binding.kid {
            return Err(SignerError::Usage);
        }
        ring.genesis(now)?;
        ring.tick(factory, now, now)?;
        Ok(ring)
    }

    /// HO-8: publishes the outgoing provider's bindings, each superseded, beside this one and
    /// signs the metadata again at `now`; on a failure nothing changes.
    ///
    /// # Errors
    /// [`SignerError::Usage`] for a key that is not superseded or is this binding.
    pub fn supersede(&mut self, keys: Vec<BindingKey>, now: u64) -> Result<(), SignerError> {
        if keys
            .iter()
            .any(|k| k.superseded.is_none() || k.kid == self.declared_binding.kid)
        {
            return Err(SignerError::Usage);
        }
        let before = self.superseded.clone();
        for k in keys {
            if !self.superseded.iter().any(|s| s.kid == k.kid) {
                self.superseded.push(k);
            }
        }
        match self.sign_metadata(now) {
            Ok(m) => {
                self.metadata = Some(m);
                Ok(())
            }
            Err(e) => {
                self.superseded = before;
                Err(e)
            }
        }
    }

    fn records(&self) -> Vec<Key> {
        self.records_in(false)
    }

    fn records_in(&self, pq: bool) -> Vec<Key> {
        self.entries
            .iter()
            .filter(|e| is_ml_dsa(e.declared.alg) == pq)
            .map(|e| e.record.clone())
            .collect()
    }

    /// The ML-DSA parameter set the domain's operational keys sign with: ML-DSA-87 when the
    /// allowlist has it (CNSA), else ML-DSA-65; ML-DSA-44 is for offline projections only
    /// (CR-41 m.2, OP-159 m.3 (e)).
    #[must_use]
    pub fn pq_algorithm(&self) -> Option<Algorithm> {
        [Algorithm::MlDsa87, Algorithm::MlDsa65]
            .into_iter()
            .find(|a| self.template.algorithms.contains(a))
    }

    fn classical_on(&self) -> bool {
        self.template
            .algorithms
            .contains(&self.template.operational_alg)
    }

    fn lanes(&self) -> Vec<(bool, Algorithm)> {
        let mut out = Vec::new();
        if self.classical_on() {
            out.push((false, self.template.operational_alg));
        }
        if let Some(pq) = self.pq_algorithm() {
            out.push((true, pq));
        }
        out
    }

    fn binding_sign(&self, content_type: &str, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(sign_sign1(
            self.binding.as_ref(),
            self.declared_binding.kid,
            content_type,
            payload,
        )?)
    }

    /// Brings the keys to the schedule at `now` and re-signs the metadata when the published
    /// set changed; `draw` is a random value for the jitter of a new key. A key generated in a
    /// round is published in the same round, and a founding key signs from that round (CR-59).
    ///
    /// # Errors
    /// [`SignerError`] when the binding key cannot sign; the keys stay as they were.
    pub fn tick(
        &mut self,
        factory: &mut dyn KeyFactory,
        now: u64,
        draw: u64,
    ) -> Result<Round, SignerError> {
        let mut round = Round::default();
        let mut published_changed = self.metadata.is_none();
        for (pq, alg) in self.lanes() {
            published_changed |= self.tick_lane(factory, (pq, alg), now, draw, &mut round)?;
        }
        if published_changed {
            self.metadata = Some(self.sign_metadata(now)?);
        }
        Ok(round)
    }

    fn tick_lane(
        &mut self,
        factory: &mut dyn KeyFactory,
        (pq, alg): (bool, Algorithm),
        now: u64,
        draw: u64,
        round: &mut Round,
    ) -> Result<bool, SignerError> {
        let mut published_changed = false;
        for _ in 0..PASSES {
            let mut progressed = false;
            for step in rotation::plan(&self.records_in(pq), &self.policy, now, draw) {
                match &step {
                    Step::Generate {
                        valid_from,
                        valid_until,
                        jitter_permille,
                        founding,
                    } => {
                        let Ok(generated) = factory.generate(alg) else {
                            round.outage = true;
                            continue;
                        };
                        let signer = generated.signer;
                        let key = signer.public_key();
                        let record = Key {
                            kid: thumbprint(&key),
                            state: State::Pending,
                            published_at: None,
                            valid_from: *valid_from,
                            valid_until: *valid_until,
                            activated_at: None,
                            jitter_permille: *jitter_permille,
                            signatures: 0,
                            founding: *founding,
                        };
                        let declared = declaration(&record, signer.algorithm(), key);
                        self.entries.push(Entry {
                            record,
                            declared,
                            signer: Some(signer),
                            sealed: Some(generated.sealed),
                            excerpt: None,
                        });
                    }
                    Step::Publish(kid) => {
                        let excerpt = KeyExcerpt {
                            domain: self.template.domain,
                            key: self.declared(kid)?,
                        };
                        let bytes = excerpt.to_bytes().map_err(|_| SignerError::Encode)?;
                        let signed = self.binding_sign(EXCERPT_CONTENT_TYPE, &bytes)?;
                        if let Some(e) = self.entries.iter_mut().find(|e| e.record.kid == *kid) {
                            e.excerpt = Some(signed);
                        }
                        published_changed = true;
                    }
                    Step::Drop(_) => published_changed = true,
                    Step::Activate(_) | Step::Retire(_) => {}
                }
                let mut records = self.records_in(pq);
                rotation::apply(&mut records, &step, now);
                for (e, r) in self
                    .entries
                    .iter_mut()
                    .filter(|e| is_ml_dsa(e.declared.alg) == pq)
                    .zip(records)
                {
                    e.record = r;
                    if e.record.state == State::Dropped {
                        e.signer = None;
                        e.sealed = None;
                    }
                }
                round.applied.push(step);
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        Ok(published_changed)
    }

    /// How long the active key is past its rotation time at `now`, if it is (CR-23).
    #[must_use]
    pub fn overdue(&self, now: u64) -> Option<u64> {
        self.lanes()
            .into_iter()
            .filter_map(|(pq, _)| rotation::overdue(&self.records_in(pq), &self.policy, now))
            .max()
    }

    fn declared(&self, kid: &[u8; 32]) -> Result<OperationalKey, SignerError> {
        self.entries
            .iter()
            .find(|e| e.record.kid == *kid)
            .map(|e| e.declared.clone())
            .ok_or(SignerError::NoKey)
    }

    fn sign_metadata(&self, now: u64) -> Result<Vec<u8>, SignerError> {
        let published = self
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    e.record.state,
                    State::Published | State::Active | State::Retiring
                )
            })
            .map(|e| e.declared.clone())
            .collect();
        let m = metadata(
            &self.template,
            &self.declared_binding,
            &self.superseded,
            published,
            now,
        );
        let bytes = m.to_bytes().map_err(|_| SignerError::Encode)?;
        self.binding_sign(METADATA_CONTENT_TYPE, &bytes)
    }

    /// The keys as the vault keeps them.
    #[must_use]
    pub fn saved(&self) -> Vec<Saved> {
        self.entries
            .iter()
            .map(|e| Saved {
                record: e.record.clone(),
                declared: e.declared.clone(),
                excerpt: e.excerpt.clone(),
                sealed: e.sealed.clone(),
            })
            .collect()
    }

    /// A keyring restored from the vault after a restart: sealed keys are loaded back and the
    /// metadata is signed again at `now` (CR-23). A key that cannot be loaded no longer signs.
    ///
    /// # Errors
    /// [`SignerError`] when the binding key cannot sign the metadata.
    pub fn restore(
        template: Template,
        binding_signer: Box<dyn Signer + Send>,
        policy: Policy,
        saved: Vec<Saved>,
        factory: &mut dyn KeyFactory,
        now: u64,
    ) -> Result<Self, SignerError> {
        let mut ring = Self::new(template, binding_signer, policy);
        for s in saved {
            let signer = s
                .sealed
                .as_deref()
                .and_then(|sealed| factory.load(s.declared.alg, sealed).ok())
                .filter(|k| thumbprint(&k.public_key()) == s.record.kid);
            ring.entries.push(Entry {
                record: s.record,
                declared: s.declared,
                signer,
                sealed: s.sealed,
                excerpt: s.excerpt,
            });
        }
        ring.metadata = Some(ring.sign_metadata(now)?);
        Ok(ring)
    }

    /// Publishes `declared` as what the domain declares (OP-158 m.3 (b), (f)): the metadata is
    /// signed again at `now`; on a failure the declarations stay as they were.
    ///
    /// # Errors
    /// [`SignerError`] when the binding key cannot sign the metadata.
    pub fn declare(
        &mut self,
        declared: access_kernel::verify::key_scope::Declarations,
        now: u64,
    ) -> Result<(), SignerError> {
        let before = std::mem::replace(&mut self.template.declared, declared);
        match self.sign_metadata(now) {
            Ok(m) => {
                self.metadata = Some(m);
                Ok(())
            }
            Err(e) => {
                self.template.declared = before;
                Err(e)
            }
        }
    }

    /// The template the keyring was opened with, as declared now.
    #[must_use]
    pub const fn template(&self) -> &Template {
        &self.template
    }

    /// The current binding-signed Domain Metadata.
    #[must_use]
    pub fn metadata(&self) -> Option<&[u8]> {
        self.metadata.as_deref()
    }

    /// The binding key the metadata names.
    #[must_use]
    pub const fn binding_key(&self) -> &BindingKey {
        &self.declared_binding
    }

    /// Signs `payload` for `usage` at `now` with the key that may sign now (SAI-46); without
    /// one, nothing is signed (CR-23, G42).
    ///
    /// # Errors
    /// [`SignerError::NoKey`], [`SignerError::Usage`] or the signer's failure.
    pub fn sign(
        &mut self,
        usage: KeyUsage,
        content_type: &str,
        payload: &[u8],
        now: u64,
    ) -> Result<Signed, SignerError> {
        let pq = self.pq_algorithm().is_some();
        let sign = |signer: &dyn Signer, kid| sign_sign1(signer, kid, content_type, payload);
        if !self.classical_on() {
            let (sign1, excerpt, kid) = self.with_key_in(true, usage, now, sign)?;
            return Ok(Signed {
                sign1,
                excerpt,
                kid,
                pq: None,
            });
        }
        let (sign1, excerpt, kid) = self.with_key_in(false, usage, now, sign)?;
        // CR-42 m.4, OP-159 m.3 (e)
        let pq = if pq {
            let (sign1, excerpt, _) = self.with_key_in(true, usage, now, sign)?;
            Some(Component { sign1, excerpt })
        } else {
            None
        };
        Ok(Signed {
            sign1,
            excerpt,
            kid,
            pq,
        })
    }

    /// Signs a checkpoint body of the domain's log as a post-quantum re-anchor checkpoint: a
    /// `COSE_Sign1` over the byte-identical note body with the ML-DSA key that may sign
    /// `checkpoint` now (CR-45 RA-2, OP-159 m.3 (g)).
    ///
    /// # Errors
    /// [`SignerError::Note`] for a body that is not a checkpoint of this domain,
    /// [`SignerError::PqKeyUnavailable`] without an ML-DSA key, or the signer's failure.
    pub fn sign_pq_checkpoint(&mut self, body: &str, now: u64) -> Result<Signed, SignerError> {
        let origin = crate::domain::origin(&self.template.domain);
        let cp = Checkpoint::parse(body).map_err(|_| SignerError::Note)?;
        if cp.origin != origin || cp.to_body().ok().as_deref() != Some(body) {
            return Err(SignerError::Note);
        }
        if self.pq_algorithm().is_none() {
            return Err(SignerError::PqKeyUnavailable);
        }
        let (sign1, excerpt, kid) =
            self.with_key_in(true, KeyUsage::Checkpoint, now, |signer, kid| {
                sign_sign1(signer, kid, PQ_CHECKPOINT_CONTENT_TYPE, body.as_bytes())
            })?;
        Ok(Signed {
            sign1,
            excerpt,
            kid,
            pq: None,
        })
    }

    /// Adds `alg` to the domain's allowlist and signs the metadata again at `now` (OP-159 m.9
    /// (h)): a FIPS domain cannot add ML-DSA (CR-44), and adding ML-DSA makes the hybrid policy
    /// `both` unless it is already stricter (OP-159 m.3 (e)). The next tick creates the ML-DSA
    /// operational keys.
    ///
    /// # Errors
    /// [`SignerError::AlgorithmConflict`]; the binding key's failure, with nothing changed.
    pub fn admit(&mut self, alg: Algorithm, now: u64) -> Result<(), SignerError> {
        access_kernel::meta::admit_algorithm(&self.template.declared, alg)
            .map_err(|_| SignerError::AlgorithmConflict)?;
        let before = self.template.clone();
        self.template.algorithms.insert(alg);
        if is_ml_dsa(alg)
            && matches!(self.template.hybrid, None | Some(Hybrid::Classic))
            && alg != Algorithm::MlDsa44
        {
            self.template.hybrid = Some(Hybrid::Both);
        }
        self.resign(before, now)
    }

    /// Retires the classical algorithm `alg` (§15.16 step (b), OP-159 m.3 (f)): it leaves the
    /// allowlist and the hybrid policy becomes `pq`. Refused without an ML-DSA operational key
    /// or a published re-anchor, and while the binding itself signs with `alg`: the metadata
    /// could no longer be verified.
    ///
    /// # Errors
    /// [`SignerError::AlgorithmConflict`] for an algorithm that is not a listed classical one,
    /// [`SignerError::ReanchorRequired`] without a published re-anchor,
    /// [`SignerError::PqKeyUnavailable`] without an ML-DSA key or binding.
    pub fn retire(&mut self, alg: Algorithm, now: u64) -> Result<(), SignerError> {
        if is_ml_dsa(alg) || !self.template.algorithms.contains(&alg) {
            return Err(SignerError::AlgorithmConflict);
        }
        if self.template.declared.pq_reanchor.is_none() {
            return Err(SignerError::ReanchorRequired);
        }
        if self.pq_algorithm().is_none() || !is_ml_dsa(self.declared_binding.alg) {
            return Err(SignerError::PqKeyUnavailable);
        }
        let before = self.template.clone();
        self.template.algorithms.remove(&alg);
        self.template.hybrid = Some(Hybrid::Pq);
        self.resign(before, now)
    }

    fn resign(&mut self, before: Template, now: u64) -> Result<(), SignerError> {
        match self.sign_metadata(now) {
            Ok(m) => {
                self.metadata = Some(m);
                Ok(())
            }
            Err(e) => {
                self.template = before;
                Err(e)
            }
        }
    }

    /// Signs a checkpoint body of the domain's log as a C2SP note with the key that may sign
    /// `checkpoint` now; the key name is the log's origin (T20, L2-CKP-3). Without a key,
    /// nothing is signed (CR-23, G42).
    ///
    /// # Errors
    /// [`SignerError::Note`] for a body that is not a checkpoint of this domain,
    /// [`SignerError::NoKey`], [`SignerError::Usage`] or the signer's failure (an operational
    /// key that is not Ed25519 cannot sign a note).
    pub fn sign_note(&mut self, body: &str, now: u64) -> Result<Noted, SignerError> {
        let origin = crate::domain::origin(&self.template.domain);
        let cp = Checkpoint::parse(body).map_err(|_| SignerError::Note)?;
        if cp.origin != origin || cp.to_body().ok().as_deref() != Some(body) {
            return Err(SignerError::Note);
        }
        let (line, excerpt, _) = self.with_key(KeyUsage::Checkpoint, now, |signer, _| {
            sign_note(signer, &origin, body).map(|(_, line)| line)
        })?;
        Ok(Noted { line, excerpt })
    }

    /// Signs an access token's JSON `claims` at `now` as an `at+jwt` JWS with the key that may
    /// sign `token` now (§9.9.3 rule 7). The claims must bind a holder (`cnf`, PI-11) and carry
    /// an `exp` no later than the end of the key's publication, its window plus the retention
    /// (CR-19: `T_token < T_sign`). Without a key, nothing is signed (CR-23, G42).
    ///
    /// # Errors
    /// [`SignerError::Token`], [`SignerError::TokenHorizon`], [`SignerError::NoKey`],
    /// [`SignerError::Usage`] or the signer's failure.
    pub fn sign_token(&mut self, claims: &[u8], now: u64) -> Result<Token, SignerError> {
        let parsed = access_kernel::json::parse(claims, access_kernel::verify::jws::MAX_PAYLOAD)
            .map_err(|_| SignerError::Token)?;
        let exp_ms = parsed
            .get("exp")
            .and_then(access_kernel::json::Json::as_int)
            .and_then(|s| u64::try_from(s).ok())
            .and_then(|s| s.checked_mul(1000))
            .ok_or(SignerError::Token)?;
        let bound = matches!(
            parsed.get("cnf"),
            Some(access_kernel::json::Json::Object(m)) if !m.is_empty()
        );
        if !bound {
            return Err(SignerError::Token);
        }
        let retain = self.policy.retain_ms;
        let records = self.records();
        let until = rotation::signing_key(&records, &self.policy, now)
            .map(|k| k.valid_until.saturating_add(retain))
            .ok_or(SignerError::NoKey)?;
        if exp_ms > until {
            return Err(SignerError::TokenHorizon);
        }
        let (jws, excerpt, kid) = self.with_key(KeyUsage::Token, now, |signer, kid| {
            access_crypto::jose::sign_compact(signer, &kid, TOKEN_TYP, claims).map_err(
                |e| match e {
                    access_crypto::jose::JoseError::Sign(s) => s,
                    _ => SignError::Encode,
                },
            )
        })?;
        Ok(Token { jws, excerpt, kid })
    }

    fn with_key<T>(
        &mut self,
        usage: KeyUsage,
        now: u64,
        sign: impl FnOnce(&dyn Signer, [u8; 32]) -> Result<T, SignError>,
    ) -> Result<(T, Vec<u8>, [u8; 32]), SignerError> {
        self.with_key_in(false, usage, now, sign)
    }

    fn with_key_in<T>(
        &mut self,
        pq: bool,
        usage: KeyUsage,
        now: u64,
        sign: impl FnOnce(&dyn Signer, [u8; 32]) -> Result<T, SignError>,
    ) -> Result<(T, Vec<u8>, [u8; 32]), SignerError> {
        let records = self.records_in(pq);
        let kid = rotation::signing_key(&records, &self.policy, now)
            .map(|k| k.kid)
            .ok_or(SignerError::NoKey)?;
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record.kid == kid)
            .ok_or(SignerError::NoKey)?;
        if !entry.declared.usage.contains(&usage) {
            return Err(SignerError::Usage);
        }
        let (Some(signer), Some(excerpt)) = (entry.signer.as_deref(), entry.excerpt.clone()) else {
            return Err(SignerError::NoKey);
        };
        let out = sign(signer, kid)?;
        entry.record.signatures = entry.record.signatures.saturating_add(1);
        Ok((out, excerpt, kid))
    }

    /// The binding-signed Genesis statement, signed once at `now` and kept from then on.
    ///
    /// # Errors
    /// [`SignerError`] when the binding key cannot sign.
    pub fn genesis(&mut self, now: u64) -> Result<&[u8], SignerError> {
        if self.genesis.is_none() {
            let statement = crate::genesis::Statement {
                domain: self.template.domain,
                genesis: self.template.genesis,
                issued_at: now,
            };
            let bytes = statement.to_bytes().map_err(|_| SignerError::Encode)?;
            self.genesis = Some(self.binding_sign(crate::genesis::CONTENT_TYPE, &bytes)?);
        }
        self.genesis.as_deref().ok_or(SignerError::Encode)
    }

    /// The Genesis statement already signed, if any.
    #[must_use]
    pub fn genesis_signed(&self) -> Option<&[u8]> {
        self.genesis.as_deref()
    }

    /// Keeps a Genesis statement signed before a restart.
    pub fn keep_genesis(&mut self, signed: Vec<u8>) {
        self.genesis = Some(signed);
    }
}

/// `typ` of an authority-carrying access token (RFC 9068 §2.1).
pub const TOKEN_TYP: &str = "at+jwt";

/// An access token and the excerpt that declares its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The compact JWS.
    pub jws: String,
    /// Binding-signed excerpt of the operational key (CR-58 m.1).
    pub excerpt: Vec<u8>,
    /// The key's `kid`.
    pub kid: [u8; 32],
}

/// A note signature line and the excerpt that declares its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Noted {
    /// `— <origin> <base64>` with its newline (L2-CKP-2).
    pub line: String,
    /// Binding-signed excerpt of the operational key (CR-58 m.1).
    pub excerpt: Vec<u8>,
}

#[cfg(test)]
mod tests;
