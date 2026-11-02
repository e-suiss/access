//! The keyring of one domain: it follows the rotation schedule, keeps the binding-signed
//! metadata and excerpts current, and signs with the key that may sign now (CR-23, CR-25,
//! CR-27, SAI-46).

use access_kernel::codec::Canonical;
use access_kernel::verify::key_scope::{
    BindingKey, EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage, METADATA_CONTENT_TYPE, OperationalKey,
    thumbprint,
};
use suiss_crypto::rotation::{self, Key, Policy, State, Step};
use suiss_crypto::signer::{Signer, sign_sign1};

use crate::SignerError;
use crate::domain::{Template, binding, declaration, metadata};
use crate::ports::KeyFactory;

struct Entry {
    record: Key,
    declared: OperationalKey,
    signer: Option<Box<dyn Signer + Send>>,
    excerpt: Option<Vec<u8>>,
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
}

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
        }
    }

    fn records(&self) -> Vec<Key> {
        self.entries.iter().map(|e| e.record.clone()).collect()
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
    /// set changed; `draw` is a random value for the jitter of a new key.
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
        for step in rotation::plan(&self.records(), &self.policy, now, draw) {
            match &step {
                Step::Generate {
                    valid_from,
                    valid_until,
                    jitter_permille,
                } => {
                    let Ok(signer) = factory.generate(self.template.operational_alg) else {
                        round.outage = true;
                        continue;
                    };
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
                    };
                    let declared = declaration(&record, signer.algorithm(), key);
                    self.entries.push(Entry {
                        record,
                        declared,
                        signer: Some(signer),
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
            let mut records = self.records();
            rotation::apply(&mut records, &step, now);
            for (e, r) in self.entries.iter_mut().zip(records) {
                e.record = r;
                if e.record.state == State::Dropped {
                    e.signer = None;
                }
            }
            round.applied.push(step);
        }
        if published_changed {
            self.metadata = Some(self.sign_metadata(now)?);
        }
        Ok(round)
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
        let m = metadata(&self.template, &self.declared_binding, published, now);
        let bytes = m.to_bytes().map_err(|_| SignerError::Encode)?;
        self.binding_sign(METADATA_CONTENT_TYPE, &bytes)
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
        let records = self.records();
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
        let sign1 = sign_sign1(signer, kid, content_type, payload)?;
        entry.record.signatures = entry.record.signatures.saturating_add(1);
        Ok(Signed {
            sign1,
            excerpt,
            kid,
        })
    }
}

#[cfg(test)]
mod tests;
