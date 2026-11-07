//! The domain the fake upstreams speak for (OP-150 m.1 (a)): a binding key, operational keys
//! for receipts, tokens and status lists, the holder key the tokens are bound to, and the
//! one intent the cases enforce. Generated per run, so receipts bind to the request nonce and
//! tokens are real `at+jwt` projections (L2-RCP-3, L2-JOS-1).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::verify::cose::{Algorithm, PublicKey};
use access_kernel::verify::key_scope::{
    BindingKey, BindingScope, DomainMetadata, EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage,
    METADATA_CONTENT_TYPE, OperationalKey, SpecVersions, thumbprint,
};
use suiss_crypto::signer::{SignError, Signer, SoftSigner, sign_sign1};

/// The PEP / resource server audience of the healthy cases.
pub const AUDIENCE: &str = "pep.example";

/// The actor's pairwise pseudonym in tokens.
pub const ACTOR: &str = "conformance-actor";

/// The OAuth client of the tokens.
pub const CLIENT: &str = "conformance";

/// Trusted time of every case, Unix milliseconds (10:30).
pub const NOW: u64 = 37_800_000;

/// Operational key window half-width.
const HALF_WINDOW_MS: u64 = 30 * 60 * 1000;

/// Why the fixture cannot be built.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// Key generation or signing failed.
    #[error("signing: {0}")]
    Sign(#[from] SignError),
    /// A model value could not be encoded.
    #[error("encoding: {0}")]
    Encode(#[from] suiss_crypto::dcbor::EncodeError),
    /// A key is not Ed25519.
    #[error("not an Ed25519 key")]
    Key,
}

/// The domain, its keys and the intent.
pub struct Fixture {
    /// Verified `domain-metadata` (CBOR) the PEP is configured with.
    pub metadata: Vec<u8>,
    /// The same metadata as the domain serves it: a `COSE_Sign1` by the binding key (CR-58).
    pub signed_metadata: Vec<u8>,
    /// The domain ID.
    pub domain: Digest,
    /// The PEP audience the receipts and tokens are for.
    pub audience: String,
    /// The intent the effect applies.
    pub envelope: IntentEnvelope,
    /// Its digest.
    pub intent: Digest,
    /// Trusted time of the cases.
    pub now: u64,
    binding: SoftSigner,
    receipt: SoftSigner,
    token: SoftSigner,
    list: SoftSigner,
    holder: SoftSigner,
    other: SoftSigner,
    receipt_excerpt: Vec<u8>,
}

impl std::fmt::Debug for Fixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fixture")
            .field("domain", &self.domain)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(d));
            }
        }
    }
    out
}

/// Decodes hex; `None` when it is not hex.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[h, l]| Some(digit(*h)? << 4 | digit(*l)?))
        .collect()
}

fn generate() -> Result<SoftSigner, FixtureError> {
    Ok(SoftSigner::generate_ed25519()?.0)
}

fn operational(signer: &SoftSigner, usage: KeyUsage) -> OperationalKey {
    let key = signer.public_key();
    OperationalKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        valid_from: NOW.saturating_sub(HALF_WINDOW_MS),
        valid_until: NOW.saturating_add(HALF_WINDOW_MS),
        usage: BTreeSet::from([usage]),
    }
}

/// The action the cases enforce.
#[must_use]
pub fn action() -> ActionRef {
    ActionRef {
        namespace: "door".to_owned(),
        name: "open".to_owned(),
        major: 1,
        schema: Digest([9; 32]),
    }
}

fn envelope() -> IntentEnvelope {
    IntentEnvelope {
        action: action(),
        resources: vec![ResourceRef {
            namespace: "door".to_owned(),
            path: vec!["1".to_owned()],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: NOW.saturating_mul(2),
        },
    }
}

impl Fixture {
    /// Generates the domain.
    ///
    /// # Errors
    /// [`FixtureError`].
    pub fn generate() -> Result<Self, FixtureError> {
        let binding = generate()?;
        let receipt = generate()?;
        let token = generate()?;
        let list = generate()?;
        let holder = generate()?;
        let other = generate()?;
        let domain = Digest([1; 32]);
        let binding_key = BindingKey {
            kid: thumbprint(&binding.public_key()),
            alg: Algorithm::Ed25519,
            key: binding.public_key(),
            scope: BindingScope::Domain,
            superseded: None,
        };
        let metadata = DomainMetadata {
            domain,
            genesis: Digest([2; 32]),
            issued_at: NOW.saturating_sub(HALF_WINDOW_MS),
            binding: BTreeMap::from([(binding_key.kid, binding_key.clone())]),
            algorithms: BTreeSet::from([Algorithm::Ed25519]),
            operational_window_max_ms: 2 * HALF_WINDOW_MS,
            operational_keys: vec![
                operational(&receipt, KeyUsage::Receipt),
                operational(&token, KeyUsage::Token),
                operational(&list, KeyUsage::StatusList),
            ],
            min_versions: SpecVersions::default(),
            adopted: SpecVersions::default(),
            caps: None,
            hybrid: None,
            discovery: None,
        };
        let excerpt = KeyExcerpt {
            domain,
            key: operational(&receipt, KeyUsage::Receipt),
        };
        let receipt_excerpt = sign_sign1(
            &binding,
            binding_key.kid,
            EXCERPT_CONTENT_TYPE,
            &excerpt.to_bytes()?,
        )?;
        let envelope = envelope();
        let signed_metadata = sign_sign1(
            &binding,
            binding_key.kid,
            METADATA_CONTENT_TYPE,
            &metadata.to_bytes()?,
        )?;
        Ok(Self {
            metadata: metadata.to_bytes()?,
            signed_metadata,
            domain,
            audience: AUDIENCE.to_owned(),
            intent: intent_digest(&envelope)?,
            envelope,
            now: NOW,
            binding,
            receipt,
            token,
            list,
            holder,
            other,
            receipt_excerpt,
        })
    }

    /// Signs a receipt payload with the domain's receipt key; returns the `COSE_Sign1` and the
    /// binding-signed key excerpt (L2-RCP-2).
    ///
    /// # Errors
    /// [`FixtureError::Sign`].
    pub fn sign_receipt(&self, payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FixtureError> {
        let kid = thumbprint(&self.receipt.public_key());
        let sign1 = sign_sign1(
            &self.receipt,
            kid,
            access_kernel::receipt::CONTENT_TYPE,
            payload,
        )?;
        Ok((sign1, self.receipt_excerpt.clone()))
    }

    /// The token signing key, declared for `token` in the Domain Metadata (§10.4.5).
    #[must_use]
    pub fn token_signer(&self) -> &SoftSigner {
        &self.token
    }

    /// The holder key the tokens are bound to.
    #[must_use]
    pub fn holder(&self) -> &SoftSigner {
        &self.holder
    }

    /// A key that is nobody's: proofs signed with it must be refused.
    #[must_use]
    pub fn other(&self) -> &SoftSigner {
        &self.other
    }

    /// The status list signing key.
    #[must_use]
    pub fn list_signer(&self) -> &SoftSigner {
        &self.list
    }

    /// The binding key.
    #[must_use]
    pub fn binding(&self) -> &SoftSigner {
        &self.binding
    }

    /// The actor's party.
    #[must_use]
    pub fn actor_party() -> Id {
        Id([5; 16])
    }
}

/// The raw Ed25519 public key of a signer.
///
/// # Errors
/// [`FixtureError::Key`] for another key type.
pub fn ed25519_public(signer: &SoftSigner) -> Result<[u8; 32], FixtureError> {
    match signer.public_key() {
        PublicKey::Ed25519(pk) => Ok(pk),
        _ => Err(FixtureError::Key),
    }
}
