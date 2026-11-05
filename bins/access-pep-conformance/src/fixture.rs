//! The domain the fake ADP speaks for: Domain Metadata and a signed receipt from the
//! L2-RCP-3 vectors, so the PEP under test verifies real Kernel artefacts.

use serde::Deserialize;

const RECEIPTS: &str = include_str!("../../../conformance/vectors/core/1/receipt.json");

/// Why the fixture cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// The vector file is not what the harness expects.
    #[error("receipt vectors: {0}")]
    Vectors(&'static str),
    /// The vector file is not JSON.
    #[error("receipt vectors: {0}")]
    Json(#[from] serde_json::Error),
}

/// The pinned domain, the receipt the healthy ADP returns and the time it is valid at.
#[derive(Clone, Debug)]
pub struct Fixture {
    /// Verified `domain-metadata` (CBOR) the PEP is configured with.
    pub metadata: Vec<u8>,
    /// The domain ID (CBOR digest).
    pub domain: Vec<u8>,
    /// The PEP audience the receipt is for.
    pub audience: String,
    /// The intent digest (CBOR) the receipt is for.
    pub intent: Vec<u8>,
    /// Trusted time, Unix milliseconds, at which the receipt verifies.
    pub now: u64,
    /// The receipt `COSE_Sign1`.
    pub sign1: Vec<u8>,
    /// Its key excerpt.
    pub excerpt: Vec<u8>,
}

#[derive(Deserialize)]
struct Vectors {
    metadata: String,
    cases: Vec<VectorCase>,
}

#[derive(Deserialize)]
struct VectorCase {
    id: String,
    excerpt: String,
    sign1: String,
    domain: String,
    audience: String,
    intent: String,
    now: u64,
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

impl Fixture {
    /// Reads the fixture from the committed receipt vectors.
    ///
    /// # Errors
    /// [`FixtureError`].
    pub fn load() -> Result<Self, FixtureError> {
        let v: Vectors = serde_json::from_str(RECEIPTS)?;
        let case = v
            .cases
            .into_iter()
            .find(|c| c.id == "valid")
            .ok_or(FixtureError::Vectors("no `valid` case"))?;
        let field = |s: &str| unhex(s).ok_or(FixtureError::Vectors("not hex"));
        Ok(Self {
            metadata: field(&v.metadata)?,
            domain: field(&case.domain)?,
            audience: case.audience,
            intent: field(&case.intent)?,
            now: case.now,
            sign1: field(&case.sign1)?,
            excerpt: field(&case.excerpt)?,
        })
    }
}
