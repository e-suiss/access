//! Access digest contexts over the shared digest and Merkle primitives (OP-106, OP-140 m.2).

pub use suiss_crypto::digest::{
    BODY, Digest, FIELD, Hash, LEAF, MAX_PROOF, NODE, ProofError, SHA256_ALG, body_commit,
    field_commit, leaf_hash, node_hash, root, verify_consistency, verify_inclusion,
};

/// What a digest is of; each kind hashes under its own context string (OP-106 m.22).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// `IntentEnvelope`.
    Intent,
    /// Genesis record without `domain`; the result is the `DomainID` (OP-106 m.10).
    Genesis,
}

impl Context {
    /// The context string.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Intent => "access/intent/v1",
            Self::Genesis => "access/genesis/v1",
        }
    }
}

/// `SHA-256(context ‖ 0x00 ‖ canonical bytes)`.
#[must_use]
pub fn digest(context: Context, canonical: &[u8]) -> Digest {
    suiss_crypto::digest::context_digest(context.label(), canonical)
}

/// Domain identifier: the `access/genesis/v1` digest of the Genesis `record-envelope`, which has no
/// `domain` field (OP-106 m.10, OP-117 m.2).
#[must_use]
pub fn domain_id(genesis_envelope: &[u8]) -> Digest {
    digest(Context::Genesis, genesis_envelope)
}

/// Digest context of a support case reference (OP-157 m.3 (b), TN-73).
pub const CASE_REF: &str = "access/case-ref/v1";

/// `SHA-256("access/case-ref/v1" ‖ 0x00 ‖ dCBOR([system, case]))`, the value of
/// [`crate::model::PurposeRef::Case`]: the Kernel holds no case number (§5.3).
///
/// # Errors
/// The texts are outside the structural limits.
pub fn case_ref(system: &str, case: &str) -> Result<Digest, suiss_crypto::dcbor::EncodeError> {
    use suiss_crypto::dcbor::{self, Limits, Value};
    let bytes = dcbor::encode(
        &Value::Array(alloc::vec![Value::text(system), Value::text(case)]),
        Limits::CEILING,
    )?;
    Ok(suiss_crypto::digest::context_digest(CASE_REF, &bytes))
}

#[cfg(test)]
mod tests;
