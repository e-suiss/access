//! Workload identity and hardware attestation checks of the identity plane (§11.12, AG-30,
//! AG-31, L21, L25, OP-154 m.3 (r), (s)), free of I/O (OP-63).
//!
//! What a workload or a device proves enters Access only as a Claim (U20): a verified SPIFFE
//! or WIMSE credential becomes the realm issuer's `identity_binding_workload` Claim and a
//! verified hardware attestation its `attestation_runtime` Claim. Nothing here decides
//! authority; a Grant is always needed as well.
//!
//! - [`domain::workload`]: hierarchical `spiffe://` and `wimse://` identifiers and the selectors over
//!   them; a wildcard never grants.
//! - [`domain::bundle`]: SPIFFE bundles, their refresh interval and when a stale one stops verifying.
//! - [`domain::svid`]: JWT-SVID and X.509-SVID checks.
//! - [`domain::android`], [`domain::apple`], [`domain::tpm`]: the hardware attestation checklists, over the roots in
//!   [`domain::roots`].
//! - [`domain::runtime`]: the attested runtime class, the attester model, the narrowing device signals
//!   and the three records an agent's Instance is kept apart from.
//! - [`app`]: a workload credential checked against its trust domain's current bundle, which
//!   [`ports::Bundles`] keeps and fetches.

pub mod app;
pub mod domain;
pub mod ports;

/// Why an attestation is not accepted; a decision, not an infrastructure error (OP-64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttestError {
    /// The evidence is not well formed.
    #[error("malformed evidence")]
    Format,
    /// The certificate chain does not verify to an embedded root.
    #[error("certificate chain")]
    Chain,
    /// A required certificate property is missing or wrong.
    #[error("certificate")]
    Certificate,
    /// The challenge or nonce the evidence binds is not the expected one.
    #[error("challenge")]
    Challenge,
    /// The key is not the one the evidence names.
    #[error("key")]
    Key,
    /// The signature does not verify.
    #[error("signature")]
    Signature,
    /// The attested properties are weaker than the policy asks.
    #[error("policy")]
    Policy,
}

impl AttestError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Format => "attestation-format",
            Self::Chain => "attestation-chain",
            Self::Certificate => "attestation-certificate",
            Self::Challenge => "attestation-challenge",
            Self::Key => "attestation-key",
            Self::Signature => "attestation-signature",
            Self::Policy => "attestation-policy",
        }
    }
}
