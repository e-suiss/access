//! What Access is not (IDP-34, §10.3.1, Ek B "KYC uygulaması değil"): it reads, chips, faces or
//! liveness of no one. Remote identity proofing happens at an external provider, and its result
//! is that provider's `identity_proofing` Claim. `cargo xtask check kyc-boundary` keeps these
//! capabilities out of the code.

/// The proofing capabilities Access never implements: an NFC chip read, a face match, a
/// liveness check and a remote identity proofing session of its own.
pub const NOT_IMPLEMENTED: [&str; 4] = ["nfc-chip-read", "face-match", "liveness", "remote-idv"];

/// Whether Access claims a proofing method of its own: never. A proofing level comes only from
/// an accepted `identity_proofing` Claim of an external source.
#[must_use]
pub const fn proofs_identity_itself() -> bool {
    false
}
