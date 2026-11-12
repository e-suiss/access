//! The advanced assurance codes (OP-159 m.3 (nn)): post-quantum keys, re-anchor and anchors,
//! algorithm and crypto profiles, projection references and WebAuthn attestation. Each is
//! catalogued before its lane returns it.

use super::{Code, code};

/// The HSM token offers no ML-DSA mechanism, so the post-quantum profile cannot be opened; nothing changed and no software key stands in (CR-18, OP-159 m.3 (d)).
pub const PQ_KEY_UNAVAILABLE: Code = code(
    "pq-key-unavailable",
    409,
    "Conflict",
    "The HSM token offers no ML-DSA mechanism, so the post-quantum profile cannot be opened; nothing changed and no software key stands in (CR-18, OP-159 m.3 (d)).",
);

/// No post-quantum re-anchor checkpoint covering the head with an independent witness's post-quantum cosign exists within the cadence, so the classical algorithm cannot be retired (CR-45 RA-6, OP-159 m.3 (f)).
pub const REANCHOR_REQUIRED: Code = code(
    "reanchor-required",
    409,
    "Conflict",
    "No post-quantum re-anchor checkpoint covering the head with an independent witness's post-quantum cosign exists within the cadence, so the classical algorithm cannot be retired (CR-45 RA-6, OP-159 m.3 (f)).",
);

/// The domain retired its classical algorithm and the verifier holds no pinned post-quantum anchor, so a classical artefact is refused (CR-45 RA-7, OP-159 m.3 (h)).
pub const PQ_ANCHOR_MISSING: Code = code(
    "pq-anchor-missing",
    422,
    "Unprocessable Content",
    "The domain retired its classical algorithm and the verifier holds no pinned post-quantum anchor, so a classical artefact is refused (CR-45 RA-7, OP-159 m.3 (h)).",
);

/// The domain declares the FIPS crypto profile, so ML-DSA cannot join its algorithm allowlist (CR-44, HL-27, OP-159 m.3 (r)).
pub const ALGORITHM_PROFILE_CONFLICT: Code = code(
    "algorithm-profile-conflict",
    409,
    "Conflict",
    "The domain declares the FIPS crypto profile, so ML-DSA cannot join its algorithm allowlist (CR-44, HL-27, OP-159 m.3 (r)).",
);

/// The realm's FIPS crypto profile and its post-quantum signing profile cannot both be on, whichever comes first (CR-44, HL-27, OP-159 m.3 (r)).
pub const FIPS_PQ_EXCLUSIVE: Code = code(
    "fips-pq-exclusive",
    409,
    "Conflict",
    "The realm's FIPS crypto profile and its post-quantum signing profile cannot both be on, whichever comes first (CR-44, HL-27, OP-159 m.3 (r)).",
);

/// The offline projection would exceed its carrier's size budget, so it is not produced (CR-43, OP-159 m.3 (p)).
pub const PROJECTION_OVER_BUDGET: Code = code(
    "projection-over-budget",
    422,
    "Unprocessable Content",
    "The offline projection would exceed its carrier's size budget, so it is not produced (CR-43, OP-159 m.3 (p)).",
);

/// The referenced projection expired and its blob was shredded; ask for a new projection (CR-43, OP-73, OP-159 m.3 (q)).
pub const PROJECTION_REF_EXPIRED: Code = code(
    "projection-ref-expired",
    410,
    "Gone",
    "The referenced projection expired and its blob was shredded; ask for a new projection (CR-43, OP-73, OP-159 m.3 (q)).",
);

/// The attestation statement's format is not supported or does not verify under the realm's direct attestation policy (§10.2.4, OP-159 m.3 (ll)).
pub const ATTESTATION_FORMAT: Code = code(
    "attestation-format",
    422,
    "Unprocessable Content",
    "The attestation statement's format is not supported or does not verify under the realm's direct attestation policy (§10.2.4, OP-159 m.3 (ll)).",
);

/// The revocation status of the attestation chain could not be read, so the direct attestation policy refuses the registration (§10.2.4, OP-159 m.3 (ll)).
pub const ATTESTATION_REVOCATION_UNKNOWN: Code = code(
    "attestation-revocation-unknown",
    422,
    "Unprocessable Content",
    "The revocation status of the attestation chain could not be read, so the direct attestation policy refuses the registration (§10.2.4, OP-159 m.3 (ll)).",
);
