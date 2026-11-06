//! Connectivity ceilings (§13.7.2, PD; §9.10 step 2; T20, U25, CR-K1): the local acceptance
//! ceilings a conformant verifier applies by connectivity variant and consequence tier,
//! whatever the artefact declares. The table is the Kernel's (`validity::ceiling`), so the
//! issuer and the verifier read the same one.

pub use access_kernel::validity::ceiling::{
    CT2_OFFLINE_EXTENSION_MS, Ceiling, EXACT_INTENT_HORIZON_MS, HOUR_MS, METADATA_FRESHNESS_MS,
    MINUTE_MS, REPORT_GRACE_MS, SECURE_CLOCK_CLASS, ct, ct2_offline_extension, policy,
    report_deadline, skew_ms,
};
