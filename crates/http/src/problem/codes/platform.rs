//! The platform-admin surface's codes (OP-151 m.2 M2): what a provisioning write refuses.

use super::{Code, code};

/// A slug outside the realm slug grammar (TN-16).
pub const INVALID_SLUG: Code = code(
    "invalid-slug",
    400,
    "Bad Request",
    "A slug outside `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$` (TN-16).",
);
/// A placement outside the placement grammar (OP-40).
pub const INVALID_PLACEMENT: Code = code(
    "invalid-placement",
    400,
    "Bad Request",
    "A placement outside `^[a-z0-9][a-z0-9-]{0,62}$` (OP-40).",
);
/// A founding root that names no Party, or a joint root below two or above its Parties.
pub const INVALID_ROOT: Code = code(
    "invalid-root",
    400,
    "Bad Request",
    "The founding root names no Party, or is a joint root with k below 2 or above its Parties; Joint(k >= 2) is recommended (TN-111, §13.7.7).",
);
/// A sole founding root without the no-recovery acknowledgement.
pub const RECOVERY_NOT_ACKNOWLEDGED: Code = code(
    "recovery-not-acknowledged",
    400,
    "Bad Request",
    "A sole founding root cannot be recovered; the request must carry acknowledge_no_recovery: true (TN-111, TN-60, §13.7.7).",
);
/// A CT3 time-lock outside one hour to thirty days.
pub const INVALID_TIME_LOCK: Code = code(
    "invalid-time-lock",
    400,
    "Bad Request",
    "The CT3 time-lock is outside one hour to thirty days (OP-141 m.34 (d)).",
);
/// The slug is taken, now or by a deleted realm.
pub const SLUG_TAKEN: Code = code(
    "slug-taken",
    409,
    "Conflict",
    "The slug is taken, now or by a deleted realm; slugs are never reused (TN-16, INV-32).",
);
