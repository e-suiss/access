//! The durability, scale and transparency codes (OP-158 m.3 (aa)): checkpoints and witnesses,
//! handover and recovery, cells and placement, the read path, limits, upgrade, restore and the
//! degraded identity plane. Each is catalogued before its lane returns it.

use super::{Code, code};

/// The recovery cites a checkpoint below R*, the highest witnessed checkpoint the records reproduce; nothing changed (SEC21, SEC22, OP-158 m.3 (b)).
pub const ROLLBACK_GUARD: Code = code(
    "rollback-guard",
    409,
    "Conflict",
    "The recovery cites a checkpoint below R*, the highest witnessed checkpoint the records reproduce; nothing changed (SEC21, SEC22, OP-158 m.3 (b)).",
);

/// The domain has no recovery entry, so forced recovery is not available (§13.6, OP-158 m.3 (m)).
pub const RECOVERY_UNAVAILABLE: Code = code(
    "recovery-unavailable",
    409,
    "Conflict",
    "The domain has no recovery entry, so forced recovery is not available (§13.6, OP-158 m.3 (m)).",
);

/// The recovery entry has too few hardware-bound keys, a threshold out of range or a key held by the provider or its operator (SEC20, U16).
pub const RECOVERY_ENTRY_INVALID: Code = code(
    "recovery-entry-invalid",
    422,
    "Unprocessable Content",
    "The recovery entry has too few hardware-bound keys, a threshold out of range or a key held by the provider or its operator (SEC20, U16).",
);

/// The domain is frozen for a handover; no write commits until the handover ends (OP-158 m.3 (l)).
pub const HANDOVER_FROZEN: Code = code(
    "handover-frozen",
    409,
    "Conflict",
    "The domain is frozen for a handover; no write commits until the handover ends (OP-158 m.3 (l)).",
);

/// The incoming provider has not passed the provider conformance profile; the export was given and no handover batch was written (OP-158 m.3 (l)).
pub const PROVIDER_NOT_CONFORMANT: Code = code(
    "provider-not-conformant",
    409,
    "Conflict",
    "The incoming provider has not passed the provider conformance profile; the export was given and no handover batch was written (OP-158 m.3 (l)).",
);

/// The domain is sealed for a cell move; it commits again once the target cell accepts it (OP-158 m.3 (n)).
pub const DOMAIN_SEALED: Code = code(
    "domain-sealed",
    409,
    "Conflict",
    "The domain is sealed for a cell move; it commits again once the target cell accepts it (OP-158 m.3 (n)).",
);

/// This cell is not the domain's or realm's placement; ask the cell the placement names (TI-17, OP-158 m.3 (o)).
pub const PLACEMENT_MISMATCH: Code = code(
    "placement-mismatch",
    421,
    "Misdirected Request",
    "This cell is not the domain's or realm's placement; ask the cell the placement names (TI-17, OP-158 m.3 (o)).",
);

/// A realm rehome needs an Exercise in both the old and the new governing domain; the realm stays where it is (OP-158 m.3 (o)).
pub const REHOME_INCOMPLETE: Code = code(
    "rehome-incomplete",
    409,
    "Conflict",
    "A realm rehome needs an Exercise in both the old and the new governing domain; the realm stays where it is (OP-158 m.3 (o)).",
);

/// The as_of position is outside the 24 hour history window, or its snapshot expired (OP-158 m.3 (u)).
pub const AS_OF_EXPIRED: Code = code(
    "as-of-expired",
    409,
    "Conflict",
    "The as_of position is outside the 24 hour history window, or its snapshot expired (OP-158 m.3 (u)).",
);

/// The relationship index quota (depth 25, width 10, 1 000 tuples per write, 200 types per store) was exceeded; nothing was recorded (§9.7A.5, OP-158 m.3 (u)).
pub const INDEX_QUOTA_EXCEEDED: Code = code(
    "index-quota-exceeded",
    422,
    "Unprocessable Content",
    "The relationship index quota (depth 25, width 10, 1 000 tuples per write, 200 types per store) was exceeded; nothing was recorded (§9.7A.5, OP-158 m.3 (u)).",
);

/// A password hash profile can be raised and never lowered (OP-33, OP-158 m.3 (a)).
pub const HASH_PROFILE_DOWNGRADE: Code = code(
    "hash-profile-downgrade",
    409,
    "Conflict",
    "A password hash profile can be raised and never lowered (OP-33, OP-158 m.3 (a)).",
);

/// The hot audit window is shorter than 30 days (OP-37, OP-158 m.3 (a), (w)).
pub const AUDIT_TIER_TOO_SHORT: Code = code(
    "audit-tier-too-short",
    422,
    "Unprocessable Content",
    "The hot audit window is shorter than 30 days (OP-37, OP-158 m.3 (a), (w)).",
);

/// An export of this domain is already streaming; resume it from its last position (OP-158 m.3 (g)).
pub const EXPORT_IN_PROGRESS: Code = code(
    "export-in-progress",
    409,
    "Conflict",
    "An export of this domain is already streaming; resume it from its last position (OP-158 m.3 (g)).",
);

/// The record is committed and effective; its acknowledgement waits for a witness cosign and the replica (SEC23, CL-2, OP-158 m.3 (e)).
pub const WITNESS_PENDING: Code = code(
    "witness-pending",
    409,
    "Conflict",
    "The record is committed and effective; its acknowledgement waits for a witness cosign and the replica (SEC23, CL-2, OP-158 m.3 (e)).",
);

/// The release cannot join the running set: its semantics, schema or wire versions do not overlap (OP-56, OP-158 m.3 (q)).
pub const UPGRADE_INCOMPATIBLE: Code = code(
    "upgrade-incompatible",
    409,
    "Conflict",
    "The release cannot join the running set: its semantics, schema or wire versions do not overlap (OP-56, OP-158 m.3 (q)).",
);

/// The environment was restored and its crypto-shredding has not been re-applied; writes stay refused (OP-42, OP-158 m.3 (r)).
pub const RESTORE_RESHRED_PENDING: Code = code(
    "restore-reshred-pending",
    503,
    "Service Unavailable",
    "The environment was restored and its crypto-shredding has not been re-applied; writes stay refused (OP-42, OP-158 m.3 (r)).",
);

/// Sign-in isn't available right now; tokens already issued keep working within their lifetime (OP-45, OP-158 m.3 (s)).
pub const DEGRADED_IDENTITY: Code = code(
    "degraded-identity",
    503,
    "Service Unavailable",
    "Sign-in isn't available right now; tokens already issued keep working within their lifetime (OP-45, OP-158 m.3 (s)).",
);

/// A tenant, realm or domain quota was reached; narrowing actions, export, handover and recovery are never counted (T27, OP-158 m.3 (v)).
pub const QUOTA_EXCEEDED: Code = code(
    "quota-exceeded",
    429,
    "Too Many Requests",
    "A tenant, realm or domain quota was reached; narrowing actions, export, handover and recovery are never counted (T27, OP-158 m.3 (v)).",
);
