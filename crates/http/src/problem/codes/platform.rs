//! The platform-admin surface's codes (OP-151 m.2 M2) and the tenant administration's (OP-159 m.47):
//! what a provisioning, founding or tenant write refuses.

use super::{Code, code};

/// A slug outside the environment slug grammar (TN-16).
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
/// The slug is taken, now or by a deleted environment.
pub const SLUG_TAKEN: Code = code(
    "slug-taken",
    409,
    "Conflict",
    "The slug is taken, now or by a deleted environment; slugs are never reused (TN-16, INV-32).",
);
/// A tenant display name that is empty, too long or has control characters (TN-131).
pub const INVALID_TENANT_NAME: Code = code(
    "invalid-tenant-name",
    400,
    "Bad Request",
    "The tenant's display name is 1 to 120 characters without control characters or surrounding white space (TN-131).",
);
/// An address that is not one (TN-89 (4)).
pub const INVALID_EMAIL: Code = code(
    "invalid-email",
    400,
    "Bad Request",
    "The address is not an e-mail address (TN-89 (4)).",
);
/// The tenant is not in the state the change needs.
pub const TENANT_STATE: Code = code(
    "tenant-state",
    409,
    "Conflict",
    "The tenant is not in the state this change needs: a new tenant exists already, a reinvitation is only for a tenant awaiting its founder, a suspension only for an active one, a reactivation only for a suspended one (OP-159 m.47 (c), (h)).",
);
/// A tenant write sent to an environment that is not the tenant's management environment, or a
/// third-party client in a management environment.
pub const MANAGEMENT_ENVIRONMENT: Code = code(
    "management-environment",
    409,
    "Conflict",
    "Tenant administration happens in the tenant's management environment, and a management environment keeps only the first-party console and account clients (TN-138, OP-159 m.47 (b)).",
);
/// The founder invitation expired.
pub const FOUNDING_EXPIRED: Code = code(
    "founding-expired",
    410,
    "Gone",
    "The founder invitation expired; the platform can send a new one (TN-141).",
);
/// A founding step out of order.
pub const FOUNDING_STATE: Code = code(
    "founding-state",
    409,
    "Conflict",
    "The founding is completed already, or its address is not proven yet (TN-141).",
);
/// The address or the code does not match the founder invitation.
pub const INVALID_CODE: Code = code(
    "invalid-code",
    400,
    "Bad Request",
    "The address or the code does not match the invitation (TN-89 (5)).",
);
/// The tenant's last owner cannot be removed.
pub const LAST_TENANT_OWNER: Code = code(
    "last-tenant-owner",
    409,
    "Conflict",
    "The tenant keeps at least one owner; make another administrator an owner first (OP-159 m.47 (e)).",
);
/// The tenant administrator invitation expired.
pub const INVITE_EXPIRED: Code = code(
    "invite-expired",
    410,
    "Gone",
    "The administrator invitation expired; an administrator can invite again (OP-159 m.47 (f), TN-89).",
);
/// A tenant administrator invitation step out of order.
pub const INVITE_STATE: Code = code(
    "invite-state",
    409,
    "Conflict",
    "The invitation is accepted or replaced already, its address is not proven yet, the address has an account in the management environment, or the inviter is no administrator any more (OP-159 m.47 (f), TN-89 (3), (7)).",
);
