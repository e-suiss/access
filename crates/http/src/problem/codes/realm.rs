//! The realm-admin surface's codes (OP-151 m.2 M1): what a realm resource write refuses.

use super::{Code, code};

/// The body is not the operation's JSON object, or names a member the operation does not take.
pub const INVALID_BODY: Code = code(
    "invalid-body",
    400,
    "Bad Request",
    "The body is not the operation's JSON object, or names a member the operation does not take.",
);
/// The write's intent validity is missing, malformed, inverted or longer than 15 minutes (TN-110).
pub const INVALID_VALIDITY: Code = code(
    "invalid-validity",
    400,
    "Bad Request",
    "The write's intent validity is missing, malformed, inverted or longer than 15 minutes (TN-110).",
);
/// A `client_id` that is not one the server generated (OP-137, TN-15).
pub const INVALID_CLIENT_ID: Code = code(
    "invalid-client-id",
    400,
    "Bad Request",
    "A client_id that is not one the server generated (OP-137, TN-15).",
);
/// An empty, too long or control-character display name.
pub const INVALID_DISPLAY_NAME: Code = code(
    "invalid-display-name",
    400,
    "Bad Request",
    "An empty, too long or control-character display name.",
);
/// A redirect URI that is not an exact, absolute, allowed URI, or too many (IDP-7, RFC 9700).
pub const INVALID_REDIRECT_URI: Code = code(
    "invalid-redirect-uri",
    400,
    "Bad Request",
    "A redirect URI that is not an exact, absolute, allowed URI, or too many (IDP-7, RFC 9700).",
);
/// A JWKS URI that is not https, or an authentication method without the fields it needs.
pub const INVALID_JWKS_URI: Code = code(
    "invalid-jwks-uri",
    400,
    "Bad Request",
    "A JWKS URI that is not https, or an authentication method without the fields it needs.",
);
/// A host name that is not a lower-case DNS name.
pub const INVALID_HOST: Code = code(
    "invalid-host",
    400,
    "Bad Request",
    "A host name that is not a lower-case DNS name.",
);
/// A claim name that is reserved or names authority (must-never #18, P55).
pub const RESERVED_CLAIM: Code = code(
    "reserved-claim",
    400,
    "Bad Request",
    "A claim name that is reserved or names authority (must-never #18, P55).",
);
/// A profile attribute outside the OpenID Connect standard claims (§9.9.6).
pub const INVALID_ATTRIBUTE: Code = code(
    "invalid-attribute",
    400,
    "Bad Request",
    "A profile attribute outside the OpenID Connect standard claims (§9.9.6).",
);
/// Argon2 parameters may only be raised (OP-33).
pub const ARGON2_LOWERED: Code = code(
    "argon-parameters-lowered",
    400,
    "Bad Request",
    "Argon2 parameters may only be raised (OP-33).",
);
/// An RP ID that is not the issuer's host or a parent domain of it (WebAuthn §5.1.4).
pub const INVALID_RP_ID: Code = code(
    "invalid-rp-id",
    400,
    "Bad Request",
    "An RP ID that is not the issuer's host or a parent domain of it (WebAuthn §5.1.4).",
);
/// Platform product fields are not written on the realm-admin surface (OP-149 m.4).
pub const PLATFORM_FIELDS_READ_ONLY: Code = code(
    "platform-fields-read-only",
    400,
    "Bad Request",
    "Platform product fields are not written on the realm-admin surface (OP-149 m.4).",
);
/// A public key that is not a usable Ed25519 or P-256 key, or a client key that is not P-256 (MD-3).
pub const INVALID_PUBLIC_KEY: Code = code(
    "invalid-public-key",
    400,
    "Bad Request",
    "A public key that is not a usable Ed25519 or P-256 key, or a client key that is not P-256 (MD-3).",
);
/// An event receiver that is not an https URL Access may push to (OP-149 m.23).
pub const INVALID_EVENT_RECEIVER: Code = code(
    "invalid-event-receiver",
    400,
    "Bad Request",
    "An event receiver that is not an https URL Access may push to (OP-149 m.23).",
);
/// Branding outside its fields' shapes, or a logo outside its CSP origins (TN-106).
pub const INVALID_BRANDING: Code = code(
    "invalid-branding",
    400,
    "Bad Request",
    "Branding outside its fields' shapes, or a logo outside its CSP origins (TN-106).",
);
/// A key rotation policy the realm may not take (CR-26, TN-118).
pub const INVALID_KEY_POLICY: Code = code(
    "invalid-key-policy",
    400,
    "Bad Request",
    "A key rotation policy the realm may not take (CR-26, TN-118).",
);
/// A group or upstream name outside ^[a-z][a-z0-9_-]{0,63}$.
pub const INVALID_NAME: Code = code(
    "invalid-name",
    400,
    "Bad Request",
    "A group or upstream name outside ^[a-z][a-z0-9_-]{0,63}$.",
);
/// A membership issuer that is not admin or upstream:<name>, or one that would change (TN-117).
pub const INVALID_MEMBERSHIP_ISSUER: Code = code(
    "invalid-membership-issuer",
    400,
    "Bad Request",
    "A membership issuer that is not admin or upstream:<name>, or one that would change (TN-117).",
);
/// No members, or more than 100 in one change.
pub const INVALID_MEMBERS: Code = code(
    "invalid-members",
    400,
    "Bad Request",
    "No members, or more than 100 in one change.",
);
/// An upstream registration outside its fields' shapes; its secret is a secret:// reference, never the secret (OP-150 m.11 (j)).
pub const INVALID_UPSTREAM: Code = code(
    "invalid-upstream",
    400,
    "Bad Request",
    "An upstream registration outside its fields' shapes; its secret is a secret:// reference, never the secret (OP-150 m.11 (j)).",
);
/// An upstream subject that is empty, longer than 255 bytes or has control characters.
pub const INVALID_UPSTREAM_SUBJECT: Code = code(
    "invalid-upstream-subject",
    400,
    "Bad Request",
    "An upstream subject that is empty, longer than 255 bytes or has control characters.",
);
/// The upstream subject is linked to another account; a link is never moved (TN-42).
pub const UPSTREAM_SUBJECT_LINKED: Code = code(
    "upstream-subject-linked",
    409,
    "Conflict",
    "The upstream subject is linked to another account; a link is never moved (TN-42).",
);
/// Sign-in requirements outside their shapes (TN-132).
pub const INVALID_SIGNIN_POLICY: Code = code(
    "invalid-signin-policy",
    400,
    "Bad Request",
    "Sign-in requirements outside their shapes (TN-132).",
);
/// A console session policy beyond 12 hours absolute or 15 minutes idle, or without a binding (TN-129, OP-151 m.3 (f)).
pub const INVALID_SESSION_POLICY: Code = code(
    "invalid-session-policy",
    400,
    "Bad Request",
    "A console session policy beyond 12 hours absolute or 15 minutes idle, or without a binding (TN-129, OP-151 m.3 (f)).",
);
/// A resource with this natural key exists, or existed and was retired; keys are never reused (OP-73).
pub const RESOURCE_EXISTS: Code = code(
    "resource-exists",
    409,
    "Conflict",
    "A resource with this natural key exists, or existed and was retired; keys are never reused (OP-73).",
);
/// The group's members are issued by an upstream provider, not by the administration (TN-117).
pub const MEMBERSHIP_ISSUED_UPSTREAM: Code = code(
    "membership-issued-upstream",
    409,
    "Conflict",
    "The group's members are issued by an upstream provider, not by the administration (TN-117).",
);
/// The account is not in a state the change leaves (§12.3.1, TN-49).
pub const ACCOUNT_STATE_CONFLICT: Code = code(
    "account-state-conflict",
    409,
    "Conflict",
    "The account is not in a state the change leaves (§12.3.1, TN-49).",
);
/// The client does not authenticate with a secret (CR-38).
pub const CLIENT_HAS_NO_SECRET: Code = code(
    "client-has-no-secret",
    409,
    "Conflict",
    "The client does not authenticate with a secret (CR-38).",
);
/// An RP ID change makes the realm's registered passkeys unusable; `acknowledge_passkey_loss` must equal their count (IDI-4).
pub const PASSKEY_LOSS_NOT_ACKNOWLEDGED: Code = code(
    "passkey-loss-not-acknowledged",
    409,
    "Conflict",
    "An RP ID change makes the realm's registered passkeys unusable; acknowledge_passkey_loss must equal their count (IDI-4).",
);
/// The resource changed while the write was applied; nothing changed.
pub const CONFLICT: Code = code(
    "conflict",
    409,
    "Conflict",
    "The resource changed while the write was applied; nothing changed.",
);
/// The operation named is not a realm write operation.
pub const UNKNOWN_OPERATION: Code = code(
    "unknown-operation",
    400,
    "Bad Request",
    "The operation named is not a realm write operation.",
);
/// A public `sub` without `public_sub_opt_in: true`, or an unknown subject type (MD-10).
pub const PUBLIC_SUB_NOT_OPTED_IN: Code = code(
    "public-sub-not-opted-in",
    400,
    "Bad Request",
    "A client reads pairwise subs unless subject_type is public and public_sub_opt_in is true (MD-10).",
);
/// A sector identifier URI that is not https, or whose document does not list every redirect URI.
pub const INVALID_SECTOR_IDENTIFIER_URI: Code = code(
    "invalid-sector-identifier-uri",
    400,
    "Bad Request",
    "The sector_identifier_uri is not https, or its document is not a JSON array of https URIs listing every redirect URI (OIDC Core 8.1).",
);
/// A declared operation that is reserved: it is never applied (OP-150 m.11 (b)).
pub const RESERVED_OPERATION: Code = code(
    "reserved-operation",
    501,
    "Not Implemented",
    "The operation is declared in the catalogue and reserved; it is never applied (OP-150 m.11 (b)).",
);
/// A JOSE algorithm other than ES256 or Ed25519 (MD-3, CR-5).
pub const INVALID_JOSE_ALG: Code = code(
    "invalid-jose-alg",
    400,
    "Bad Request",
    "The realm signs with ES256 or Ed25519; EdDSA is never named (MD-3, CR-5).",
);
/// A protection mode outside its model; brute-force protection is always enforced.
pub const INVALID_PROTECTION_MODE: Code = code(
    "invalid-protection-mode",
    400,
    "Bad Request",
    "Each protection is monitor or enforce, sl2 is shadow, stepup or stepup_caep, at most 1024 nonzero denied ASNs; brute-force protection is always enforce (OP-151 m.3 (o), TI-9).",
);
/// A job body that is not `{mode, operations}` with 1 to 100 items (TN-125).
pub const INVALID_JOB: Code = code(
    "invalid-job",
    400,
    "Bad Request",
    "A job is {mode: sequential or parallel, operations: 1 to 100 items of {operation, key, if_match, body with its ais}} (TN-125).",
);
/// An item that is not a realm write whose answer may be kept (TN-125).
pub const JOB_OPERATION_NOT_ALLOWED: Code = code(
    "job-operation-not-allowed",
    400,
    "Bad Request",
    "A job item is a realm write whose answer may be kept; a write that shows a secret once is sent on its own (TN-125, CR-38).",
);
/// The envelope's AIS does not sign this job's digest (TN-110, TN-125).
pub const JOB_INTENT_MISMATCH: Code = code(
    "job-intent-mismatch",
    400,
    "Bad Request",
    "The job's AIS does not sign the digest of its mode and items; draft it with POST intents (TN-110, TN-125).",
);
/// An item of a sequential job after a failed one (TN-125).
pub const FAILED_DEPENDENCY: Code = code(
    "failed-dependency",
    424,
    "Failed Dependency",
    "An earlier item of the sequential job did not commit, so this one was not run (TN-125).",
);
/// A hook or webhook URL that is not `https` on a DNS name, or a private target the realm does not allow or the operator did not declare (OP-151 m.10 (e), OP-149 m.23).
pub const INVALID_EXTENSION_TARGET: Code = code(
    "invalid-extension-target",
    400,
    "Bad Request",
    "A hook or webhook URL that is not https on a DNS name, or a private target the realm does not allow or the operator did not declare (OP-151 m.10 (e), OP-149 m.23).",
);
/// A hook registration outside its call point's contract (TN-135).
pub const INVALID_HOOK: Code = code(
    "invalid-hook",
    400,
    "Bad Request",
    "A hook registration outside its call point's contract (TN-135).",
);
/// A hook asks for personal data the realm's extension policy does not permit (OP-151 m.10 (e)).
pub const DISCLOSURE_NOT_PERMITTED: Code = code(
    "disclosure-not-permitted",
    400,
    "Bad Request",
    "A hook asks for personal data the realm's extension policy does not permit (OP-151 m.10 (e)).",
);
/// Webhook events outside the identity event catalogue (TN-136).
pub const INVALID_WEBHOOK_EVENTS: Code = code(
    "invalid-webhook-events",
    400,
    "Bad Request",
    "Webhook events outside the identity event catalogue (TN-136).",
);
/// An extension policy outside its shape (OP-151 m.10 (e)).
pub const INVALID_EXTENSION_POLICY: Code = code(
    "invalid-extension-policy",
    400,
    "Bad Request",
    "An extension policy outside its shape (OP-151 m.10 (e)).",
);
/// The call point has a live hook already; retire it first (OP-151 m.10 (d)).
pub const HOOK_POINT_TAKEN: Code = code(
    "hook-point-taken",
    409,
    "Conflict",
    "The call point has a live hook already; retire it first (OP-151 m.10 (d)).",
);
/// The realm's governing domain does not accept the catalog that declares the action yet; the
/// realm's catalog upgrade must commit first (OP-153 m.3 (a)).
pub const CATALOG_UPGRADE_REQUIRED: Code = code(
    "catalog-upgrade-required",
    409,
    "Conflict",
    "The realm does not accept this action's catalog yet; its catalog upgrade must commit first (OP-153 m.3 (a)).",
);
/// The change would leave the organization without an active owner (TN-91, OP-153 m.3 (p)).
pub const LAST_OWNER: Code = code(
    "last-owner",
    409,
    "Conflict",
    "The organization keeps at least one active owner on every path; add another owner first (TN-91).",
);
/// An audit stream rendering other than `ocsf`, `cef` or `set` (OP-41).
pub const INVALID_AUDIT_FORMAT: Code = code(
    "invalid-audit-format",
    400,
    "Bad Request",
    "An audit stream rendering other than ocsf, cef or set (OP-41).",
);
/// A recovery policy outside its ranges, or below the cooling table's floor (TN-55).
pub const INVALID_RECOVERY_POLICY: Code = code(
    "invalid-recovery-policy",
    400,
    "Bad Request",
    "A recovery policy outside its ranges, or a cooling entry below the floor of the realm default (TN-55, OP-153 m.3 (e)).",
);
/// The realm does not allow temporary access passes, or the account turned assisted recovery
/// off (TN-60, TN-62).
pub const RECOVERY_OPTION_OFF: Code = code(
    "recovery-option-off",
    409,
    "Conflict",
    "The realm does not allow temporary access passes, or the account turned assisted recovery off (TN-60, TN-62).",
);
/// Nobody issues a reset intent or a temporary access pass for their own account (TN-62).
pub const SELF_ISSUE_REFUSED: Code = code(
    "self-issue-refused",
    403,
    "Forbidden",
    "Nobody issues a reset intent or a temporary access pass for their own account (TN-62).",
);
/// The Party is not a live organization Party of the realm's governing domain (OP-153 m.3 (b)).
pub const NOT_AN_ORGANIZATION: Code = code(
    "not-an-organization",
    409,
    "Conflict",
    "The Party is not a live organization Party of the realm's governing domain (OP-153 m.3 (b)).",
);
