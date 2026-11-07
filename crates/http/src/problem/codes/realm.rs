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
