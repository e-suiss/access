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
/// N5: a Related Origins list that is not `https` origins, names more than five registrable
/// labels with the RP ID, or an origin outside the realm's verified domains (TN-18,
/// OP-153 m.3 (u)).
pub const INVALID_RELATED_ORIGINS: Code = code(
    "invalid-related-origins",
    400,
    "Bad Request",
    "A Related Origins list that is not https origins, names more than five registrable labels with the RP ID, or an origin outside the realm's verified domains (TN-18, OP-153 m.3 (u)).",
);
/// N5: message overrides naming a protected or unknown key, or text that is not plain (X35,
/// XI-25, OP-153 m.3 (s)).
pub const INVALID_LOCALE_OVERRIDES: Code = code(
    "invalid-locale-overrides",
    400,
    "Bad Request",
    "Message overrides naming a protected or unknown key, or text that is not plain (X35, XI-25, OP-153 m.3 (s)).",
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
/// A certificate sign-in setting outside its model (OP-155 m.3 (m)).
pub const INVALID_CERTIFICATE_LOGIN: Code = code(
    "invalid-certificate-login",
    400,
    "Bad Request",
    "Certificate sign-in names its rule (san_email or san_upn), 1 to 16 distinct CA certificates as base64url DER of at most 8 KB while on, and at most 16 issuer policy OIDs in dotted form (OP-155 m.3 (m)).",
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
/// A malformed agent: kind, operator, name, description or sponsors (OP-154 m.3 (c), (e)).
pub const INVALID_AGENT: Code = code(
    "invalid-agent",
    400,
    "Bad Request",
    "The agent is malformed: an unknown kind, an operator that is no live organization or person, a bad name or description, or no distinct active sponsor (OP-154 m.3 (c), (e)).",
);
/// An agent Grant template outside OP-154 m.3 (g).
pub const INVALID_AGENT_TEMPLATE: Code = code(
    "invalid-agent-template",
    400,
    "Bad Request",
    "An agent Grant template needs its budget (a count per window, and for consumption a cap per intent and a daily window), at most one delegation hop and no core meta-action (OP-154 m.3 (g), RR-12).",
);
/// A workload client outside OP-154 m.3 (r).
pub const INVALID_WORKLOAD_CLIENT: Code = code(
    "invalid-workload-client",
    400,
    "Bad Request",
    "A workload client names a SPIFFE ID or a whole-segment prefix ending in /*, an https Bundle Endpoint and its agent, and no redirect URI (OP-154 m.3 (r), §11.12.1).",
);
/// A protected resource that is not a canonical `https` URI, or a display name outside 1–128
/// printable characters (AG-8, RFC 8707 §2).
pub const INVALID_PROTECTED_RESOURCE: Code = code(
    "invalid-protected-resource",
    400,
    "Bad Request",
    "A protected resource is a canonical https URI without query, fragment or trailing slash, and a display name of 1 to 128 printable characters (AG-8, RFC 8707 §2).",
);
/// A DCR policy outside OP-154 m.3 (j).
pub const INVALID_DCR_POLICY: Code = code(
    "invalid-dcr-policy",
    400,
    "Bad Request",
    "A DCR policy names whether registration is open, at most 64 redirect domains and at most 16 initial access tokens as unpadded base64url SHA-256 digests; an open policy names at least one (OP-154 m.3 (j)).",
);
/// A client profile outside OP-155 m.3 (k).
pub const INVALID_CLIENT_PROFILE: Code = code(
    "invalid-client-profile",
    400,
    "Bad Request",
    "A client profile names FAPI 2.0 only for a confidential private_key_jwt or mutual TLS client without RS256 or the bearer exception, client_secret_post only over a registered secret, an ID token algorithm the realm serves, an encryption key for ECDH-ES+A256KW or RSA-OAEP-256 and something to encrypt, or an upstream by name (OP-155 m.3 (k)).",
);
/// A cross-app connection outside OP-154 m.3 (n).
pub const INVALID_CROSS_APP_CONNECTION: Code = code(
    "invalid-cross-app-connection",
    400,
    "Bad Request",
    "A cross-app connection names a slug, a registered client, the Resource authorization server's issuer and the resource there as canonical https URIs, at most 64 scopes as a hint, and the pairwise subject policy (OP-154 m.3 (n), AG-28).",
);
/// A vault Resource outside OP-154 m.3 (t), or an upstream the catalog does not have.
pub const INVALID_VAULT_RESOURCE: Code = code(
    "invalid-vault-resource",
    400,
    "Bad Request",
    "The vault Resource is malformed: an upstream the catalog does not have or an own upstream outside the catalog format, a client secret that is not a secret:// reference, a scope the upstream does not offer, a mapped action outside the Resource's scopes or in the access or idp namespaces, or an executor that is not a certificate thumbprint (OP-154 m.3 (t)).",
);
/// The change would leave the organization without an active owner (TN-91, OP-153 m.3 (p)).
pub const LAST_OWNER: Code = code(
    "last-owner",
    409,
    "Conflict",
    "The organization keeps at least one active owner on every path; add another owner first (TN-91).",
);
/// An unknown social preset or a malformed client (IDP-31).
pub const INVALID_SOCIAL_PROVIDER: Code = code(
    "invalid-social-provider",
    400,
    "Bad Request",
    "The preset is not one Access ships, or the client id and secret reference are not given together (IDP-31).",
);
/// A shared development client named for a realm that is not a sandbox (IDP-31 (4)).
pub const SHARED_SOCIAL_KEY_IN_PRODUCTION: Code = code(
    "shared-social-key-in-production",
    409,
    "Conflict",
    "Only a sandbox realm may use the shared development client; give the realm its own client id and secret reference (IDP-31).",
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
/// The actor's account is in the 24 hours after a recovery: deleting it, a new API key or client
/// secret, an identity provider link and the other restricted changes wait (TN-56).
pub const RECOVERY_GRACE: Code = code(
    "recovery-grace",
    403,
    "Forbidden",
    "The account is in the grace period after a recovery; deleting it, a new client secret, an identity provider link and the other restricted changes wait until it ends (TN-56, OP-153 m.3 (e)).",
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
/// An invitee address, inviter name, role or lifetime outside the rules (TN-89, OP-153 m.3 (o)).
pub const INVALID_INVITATION: Code = code(
    "invalid-invitation",
    400,
    "Bad Request",
    "An invitee address, inviter name, role or lifetime outside the rules (TN-89, OP-153 m.3 (o)).",
);
/// Home realm discovery goes on only with a verified domain no other organization claims (TN-98).
pub const HRD_NEEDS_VERIFIED_DOMAIN: Code = code(
    "hrd-needs-verified-domain",
    409,
    "Conflict",
    "Home realm discovery goes on only with a verified domain no other organization claims (TN-98).",
);
/// A domain that is not a lower-case DNS name, or a verification method other than `dns_txt`,
/// `https` or `idp` (TN-90).
pub const INVALID_DOMAIN_CLAIM: Code = code(
    "invalid-domain-claim",
    400,
    "Bad Request",
    "A domain that is not a lower-case DNS name, or a verification method other than dns_txt, https or idp (TN-90).",
);
/// Autojoin is refused on a consumer, free mail, ISP or university domain (TN-90).
pub const CONSUMER_DOMAIN: Code = code(
    "consumer-domain",
    409,
    "Conflict",
    "Autojoin is refused on a consumer, free mail, ISP or university domain (TN-90).",
);
/// Another organization claims the domain too, so none of them gets autojoin (TN-90).
pub const DOMAIN_CONTESTED: Code = code(
    "domain-contested",
    409,
    "Conflict",
    "Another organization claims the domain too, so none of them gets autojoin (TN-90).",
);
/// The organization's claim of the domain is not verified now (TN-90).
pub const DOMAIN_NOT_VERIFIED: Code = code(
    "domain-not-verified",
    409,
    "Conflict",
    "The organization's claim of the domain is not verified now (TN-90).",
);
/// A connection draft whose issuer is not an https URL or whose client id is empty or too long
/// (TN-120).
pub const INVALID_CONNECTION_DRAFT: Code = code(
    "invalid-connection-draft",
    400,
    "Bad Request",
    "A connection draft whose issuer is not an https URL or whose client id is empty or too long (TN-120).",
);
/// Only an owner proposes or completes an ownership handover, and only its own client signs it
/// (TN-91).
pub const OWNER_ONLY: Code = code(
    "owner-only",
    403,
    "Forbidden",
    "Only an owner proposes or completes an ownership handover, and only its own client signs it (TN-91).",
);
/// The handover waits for its recipient's contribution or its 24-hour delay (TN-91).
pub const HANDOVER_WAITING: Code = code(
    "handover-waiting",
    409,
    "Conflict",
    "The handover waits for its recipient's contribution or its 24-hour delay (TN-91).",
);
/// The signed change is not this organization's handover to that recipient (TN-91).
pub const NOT_THE_HANDOVER: Code = code(
    "not-the-handover",
    409,
    "Conflict",
    "The signed change is not this organization's handover to that recipient (TN-91).",
);
/// A SAML service provider registration outside §10.6.1 or its template's interop profile
/// (OP-155 m.3 (e)).
pub const INVALID_SAML_SP: Code = code(
    "invalid-saml-sp",
    400,
    "Bad Request",
    "The SAML service provider registration is malformed: an entity ID that is not a bounded URI, an ACS that is not exact https or not HTTP-POST, a certificate that is not base64 DER, signed requests without a pinned certificate, encryption without an encryption certificate, nothing signed, an e-mail NameID without a template that asks for it, a duplicated attribute, or a registration its template's profile refuses (OP-155 m.3 (e)).",
);
/// The name or entity ID was registered before; neither is reused (OP-73).
pub const SAML_SP_EXISTS: Code = code(
    "saml-sp-exists",
    409,
    "Conflict",
    "A SAML service provider with this name or entity ID was registered before; a retired registration's name and entity ID are never reused (OP-73).",
);
/// A SAML certificate policy whose phases are shorter than 14 days, or an unknown algorithm.
pub const INVALID_SAML_CERTIFICATE_POLICY: Code = code(
    "invalid-saml-certificate-policy",
    400,
    "Bad Request",
    "The SAML certificate policy keeps each rotation phase at least 14 days, rotates every 30 to 1825 days and names rsa-3072 or p-256 (OP-155 m.3 (e)).",
);
/// A gateway registration that is not a kind, a gateway name and a certificate digest, or the
/// retirement of a gateway that is not live (OP-155 m.3 (c)).
pub const INVALID_GATEWAY: Code = code(
    "invalid-gateway",
    400,
    "Bad Request",
    "The gateway registration needs a kind (saml, ldap, kerberos or radius), a name of lower-case letters, digits and hyphens, and the SHA-256 of its client certificate in hex; only a live gateway can be retired (OP-155 m.3 (c)).",
);
/// The organization's SCIM source answers for its membership: invitations are closed (TN-95,
/// OP-155 m.3 (i)).
pub const INVITATIONS_CLOSED_BY_SCIM: Code = code(
    "invitations-closed-by-scim",
    409,
    "Conflict",
    "The organization's SCIM source answers for its membership, so it takes no invitation; members come and go through the SCIM client (TN-95).",
);
/// A setup link order whose address is not one (TN-134).
pub const INVALID_SETUP_LINK: Code = code(
    "invalid-setup-link",
    400,
    "Bad Request",
    "The setup link order names an address that is not an e-mail address (TN-134).",
);
/// The undelivered Relay message's sealed content was crypto-shredded; it cannot be resent
/// (OP-156 m.3 (c), OP-73).
pub const CONTENT_SHREDDED: Code = code(
    "content-shredded",
    410,
    "Gone",
    "The message's sealed content was crypto-shredded, so it cannot be resent; nothing was written (OP-156 m.3 (c)).",
);
/// The undelivered Relay message is past its expiry; resending it would deliver a worthless
/// code or link (OP-156 m.3 (c)).
pub const MESSAGE_EXPIRED: Code = code(
    "message-expired",
    409,
    "Conflict",
    "The message is past its expiry, so it is not resent; start the flow that sends it again (OP-156 m.3 (c)).",
);
/// A custom domain that is not a host below a registrable domain outside the deployment's base,
/// or a retirement of one bound as the issuer or RP ID (OP-156 m.3 (i)).
pub const INVALID_CUSTOM_DOMAIN: Code = code(
    "invalid-custom-domain",
    400,
    "Bad Request",
    "A custom domain is a lower-case host below a registrable domain, outside the deployment's base domain and never localhost; one bound as the issuer or passkey RP ID is never retired (OP-156 m.3 (i)).",
);
/// The realm's issuer stays fixed: it was activated, or its issuer is path-based (TN-16).
pub const ISSUER_FIXED: Code = code(
    "issuer-fixed",
    409,
    "Conflict",
    "The realm's issuer moves to a custom domain only before its first client or service provider is registered, and only from a subdomain issuer (TN-16, OP-156 m.3 (i)).",
);
