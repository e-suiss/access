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
/// An SSH CA body that is not `{"enabled": true|false}`, or a rotation or replacement with a
/// body (OP-156 m.3 (o)).
pub const INVALID_SSH_CA: Code = code(
    "invalid-ssh-ca",
    400,
    "Bad Request",
    "The SSH CA change is `{\"enabled\": true}` or `{\"enabled\": false}`; a rotation or a replacement has an empty body (OP-156 m.3 (o)).",
);
/// An SSH server group that is not a name of lower-case letters, digits and hyphens with a
/// short description (OP-156 m.3 (o)).
pub const INVALID_SSH_HOST_GROUP: Code = code(
    "invalid-ssh-host-group",
    400,
    "Bad Request",
    "The SSH server group needs a name of a lower-case letter followed by up to 62 lower-case letters, digits and hyphens, and a description of at most 256 characters (OP-156 m.3 (o)).",
);
/// The SSH server group name was registered before; it is not reused (OP-73).
pub const SSH_HOST_GROUP_EXISTS: Code = code(
    "ssh-host-group-exists",
    409,
    "Conflict",
    "An SSH server group with this name was registered before; a retired group's name is never reused (OP-73).",
);
/// The realm's SSH certificate authority is off: no key signs (OP-156 m.3 (o)).
pub const SSH_CA_OFF: Code = code(
    "ssh-ca-off",
    409,
    "Conflict",
    "The realm's SSH certificate authority is off, so no certificate is issued and no CA key is published; an administrator turns it on with idp.ssh.ca_enable (OP-156 m.3 (o)).",
);
/// An SSH certificate request outside the holder's ssh.login Grant (IDP-32, G2).
pub const SSH_NOT_GRANTED: Code = code(
    "ssh-not-granted",
    403,
    "Forbidden",
    "No live ssh.login Grant of the caller covers this server group with these principals, constraints and extensions, or the server group is not live; a certificate never carries more than its Grant (IDP-32).",
);
/// An SSH certificate lifetime past the holder's ceiling (OP-156 m.3 (o)).
pub const SSH_LIFETIME: Code = code(
    "ssh-lifetime",
    400,
    "Bad Request",
    "A person's certificate lives at most 12 hours and an agent's at most 1 hour, never past the Grant or the horizon (OP-156 m.3 (o)).",
);
/// A malformed SSH certificate request (OP-156 m.3 (o)).
pub const INVALID_SSH_REQUEST: Code = code(
    "invalid-ssh-request",
    400,
    "Bad Request",
    "The request is a draft ask {host_group, public_key, principals?, lifetime_s?} or a signed draft {draft, ais}; the AIS is signed by the key the access token is bound to (OP-156 m.3 (o)).",
);
/// The projection was decided and not allowed (OP-156 m.3 (o)).
pub const SSH_DENIED: Code = code(
    "ssh-denied",
    403,
    "Forbidden",
    "The authority decision on the certificate's projection.issue is not ALLOW: it was denied or waits on an action such as a fresh sign-in or an approval; the decision is in `decision` (OP-156 m.3 (o)).",
);
/// A proxy registration outside the rules (OP-156 m.3 (l)).
pub const INVALID_PROXY: Code = code(
    "invalid-proxy",
    400,
    "Bad Request",
    "The proxy needs a name of a lower-case letter followed by up to 62 lower-case letters, digits and hyphens, an engine of nginx, traefik, caddy or envoy, an application host, an http(s) upstream, a client_id, the proxy's transport identity (the base64url of its certificate or DPoP key thumbprint), an action, a resource namespace and 1 to 64 path patterns (OP-156 m.3 (l)).",
);
/// The proxy name was registered before; it is not reused (OP-73).
pub const PROXY_EXISTS: Code = code(
    "proxy-exists",
    409,
    "Conflict",
    "A proxy with this name was registered before; a retired proxy's name is never reused (OP-73).",
);
/// The proxy's client is not live, or does not list the application host's callback.
pub const INVALID_PROXY_CLIENT: Code = code(
    "invalid-proxy-client",
    400,
    "Bad Request",
    "The proxy's client_id names no live client of the realm that lists https://{host}/access-proxy/v1/callback as a redirect URI (OP-156 m.3 (l)).",
);
/// The application answers outside the proxy, so plain identity headers stay off.
pub const PROXY_REACHABLE_DIRECTLY: Code = code(
    "proxy-reachable-directly",
    409,
    "Conflict",
    "The setup check reached the application's upstream directly, so anyone could send it X-Access-User; plain identity headers stay off until the application answers only through the proxy (IDP-30 (3), OP-156 m.3 (l)).",
);
/// The asking proxy has no live registration for the application host (IDP-30, B22).
pub const PROXY_UNREGISTERED: Code = code(
    "proxy-unregistered",
    401,
    "Unauthorized",
    "The forward-auth check came without a proxy transport identity, or none registered for this application host; register the proxy with idp.proxy.register (IDP-30, OP-156 m.3 (l)).",
);
/// The engine's forwarded request cannot be read (OP-156 m.3 (l)).
pub const INVALID_FORWARDED_REQUEST: Code = code(
    "invalid-forwarded-request",
    400,
    "Bad Request",
    "The forward-auth check does not name the request it asks about: the engine's method, URI and host headers are missing or malformed; the request is refused (OP-156 m.3 (l)).",
);
/// An export sink whose name, adapter, endpoint, settings or secret do not fit, or that Access
/// may not reach (OP-156 m.3 (s)).
pub const INVALID_EXPORT_SINK: Code = code(
    "invalid-export-sink",
    400,
    "Bad Request",
    "An export sink has a lower-case name, an adapter (s3_parquet, otlp, collector or syslog), an https endpoint on port 443 or one the operator declared (host:port on 6514 for syslog), the settings of its adapter or preset and, where the adapter needs one, a secret; no sampling or filter setting exists (OP-156 m.3 (s), OP-44).",
);
/// The export sink name was registered before; it is not reused (OP-73).
pub const EXPORT_SINK_EXISTS: Code = code(
    "export-sink-exists",
    409,
    "Conflict",
    "An export sink with this name was registered before; a retired sink keeps its name and its cursor (OP-73).",
);
/// A signal source that is not a name, a kind, a provider, an issuer Party and a format that
/// carries the kind (OP-156 m.3 (r)).
pub const INVALID_SIGNAL_SOURCE: Code = code(
    "invalid-signal-source",
    400,
    "Bad Request",
    "A signal source needs a name of a lower-case letter followed by up to 62 lower-case letters, digits and hyphens, a kind (kyc, mdm, risk, dlp), a provider of 1 to 64 characters, the base64url of its issuer Party, a format that carries the kind, an https transmitter only for an SSF format and an expected interval of 60 s to 30 days (OP-156 m.3 (r)).",
);
/// The signal source name was registered before; it is not reused (OP-73).
pub const SIGNAL_SOURCE_EXISTS: Code = code(
    "signal-source-exists",
    409,
    "Conflict",
    "A signal source with this name was registered before; a retired source's name is never reused (OP-73).",
);
/// A Linux host registration or policy outside the rules (OP-156 m.3 (p)).
pub const INVALID_LINUX_HOST: Code = code(
    "invalid-linux-host",
    400,
    "Bad Request",
    "A Linux host has a name and a live server group of a lower-case letter followed by up to 62 lower-case letters, digits and hyphens, the 43-character x5t#S256 of its client certificate, an absolute shell path and sudo at CT2 or CT3; it serves NSS data offline for at most 12 hours and reuses a console sign-in offline for at most 8 (OP-156 m.3 (p)).",
);
/// The Linux host name was registered before, or a live host has the certificate (OP-73).
pub const LINUX_HOST_EXISTS: Code = code(
    "linux-host-exists",
    409,
    "Conflict",
    "A Linux host with this name was registered before, or a live host presents this client certificate; a retired host's name is never reused (OP-73).",
);
/// The client certificate names no live Linux host of the realm (OP-156 m.3 (p)).
pub const LINUX_HOST_UNKNOWN: Code = code(
    "linux-host-unknown",
    403,
    "Forbidden",
    "The request did not come with the client certificate of a live Linux host of this realm, registered with idp.linux.host_register (OP-156 m.3 (p)).",
);
/// A malformed Linux client request (OP-156 m.3 (p)).
pub const INVALID_LINUX_REQUEST: Code = code(
    "invalid-linux-request",
    400,
    "Bad Request",
    "The Linux NSS request is an empty JSON object; a sign-in is {user}, a sudo step-up {user, command} with the base64url SHA-256 of the command line, each with the person's DPoP-bound access token (OP-156 m.3 (p)).",
);
/// The sudo step-up's authentication is not strong or fresh enough (IDP-8, OP-156 m.3 (p)).
pub const LINUX_STEP_UP: Code = code(
    "linux-step-up",
    403,
    "Forbidden",
    "sudo needs a sign-in in the last 5 minutes with a phishing-resistant, user-verifying authenticator (CT2; CT3 also device-bound and non-custodial); a push or a password alone is not enough (IDP-8, OP-156 m.3 (p)).",
);
/// An HR source that is not a name of lower-case letters, digits and hyphens (OP-156 m.3 (q)).
pub const INVALID_HR_SOURCE: Code = code(
    "invalid-hr-source",
    400,
    "Bad Request",
    "The HR source needs a name of a lower-case letter followed by up to 62 lower-case letters, digits and hyphens; a retirement has an empty body (OP-156 m.3 (q)).",
);
/// The HR source name was registered before; it is not reused (OP-73).
pub const HR_SOURCE_EXISTS: Code = code(
    "hr-source-exists",
    409,
    "Conflict",
    "An HR source with this name was registered before; a retired source's name and issuer are never reused (OP-73).",
);
/// An HR connector that is not a name, a live source and a vendor the service reads.
pub const INVALID_HR_CONNECTOR: Code = code(
    "invalid-hr-connector",
    400,
    "Bad Request",
    "The HR connector needs a name, the HR source it pushes to and a vendor services/hr-connector reads: personio, bamboohr, hibob, workday, successfactors, kolayik or logo (OP-156 m.3 (q)).",
);
/// The HR connector name was registered before; it is not reused (OP-73).
pub const HR_CONNECTOR_EXISTS: Code = code(
    "hr-connector-exists",
    409,
    "Conflict",
    "An HR connector with this name was registered before; a retired connector's name is never reused (OP-73).",
);
/// An HR file refused whole (OP-156 m.3 (q)).
pub const INVALID_HR_RECORDS: Code = code(
    "invalid-hr-records",
    400,
    "Bad Request",
    "The import is {file, records, content}: content is 1 to 10 000 JSON Lines records or an RFC 4180 CSV file of at most 10 MB with a header row of employee_id, email, department, title, manager, start_date, end_date and employment_status, file its SHA-256 and records its record count. One bad record, an unknown column or a digest or count that does not match refuses the whole file and nothing is written (OP-156 m.3 (q)).",
);
/// An MCP tool list that is not names and pins (OP-156 m.3 (n)).
pub const INVALID_MCP_PINS: Code = code(
    "invalid-mcp-pins",
    400,
    "Bad Request",
    "The body is {\"tools\": [{\"name\", \"pin\"}]}: at most 256 tools, each MCP tool name once (1 to 128 of A-Z a-z 0-9 _ - .) with the base64url SHA-256 of its canonical definition (the RFC 8785 form of name, description, inputSchema and annotations); the list replaces the one before (OP-156 m.3 (n)).",
);
/// The MCP gateway's call does not name one tool call of the proxy (OP-156 m.3 (n)).
pub const INVALID_MCP_CALL: Code = code(
    "invalid-mcp-call",
    400,
    "Bad Request",
    "The MCP gateway's request is not one commit of the agent's own statement on a tool of this proxy: the tool name, its pin, the evaluation's intent (the proxy's action on namespace:[proxy, tool]) or the realm's domain does not match; nothing was decided (AG-42, OP-156 m.3 (n)).",
);
/// The tool is not pinned with this definition (AG-42, OP-156 m.3 (n)).
pub const MCP_TOOL_UNPINNED: Code = code(
    "mcp-tool-unpinned",
    409,
    "Conflict",
    "The tool's definition changed or the tool is new: it is blocked until an administrator pins it with idp.proxy.mcp_pin; nothing was decided and the call is not forwarded (AG-42, OP-156 m.3 (n)).",
);
/// The `support-case-required` problem (OP-157 m.3 (y)).
pub const SUPPORT_CASE_REQUIRED: Code = code(
    "support-case-required",
    422,
    "Unprocessable Content",
    "A support Grant names exactly one case: Requirement::Purpose with a PurposeRef::Case and params.case; a support grant.issue without a case is refused (OP-157 m.3 (c)).",
);
/// The `support-case-closed` problem (OP-157 m.3 (y)).
pub const SUPPORT_CASE_CLOSED: Code = code(
    "support-case-closed",
    409,
    "Conflict",
    "The support case is closed or its support_case Claim is missing or stale, so no support access holds; nothing was granted or done (OP-157 m.3 (e)).",
);
/// The `support-request-unknown` problem (OP-157 m.3 (y)).
pub const SUPPORT_REQUEST_UNKNOWN: Code = code(
    "support-request-unknown",
    404,
    "Not Found",
    "No open support access request with this id for the caller (OP-157 m.3 (f)).",
);
/// The `support-blocked` problem (OP-157 m.3 (y)).
pub const SUPPORT_BLOCKED: Code = code(
    "support-blocked",
    409,
    "Conflict",
    "The person turned on Block support access; no support request reaches them until they turn it off (OP-157 m.3 (c)).",
);
/// The `artifact-format-refused` problem (OP-157 m.3 (y)).
pub const ARTIFACT_FORMAT_REFUSED: Code = code(
    "artifact-format-refused",
    415,
    "Unsupported Media Type",
    "Only HAR, JSON and text logs can be redacted automatically; images and video are refused (TN-74, OP-157 m.3 (g)).",
);
/// The `artifact-too-large` problem (OP-157 m.3 (y)).
pub const ARTIFACT_TOO_LARGE: Code = code(
    "artifact-too-large",
    413,
    "Content Too Large",
    "The support artifact is larger than the realm's artifact policy allows (OP-157 m.3 (g)).",
);
/// The `breakglass-minimum-two` problem (OP-157 m.3 (y)).
pub const BREAKGLASS_MINIMUM_TWO: Code = code(
    "breakglass-minimum-two",
    422,
    "Unprocessable Content",
    "A break-glass setup needs at least two break-glass Grants held by two different Parties (OP-157 m.3 (h)).",
);
/// The `breakglass-review-required` problem (OP-157 m.3 (y)).
pub const BREAKGLASS_REVIEW_REQUIRED: Code = code(
    "breakglass-review-required",
    409,
    "Conflict",
    "A break-glass use waits for its review by another Party; the review classifies it as drill, emergency or misuse and grants nothing (OP-157 m.3 (h)).",
);
/// The `breakglass-account-sso-refused` problem (OP-157 m.3 (y)).
pub const BREAKGLASS_ACCOUNT_SSO_REFUSED: Code = code(
    "breakglass-account-sso-refused",
    403,
    "Forbidden",
    "A break-glass account signs in only with the realm's own phishing-resistant method, never through SSO or an upstream provider (OP-157 m.3 (h)).",
);
/// The `approval-not-eligible` problem (OP-157 m.3 (y)).
pub const APPROVAL_NOT_ELIGIBLE: Code = code(
    "approval-not-eligible",
    403,
    "Forbidden",
    "The viewer is not in the request's eligible set, so it cannot approve it here (OP-157 m.3 (l), E26).",
);
/// The `approval-surface-not-accepted` problem (OP-157 m.3 (y)).
pub const APPROVAL_SURFACE_NOT_ACCEPTED: Code = code(
    "approval-surface-not-accepted",
    403,
    "Forbidden",
    "The domain does not accept this approval surface's profile, so its approval counts for nothing (OP-157 m.3 (m)).",
);
/// The `approval-body-mismatch` problem (OP-157 m.3 (y)).
pub const APPROVAL_BODY_MISMATCH: Code = code(
    "approval-body-mismatch",
    409,
    "Conflict",
    "The pushed request's body does not match the intent's opaque parameter digest, so it cannot be approved (PI-17, OP-157 m.3 (l)).",
);
/// The `approval-batch-invalid` problem (OP-157 m.3 (y)).
pub const APPROVAL_BATCH_INVALID: Code = code(
    "approval-batch-invalid",
    422,
    "Unprocessable Content",
    "A batch approval holds at most 10 CT1 requests of one requester and one action class, each with its own AAS (OP-157 m.3 (m)).",
);
/// The `approval-inline-off` problem (OP-157 m.3 (y)).
pub const APPROVAL_INLINE_OFF: Code = code(
    "approval-inline-off",
    409,
    "Conflict",
    "The realm has not opened in-notification approval, or the request is not CT1 (OP-157 m.3 (m)).",
);
/// The `approval-invite-limit` problem (OP-157 m.3 (y)).
pub const APPROVAL_INVITE_LIMIT: Code = code(
    "approval-invite-limit",
    429,
    "Too Many Requests",
    "At most 5 approval invitations an hour from one requester to one approver, and one per intent; try again after Retry-After (OP-157 m.3 (m)).",
);
/// The `approval-inline-assertion-required` problem (§10.2, §10.3.1, MD-11, OP-157 m.17).
pub const APPROVAL_INLINE_ASSERTION_REQUIRED: Code = code(
    "approval-inline-assertion-required",
    409,
    "Conflict",
    "The approval carries no passkey assertion over H(AAS); a device key's signature alone is not phishing resistant, so nothing was recorded; send the approver's passkey assertion with it, or approve on the Approval Surface (§10.2, §10.3.1, OP-157 m.17).",
);
/// The `policy-default-unknown` problem (OP-157 m.3 (y)).
pub const POLICY_DEFAULT_UNKNOWN: Code = code(
    "policy-default-unknown",
    422,
    "Unprocessable Content",
    "The policy.set defaults name a key the Kernel does not know: ct3_delay_s, mapping_probation_days, approval_surfaces, breakglass_review_h and support_max_min are the known ones (OP-157 m.3 (n)).",
);
/// The `mapping-not-pinned` problem (OP-157 m.3 (y)).
pub const MAPPING_NOT_PINNED: Code = code(
    "mapping-not-pinned",
    409,
    "Conflict",
    "The compatibility mapping is not pinned by the domain's schema-definition Acceptance, so it changes no coverage (PI-19, OP-157 m.3 (r)).",
);
/// The `delegated-admin-off` problem (OP-157 m.3 (y)).
pub const DELEGATED_ADMIN_OFF: Code = code(
    "delegated-admin-off",
    409,
    "Conflict",
    "The realm has not opened delegated administration, so no new admin Grant is issued; existing ones stay (OP-157 m.3 (t)).",
);
/// The `offboarding-disposition-missing` problem (OP-157 m.3 (y)).
pub const OFFBOARDING_DISPOSITION_MISSING: Code = code(
    "offboarding-disposition-missing",
    422,
    "Unprocessable Content",
    "Offboarding needs one explicit choice for every channel: direct Grants, Instances, rule-shaped holdings, the self-anchor and re-entry; there are no defaults (OP-157 m.3 (v)).",
);
/// The `ceremony-quorum-missing` problem (OP-157 m.3 (y)).
pub const CEREMONY_QUORUM_MISSING: Code = code(
    "ceremony-quorum-missing",
    403,
    "Forbidden",
    "The binding key operation needs a permit signed by k of the n ceremony keys, 2 of 3 by default, within 15 minutes and with a fresh nonce (CR-29, OP-157 m.3 (x)).",
);
/// The `case-system-unknown` problem (OP-157 m.3 (y)).
pub const CASE_SYSTEM_UNKNOWN: Code = code(
    "case-system-unknown",
    404,
    "Not Found",
    "No live support case system by that name in the realm (OP-157 m.3 (e)).",
);
