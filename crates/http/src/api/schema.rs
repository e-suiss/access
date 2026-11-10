//! The management API contract as an `OpenAPI` 3.1 document, generated from the manifest and
//! committed as `sdks/openapi/admin-v1.json` (OP-65 m.3, TN-112, OP-151 m.4): the common
//! components (problem, pagination, idempotency, conditional and rate limit headers,
//! `Request-Id`) and one operation per manifest row. `just admin-contract` rewrites it.

use serde_json::{Map, Value, json};

use super::domain::idempotency::MAX_KEY;
use super::domain::page::{CURSOR, DEFAULT_PAGE, FILTER, MAX_PAGE, PAGE_SIZE};
use super::domain::{PLATFORM_AUDIENCE, REALM_AUDIENCE_PREFIX, Surface};
use super::manifest::{Access, MANIFEST, Route, Visibility};
use crate::problem::TYPE_PREFIX;

/// Version of the contract.
pub const VERSION: &str = "1.0.0";

fn r(kind: &str, name: &str) -> Value {
    json!({ "$ref": format!("#/components/{kind}/{name}") })
}

fn text(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

/// OP-154 m.3 (d), (r): a workload client's registration beside the client's.
fn with_workload_clients(mut schemas: Value) -> Value {
    if let Some(p) = schemas
        .pointer_mut("/Client/properties")
        .and_then(Value::as_object_mut)
    {
        p.insert(
            String::from("spiffe_id"),
            text("A workload client's SPIFFE ID, or a whole-segment prefix ending in /*; any other wildcard selects nothing (OP-154 m.3 (r))."),
        );
        p.insert(
            String::from("spiffe_bundle_endpoint"),
            text(
                "The https Bundle Endpoint of the workload client's trust domain (OP-154 m.3 (r)).",
            ),
        );
        p.insert(
            String::from("agent"),
            text("The agent Party whose Instances the workloads become, unpadded base64url (OP-154 m.3 (d))."),
        );
    }
    schemas
}

#[expect(
    clippy::too_many_lines,
    reason = "one JSON literal of the contract's component schemas"
)]
fn schemas() -> Value {
    json!({
        "Problem": {
            "type": "object",
            "description": format!("RFC 9457. `type` is `{TYPE_PREFIX}<code>`, or `about:blank` when the status says all; the codes are listed in `problems.json`."),
            "required": ["type", "title", "status", "code"],
            "properties": {
                "type": text("Problem type URI."),
                "title": text("Short title."),
                "status": { "type": "integer", "minimum": 100, "maximum": 599 },
                "code": text("Stable error code (OP-65)."),
                "reason": text("A stable, non-secret reason narrowing `code`."),
                "errors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["code"],
                        "properties": {
                            "pointer": text("A JSON Pointer (RFC 6901) into the request body, as a URI fragment."),
                            "code": text("Stable code of what is wrong there."),
                        },
                    },
                },
            },
        },
        "Position": { "type": "string", "pattern": "^[0-9]{1,20}$", "description": "A ledger position, in decimal: 64-bit integers are strings (OP-65)." },
        "Time": { "type": "string", "format": "date-time", "description": "RFC 3339, UTC." },
        "ExerciseRef": {
            "type": "object",
            "additionalProperties": false,
            "description": "The Exercise a write compiled to and its position (TN-110).",
            "required": ["exercise_id", "position"],
            "properties": {
                "exercise_id": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "The ExerciseID, unpadded base64url." },
                "position": r("schemas", "Position"),
            },
        },
        "Validity": {
            "type": "object",
            "additionalProperties": false,
            "required": ["not_before", "not_after"],
            "description": "The intent's validity, at most 15 minutes; the draft fills it in (TN-110).",
            "properties": { "not_before": r("schemas", "Time"), "not_after": r("schemas", "Time") },
        },
        "WriteBody": {
            "type": "object",
            "description": "The operation's resource members as the draft returned them, with `validity` and, unless sent as `X-Access-AIS`, the `ais`. No member writes a credential (TN-61).",
            "properties": {
                "validity": r("schemas", "Validity"),
                "ais": text("The caller's AIS, unpadded base64url of its COSE_Sign1, when not in the header."),
            },
        },
        "DraftRequest": {
            "type": "object",
            "additionalProperties": false,
            "required": ["operation"],
            "properties": {
                "operation": text("The write's operationId."),
                "key": text("The path's natural key, for operations on one resource."),
                "body": r("schemas", "WriteBody"),
            },
        },
        "IntentDraft": {
            "type": "object",
            "additionalProperties": false,
            "required": ["operation", "body", "domain", "pep", "intent", "intent_digest"],
            "description": "What the caller signs: an AIS over `intent_digest` for `domain` and `pep`, mode `commit`, then the write with `body` (TN-110, PI-7). Drafting changes nothing.",
            "properties": {
                "operation": text("The write's operationId."),
                "key": { "type": ["string", "null"] },
                "body": r("schemas", "WriteBody"),
                "domain": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$" },
                "pep": text("The PEP the AIS addresses."),
                "intent": text("Deterministic CBOR of the intent, unpadded base64url."),
                "intent_digest": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$" },
            },
        },
        "Client": {
            "type": "object",
            "additionalProperties": false,
            "description": "A client registration (TN-15, IDP-7). No secret is ever read back (CR-38).",
            "properties": {
                "client_id": text("Server-generated, never reused (OP-137, TN-20)."),
                "display_name": text("Display name."),
                "token_endpoint_auth_method": { "type": "string", "enum": ["none", "private_key_jwt", "client_secret_basic", "spiffe_jwt", "spiffe_x509"] },
                "jwks_uri": { "type": ["string", "null"] },
                "redirect_uris": { "type": "array", "items": text("Compared as an exact string.") },
                "post_logout_redirect_uris": { "type": "array", "items": { "type": "string" } },
                "backchannel_logout_uri": { "type": ["string", "null"] },
                "require_pushed_authorization_requests": { "type": "boolean" },
                "platform_product": { "type": ["string", "null"], "readOnly": true },
                "status": { "type": "string", "enum": ["active", "retired"], "readOnly": true },
            },
        },
        "Group": {
            "type": "object",
            "additionalProperties": false,
            "description": "A group with its one membership issuer (TN-117); membership is an identity Claim, never authority.",
            "properties": {
                "name": text("Natural key."),
                "display_name": text("Display name."),
                "membership_issuer": { "type": "string", "pattern": "^(admin|upstream:[a-z][a-z0-9_-]{0,63})$" },
                "status": { "type": "string", "enum": ["active", "retired"], "readOnly": true },
            },
        },
        "Account": {
            "type": "object",
            "additionalProperties": false,
            "description": "An account's state (§12.3.1). There is no credential field: a reset goes through the account's own flows (TN-61).",
            "properties": {
                "account_id": text("Opaque `usr_` id (OP-137)."),
                "status": { "type": "string", "enum": ["staged", "pending_user_action", "active", "locked", "suspended", "deactivated", "tombstone", "purging"] },
                "status_at": r("schemas", "Time"),
                "created_at": r("schemas", "Time"),
            },
        },
        "Agent": {
            "type": "object",
            "additionalProperties": false,
            "description": "An agent of the realm (OP-154 m.3 (c), (e)): its own agent Party, the operator it runs for, its human sponsors and what it is connected to. It is exported to the authority plane only as `agent_kind`, `operated_by` and `sponsored_by` Claims; it holds no authority of its own (AG-19).",
            "properties": {
                "agent": text("Opaque id of the agent Party."),
                "display_name": text("Name shown to people; attacker input, rendered as text."),
                "agent_kind": { "type": "string", "enum": ["cloud", "local", "enterprise", "robot"] },
                "operator": text("The operator Party: an organization or a person."),
                "sponsors": { "type": "array", "items": { "type": "string" }, "description": "The human sponsors' account ids; at least one while the agent is active." },
                "status": { "type": "string", "enum": ["active", "suspended", "retired"], "readOnly": true },
                "connections": { "type": "array", "items": { "type": "string" }, "description": "Connected accounts for agents, by connection id; never a token." },
                "last_run_at": { "anyOf": [r("schemas", "Time"), { "type": "null" }] },
                "created_at": r("schemas", "Time"),
            },
        },
        "UpstreamIdp": {
            "type": "object",
            "additionalProperties": false,
            "description": "An upstream identity provider's registration (OP-150 m.11 (j)); its client secret only by `secret://` reference.",
            "properties": {
                "name": text("Natural key."),
                "issuer": text("https issuer."),
                "client_id": text("Access's client id at the provider."),
                "client_secret_ref": { "type": ["string", "null"], "pattern": "^secret://" },
                "jwks_uri": text("https JWKS."),
                "ssf": { "type": ["object", "null"], "description": "The provider as an SSF push transmitter: `issuer`, `jwks_uri`, `aud`, `events`, `expected_interval_s` (OP-151 m.7 (g))." },
                "status": { "type": "string", "enum": ["active", "retired"], "readOnly": true },
            },
        },
        "Organization": {
            "type": "object",
            "description": "An organization as S7 reads it (§8.5 S7, §12.3.8): its id is its Party's base64url; its roots and members, each with how the membership began (apart from any sign-in source) and its role's versioned Grant; its domain claims with their watch state; its ownership handovers, which are root standing and never billing (TN-91); its connection drafts, which nothing puts into effect but idp.upstream.register (TN-120). The list form carries only `organization`, `display_name` and `hrd`.",
            "properties": {
                "organization": { "type": "string", "readOnly": true },
                "display_name": { "type": "string" },
                "hrd": { "type": "boolean" },
                "roots": { "type": "integer", "minimum": 0, "readOnly": true },
                "members": { "type": "array", "readOnly": true, "items": {
                    "type": "object",
                    "properties": {
                        "account_id": { "type": "string" },
                        "owner": { "type": "boolean" },
                        "membership_source": { "type": "string", "enum": ["founder", "invite", "scim", "jit", "domain_autojoin"] },
                        "role": { "type": ["object", "null"] },
                        "role_grant": { "type": ["string", "null"], "enum": ["pending", "issued", "denied", null] },
                        "grant": { "type": ["string", "null"] },
                        "cooling_until": { "type": ["string", "null"], "format": "date-time" },
                        "joined_at": r("schemas", "Time"),
                    },
                } },
                "domains": { "type": "array", "readOnly": true, "items": { "type": "object" } },
                "handovers": { "type": "array", "readOnly": true, "items": {
                    "type": "object",
                    "properties": {
                        "handover": { "type": "string" },
                        "from": { "type": "string" },
                        "to": { "type": "string" },
                        "state": { "type": "string", "enum": ["proposed", "contributed", "cancelled", "completed"] },
                        "effective_at": r("schemas", "Time"),
                        "dns_recovery": { "type": "boolean" },
                    },
                } },
                "connection_drafts": { "type": "array", "readOnly": true, "items": { "type": "object" } },
            },
        },
        "SocialProvider": {
            "type": "object",
            "additionalProperties": false,
            "description": "A social preset the realm enabled (IDP-31, OP-153 m.3 (l)): its client secret only by `secret://` reference; no client means the operator's shared development client, which only a sandbox realm may use. Warnings never refuse anything (TN-87, IDP-31 (5)).",
            "properties": {
                "preset": { "type": "string", "enum": ["apple", "facebook", "github", "google", "linkedin", "microsoft"] },
                "client_id": { "type": ["string", "null"] },
                "client_secret_ref": { "type": ["string", "null"], "pattern": "^secret://" },
                "shared_development_client": { "type": "boolean", "readOnly": true },
                "status": { "type": "string", "enum": ["active", "disabled"], "readOnly": true },
                "warnings": {
                    "type": "array",
                    "readOnly": true,
                    "items": {
                        "type": "object",
                        "properties": {
                            "code": { "type": "string", "enum": ["social-client-id-changed", "apple-transfer-window", "apple-sign-in-recommended"] },
                            "at": r("schemas", "Time"),
                            "until": r("schemas", "Time"),
                        },
                    },
                },
            },
        },
        "Hook": {
            "type": "object",
            "additionalProperties": false,
            "description": "An inline hook (TN-135): one live hook per call point; a URL change is a retirement and a new registration. Its signing key is never read back (TN-61).",
            "properties": {
                "hook_id": text("Server-generated `hok_` id (OP-137); the draft assigns it."),
                "point": { "type": "string", "enum": ["pre_registration", "token_issuance", "post_login"] },
                "url": text("https on a DNS name, port 443, unless the extension policy allows a target the operator declared (OP-151 m.10 (e))."),
                "on_no_answer": { "type": "string", "enum": ["refuse", "continue_without_claims"], "description": "`continue_without_claims` only at `token_issuance`." },
                "disclose": { "type": "array", "items": { "type": "string", "enum": ["email"] }, "description": "Personal data it may receive; only at `pre_registration` and only what the extension policy permits." },
                "signing": { "type": "string", "enum": ["ed25519", "hmac"], "description": "Standard Webhooks `v1a` (default) or `v1`." },
                "public_key": { "type": ["string", "null"], "readOnly": true, "description": "The `whpk_` key `v1a` requests verify with." },
                "status": { "type": "string", "enum": ["active", "retired"], "readOnly": true },
            },
        },
        "Webhook": {
            "type": "object",
            "additionalProperties": false,
            "description": "A webhook (TN-136): signed CloudEvents of identity events, at least once. Its keys are never read back (TN-61).",
            "properties": {
                "webhook_id": text("Server-generated `whk_` id (OP-137); the draft assigns it."),
                "url": text("https on a DNS name, port 443, unless the extension policy allows a target the operator declared (OP-151 m.10 (e))."),
                "events": { "type": "array", "items": text("An identity event name of the catalogue (OP-151 m.3 (i)).") },
                "signing": { "type": "string", "enum": ["ed25519", "hmac"], "description": "Fixed at registration." },
                "status": { "type": "string", "enum": ["active", "retired"], "readOnly": true },
            },
        },
        "Signals": {
            "type": "object",
            "additionalProperties": false,
            "required": ["transmitters", "geoip", "verifiers"],
            "description": "The realm's signal sources (§8.13): a delayed source is stated, never hidden, and decisions keep using declared validity windows.",
            "properties": {
                "transmitters": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["name", "delayed_since"],
                        "properties": {
                            "name": text("The transmitter's issuer."),
                            "delayed_since": { "type": ["integer", "null"], "minimum": 0, "description": "Since when it is delayed, Unix ms; null while on time (OP-151 m.7 (g))." },
                        },
                    },
                },
                "geoip": { "type": "string", "enum": ["configured", "not_configured", "unreadable"], "description": "The GeoIP source; without one geographic signals are unavailable (OP-151 m.3 (o))." },
                "verifiers": {
                    "type": "array",
                    "description": "Verifier reports past their declared window; none is stored yet.",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["name", "declared_until"],
                        "properties": {
                            "name": text("The verifier."),
                            "declared_until": { "type": "integer", "minimum": 0, "description": "Unix ms." },
                        },
                    },
                },
            },
        },
        "Analytics": {
            "type": "object",
            "additionalProperties": false,
            "required": ["days", "surges"],
            "description": "Daily sign-in counts of the last 30 days and failed sign-in surges (IDP-36): counters only, never a decision input.",
            "properties": {
                "days": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "description": "`day` (YYYY-MM-DD, UTC), `started`, `completed`, `failed`, `active_accounts`, `passkey_accounts`, `mfa_accounts`, `mfa_setup` and `methods` (sessions by method).",
                    },
                },
                "surges": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "description": "`day`, `failed` (that day) and `baseline` (the day before).",
                    },
                },
            },
        },
        "WebhookDelivery": {
            "type": "object",
            "additionalProperties": false,
            "description": "One delivery of a webhook's log (TN-136); the event body is never read back. An item of `listWebhookDeliveries`.",
            "properties": {
                "event_id": text("The event id: the dedup key and `webhook-id`."),
                "event": text("The event name of the catalogue (OP-151 m.3 (i))."),
                "state": { "type": "string", "enum": ["pending", "delivered", "exhausted", "failed"] },
                "attempts": { "type": "integer", "minimum": 0 },
                "last_status": { "type": ["integer", "null"] },
                "last_latency_ms": { "type": ["integer", "null"] },
                "last_reason": { "type": ["string", "null"], "enum": ["status", "unreachable", "refused", "retired", "unsigned", null] },
                "occurred_at": r("schemas", "Time"),
                "queued_at": r("schemas", "Time"),
            },
        },
        "Settings": {
            "type": "object",
            "description": "The realm's settings: JOSE algorithm, Argon2, RP ID, CIMD, sign-in requirements (TN-132), console session policy (TN-129), branding (TN-106), mappers (TN-117), the extension policy (`allow_private_targets`, `hook_disclosure`; OP-151 m.10 (e)), the hosted pages' `csp_mode` (`enforce` or `report_only`), `related_origins` (TN-18) and `locale_overrides` by locale and key (X35).",
        },
        "SsoEnforcementPreview": {
            "type": "object",
            "description": "What enforcing SSO on the organization would end; nothing changes until idp.org.sso_enforce commits (TN-94, X20, OP-155 m.3 (i)). Each active member with its local sign-in methods, directory app passwords (API keys), open sign-ins and refresh families; the service accounts, members whose API keys enforcement revokes; and the pending invitations, whose fate the enforcement names (cancel or redirect_to_sso).",
            "properties": {
                "organization": { "type": "string" },
                "enforced": { "type": "boolean" },
                "invitations": { "type": ["string", "null"], "enum": ["cancel", "redirect_to_sso", null] },
                "members": { "type": "array", "items": {
                    "type": "object",
                    "properties": {
                        "account_id": { "type": "string" },
                        "owner": { "type": "boolean" },
                        "local_sign_in_methods": { "type": "integer", "minimum": 0 },
                        "password": { "type": "boolean" },
                        "api_keys": { "type": "integer", "minimum": 0 },
                        "sign_ins": { "type": "integer", "minimum": 0 },
                        "refresh_families": { "type": "integer", "minimum": 0 },
                        "linked_sign_ins": { "type": "integer", "minimum": 0 },
                        "service_account": { "type": "boolean" },
                    },
                } },
                "service_accounts": { "type": "array", "items": { "type": "string" } },
                "pending_invitations": { "type": "integer", "minimum": 0 },
                "totals": { "type": "object" },
            },
        },
        "Declared": {
            "type": "object",
            "description": "A resource whose route is declared and not served yet; its lane names its members when it serves it (OP-155 m.4).",
        },
        "Page": {
            "type": "object",
            "additionalProperties": false,
            "required": ["items"],
            "description": "One page; the next is in the `Link` header (OP-65). Only what the realm may see is listed (TN-113).",
            "properties": { "items": { "type": "array", "items": { "type": "object" } } },
        },
        "WriteResult": {
            "type": "object",
            "additionalProperties": false,
            "required": ["exercise_id", "position"],
            "description": "The Exercise the write compiled to (TN-110), the resource as it now is, and a server-generated `client_secret` (CR-38) or hook or webhook `verification_key` (TN-135, TN-136) shown this once.",
            "properties": {
                "exercise_id": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$" },
                "position": r("schemas", "Position"),
                "resource": { "type": "object" },
                "client_secret": text("Shown once; never stored or read back."),
                "verification_key": text("The `whpk_` public key or `whsec_` secret a hook's or webhook's receiver verifies with; shown once, never read back."),
                "offer": text("An administrator's binding offer, a compact JWS of type `binding-offer+jwt` signed by this realm's key, for the peer realm's `bindAccount` (OP-153 m.18 (e)); shown once."),
                "bundle": text("A migration export's bundle, dCBOR as unpadded base64url, sealed to the recipient key the change names (TN-86); shown once, never kept."),
                "setup_link": text("An organization's one-use SSO setup link, valid 72 hours; shown once and kept only as its token's SHA-256 (TN-134)."),
                "challenge": text("A domain claim's challenge, published as `suiss-access-verify=<challenge>` in a DNS TXT record at `_suiss-access.<domain>` or at `https://<domain>/.well-known/suiss-access-verify`; shown once, kept only as its SHA-256 (TN-90)."),
                "irreversible": { "type": "boolean", "description": "Set on an RP ID change: it cannot be undone and the realm's passkeys stop working (IDI-4)." },
            },
        },
        "Tenant": {
            "type": "object",
            "additionalProperties": false,
            "description": "A tenant's metadata; never its realms' content (INV-29, X31).",
            "properties": {
                "tenant_id": text("Opaque `tnt_` id (OP-137)."),
                "status": { "type": "string", "enum": ["provisioning", "active", "suspended", "deleted"] },
                "placement": text("Its placement (OP-40)."),
                "created_at": r("schemas", "Time"),
            },
        },
        "SandboxBudget": {
            "type": "object",
            "additionalProperties": false,
            "description": "The sandbox template's fixed budget (OP-151 m.3 (m)); structural fair use, not a plan.",
            "properties": {
                "exercises_per_day": r("schemas", "Position"),
                "projections_per_day": r("schemas", "Position"),
            },
        },
        "RealmMetadata": {
            "type": "object",
            "additionalProperties": false,
            "description": "A realm's metadata and the state of its signing keys; never its settings, accounts, clients or authority state (INV-29, X31, TN-119).",
            "properties": {
                "slug": text("The immutable slug (TN-16)."),
                "tenant_id": text("Opaque `tnt_` id of its tenant."),
                "issuer": { "type": ["string", "null"] },
                "status": { "type": "string", "enum": ["active", "suspended", "deleted"] },
                "placement": text("Its placement (OP-40)."),
                "domain": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "Its governing DomainID: the digest of its Genesis record." },
                "sandbox": { "type": "boolean", "description": "Whether its governing domain is a sandbox (OP-151 m.3 (m))." },
                "budget": { "oneOf": [r("schemas", "SandboxBudget"), { "type": "null" }] },
                "created_at": r("schemas", "Time"),
                "key_state": { "type": "string", "enum": ["pending", "published", "signing", "unavailable"], "description": "Its JOSE keys: none published yet, published and inside the publish lead, signing, or the signer did not answer (CR-25, SAI-46)." },
                "signing_available_at": { "oneOf": [r("schemas", "Time"), { "type": "null" }], "description": "When its first key may sign at the latest: creation plus the publish lead, 90 minutes by default (CR-25); the founding-key exception (CR-59) may make it sooner." },
            },
        },
        "OperatorHealth": {
            "type": "object",
            "additionalProperties": false,
            "description": "The deployment's readiness checks by name; no addresses, keys or secrets.",
            "properties": {
                "status": { "type": "string", "enum": ["ready", "degraded"] },
                "checks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["name", "ok"],
                        "properties": { "name": text("The check."), "ok": { "type": "boolean" } },
                    },
                },
            },
        },
        "TenantPage": {
            "type": "object",
            "additionalProperties": false,
            "required": ["items"],
            "description": "One page of tenants; the next is in the `Link` header (OP-65).",
            "properties": { "items": { "type": "array", "items": r("schemas", "Tenant") } },
        },
        "RealmPage": {
            "type": "object",
            "additionalProperties": false,
            "required": ["items"],
            "description": "One page of realms or sandbox domains; the next is in the `Link` header (OP-65).",
            "properties": { "items": { "type": "array", "items": r("schemas", "RealmMetadata") } },
        },
        "FoundingRoot": {
            "type": "object",
            "additionalProperties": false,
            "description": "The founding root of the new governing domain (TN-111): `joint` with `k` of `parties`, recommended, or `sole` with one Party; a Party is its 16-byte id, unpadded base64url.",
            "properties": {
                "sole": { "type": "string", "pattern": "^[A-Za-z0-9_-]{22}$" },
                "joint": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["k", "parties"],
                    "properties": {
                        "k": { "type": "integer", "minimum": 2 },
                        "parties": { "type": "array", "minItems": 2, "items": { "type": "string", "pattern": "^[A-Za-z0-9_-]{22}$" } },
                    },
                },
            },
        },
        "TenantCreate": {
            "type": "object",
            "additionalProperties": false,
            "description": "A new tenant; the draft assigns its `tenant_id`.",
            "examples": [{ "placement": "pool-default" }],
            "properties": {
                "tenant_id": text("Assigned by the draft; send it back unchanged."),
                "placement": text("Its placement; `pool-default` when omitted (OP-40)."),
                "validity": r("schemas", "Validity"),
                "ais": text("The caller's AIS, when not in the header."),
            },
        },
        "RealmCreate": {
            "type": "object",
            "additionalProperties": false,
            "required": ["slug", "root"],
            "description": "A new realm and the Genesis of its governing domain (TN-111, §5.16). A sole root needs `acknowledge_no_recovery: true` (TN-60, §13.7.7).",
            "examples": [
                { "slug": "shop", "issuer_style": "subdomain", "root": { "joint": { "k": 2, "parties": ["AQEBAQEBAQEBAQEBAQEBAQ", "AgICAgICAgICAgICAgICAg"] } } },
                { "slug": "lab", "root": { "sole": "AQEBAQEBAQEBAQEBAQEBAQ" }, "acknowledge_no_recovery": true },
            ],
            "properties": {
                "slug": text("The immutable slug (TN-16)."),
                "issuer_style": { "type": "string", "enum": ["subdomain", "path"], "default": "subdomain" },
                "placement": text("Its placement; `pool-default` when omitted (OP-40)."),
                "root": r("schemas", "FoundingRoot"),
                "ct3_delay_s": { "type": "integer", "minimum": 3600, "maximum": 2_592_000 },
                "causal_binding": { "type": "boolean", "default": false, "description": "Declare causal-bound allowances: an upstream ExerciseID backs at most one downstream Exercise, and chained decisions answer `causal_binding: enforced` (§7.9.7.4, E17)." },
                "acknowledge_no_recovery": { "type": "boolean", "default": false },
                "sandbox": { "type": "boolean", "description": "Open the governing domain from the sandbox template, a separate AuthorityDomain with its fixed budget (OP-151 m.3 (m)); always true on `sandbox-domains`." },
                "validity": r("schemas", "Validity"),
                "ais": text("The caller's AIS, when not in the header."),
            },
        },
        "Genesis": {
            "type": "object",
            "additionalProperties": false,
            "description": "What the new governing domain's Genesis declares (TN-111, §13.7.7): its digest (the DomainID), its root's shape, and whether it can be recovered.",
            "examples": [{ "digest": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc", "root": { "kind": "joint", "k": 2, "n": 2 }, "recovery": "not_available", "recovery_reason": "no-recover-entry" }],
            "properties": {
                "digest": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$" },
                "root": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "kind": { "type": "string", "enum": ["sole", "joint"] },
                        "k": { "type": "integer" },
                        "n": { "type": "integer" },
                    },
                },
                "recovery": { "type": "string", "enum": ["not_available"], "description": "`not_available`: the rootTerms `domain.recover` entry cannot be built; the domain cannot be recovered (NG, N-14)." },
                "recovery_reason": text("A stable reason code."),
            },
        },
        "PlatformWriteResult": {
            "type": "object",
            "additionalProperties": false,
            "required": ["exercise_id", "position"],
            "description": "The `idp.platform.*` Exercise the write compiled to (TN-110), what it created, and for a realm its Genesis.",
            "properties": {
                "exercise_id": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$" },
                "position": r("schemas", "Position"),
                "resource": { "oneOf": [r("schemas", "Tenant"), r("schemas", "RealmMetadata")] },
                "genesis": r("schemas", "Genesis"),
            },
        },
        "SurfaceRoot": {
            "type": "object",
            "additionalProperties": false,
            "required": ["surface", "audience", "scope_namespace", "read_scope", "domain", "rate_policies"],
            "properties": {
                "surface": { "type": "string", "enum": ["realm", "platform"] },
                "realm": text("The realm's slug (realm surface)."),
                "audience": text(&format!("The token audience: `{REALM_AUDIENCE_PREFIX}<slug>` or `{PLATFORM_AUDIENCE}` (TN-119).")),
                "scope_namespace": text("The surface's scope prefix: `realm.` or `platform.`."),
                "read_scope": text("The scope a read needs at least."),
                "domain": { "type": "string", "pattern": "^[A-Za-z0-9_-]{43}$", "description": "The surface's governing DomainID, unpadded base64url." },
                "rate_policies": { "type": "array", "items": text("A `RateLimit-Policy` item of the caller's own budget.") },
            },
        },
    })
}

fn headers() -> Value {
    let s = |d: &str| json!({ "description": d, "schema": { "type": "string" } });
    json!({
        "Request-Id": s("The request's W3C trace id, 32 lower-case hex digits: the `traceparent` trace id when one was sent (OP-65, OP-67)."),
        "RateLimit-Policy": s("The quotas that applied (IETF httpapi RateLimit header fields): `\"<name>\";q=<quota>;w=<window seconds>`, per layer (TN-127)."),
        "RateLimit": s("What is left of each quota: `\"<name>\";r=<remaining>;t=<seconds to reset>`."),
        "Retry-After": s("Seconds to wait before retrying (RFC 9110 §10.2.3)."),
        "ETag": s("The resource version, a strong entity tag; send it in `If-Match` to update (OP-65)."),
        "Link": s("RFC 8288 `rel=\"next\"` to the next page; absent on the last page."),
        "Deprecation": s("RFC 9745: when the operation was deprecated, `@<unix seconds>`."),
        "Sunset": s("RFC 8594: when the operation goes away, an HTTP-date."),
    })
}

fn parameters() -> Value {
    json!({
        "Traceparent": { "name": "traceparent", "in": "header", "required": false, "description": "W3C Trace Context; its trace id becomes `Request-Id`.", "schema": { "type": "string" } },
        "IdempotencyKey": {
            "name": "Idempotency-Key", "in": "header", "required": true,
            "description": "Required on every write: the AIS nonce, unpadded base64url. The same key and request replay the first answer for 24 hours; another request is 422; a running one 409 (TN-126).",
            "schema": { "type": "string", "minLength": 1, "maxLength": MAX_KEY },
        },
        "Ais": {
            "name": "X-Access-AIS", "in": "header", "required": false,
            "description": "The caller's actor intent statement, a `COSE_Sign1` signed with its Instance key, unpadded base64url; or the body member `ais` (TN-110, PI-7).",
            "schema": { "type": "string" },
        },
        "IfMatch": { "name": "If-Match", "in": "header", "required": true, "description": "The resource's ETag (OP-65): 428 without, 412 on a mismatch.", "schema": { "type": "string" } },
        "Slug": { "name": "slug", "in": "path", "required": true, "schema": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$" } },
        "PageSize": { "name": PAGE_SIZE, "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1, "maximum": MAX_PAGE, "default": DEFAULT_PAGE } },
        "Cursor": { "name": CURSOR, "in": "query", "required": false, "description": "Opaque; from the `Link` of the previous page.", "schema": { "type": "string" } },
        "Filter": { "name": FILTER, "in": "query", "required": false, "description": "SCIM filter subset: eq, ne, co, sw, pr, and, or, parentheses; an attribute the endpoint does not name is 400 (TN-112).", "schema": { "type": "string", "maxLength": access_parse::scim::MAX_LEN } },
    })
}

fn common_headers(extra: &[&str]) -> Map<String, Value> {
    ["Request-Id", "RateLimit-Policy", "RateLimit"]
        .iter()
        .chain(extra)
        .map(|h| ((*h).to_owned(), r("headers", h)))
        .collect()
}

fn problem(description: &str, extra: &[&str]) -> Value {
    json!({
        "description": description,
        "headers": common_headers(extra),
        "content": { "application/problem+json": { "schema": r("schemas", "Problem") } },
    })
}

fn responses() -> Value {
    json!({
        "BadRequest": problem("Malformed request: query, filter, cursor, body or Idempotency-Key.", &[]),
        "Unauthorized": problem("No usable credential for this surface: invalid-token, wrong-audience, token-lifetime, ais-required or ais-invalid.", &[]),
        "Forbidden": problem("insufficient-scope, ais-rejected or exercise-not-allowed.", &[]),
        "NotFound": problem("No such resource, or one the caller may not see (TN-113).", &[]),
        "Conflict": problem("idempotency-key-in-use.", &[]),
        "PreconditionFailed": problem("precondition-failed.", &[]),
        "Unprocessable": problem("idempotency-key-reused.", &[]),
        "PreconditionRequired": problem("precondition-required.", &[]),
        "TooManyRequests": problem("rate-limited.", &["Retry-After"]),
        "NotYetServed": problem("not-yet-served: the route is declared and its lane does not serve it yet; nothing was read or changed (OP-154 m.4).", &[]),
        "Unavailable": problem("A dependency is unavailable; nothing changed.", &[]),
    })
}

/// The response body schema of an operation.
fn body_of(row: &Route) -> &'static str {
    use super::platform::Shape as P;
    use super::ports::{PlatformKind, ResourceKind};
    use super::realm::{Shape, spec};
    if let Some((kind, shape)) = super::platform::spec(row.operation_id) {
        return match (kind, shape) {
            (_, P::Draft) => "IntentDraft",
            (_, P::Create) => "PlatformWriteResult",
            (PlatformKind::Tenants, P::List(_)) => "TenantPage",
            (_, P::List(_)) => "RealmPage",
            (PlatformKind::Tenants, P::Get) => "Tenant",
            (PlatformKind::Health, P::Get) => "OperatorHealth",
            (_, P::Get) => "RealmMetadata",
        };
    }
    match (row.operation_id, spec(row.operation_id)) {
        ("getPlatformSurface" | "getRealmSurface", _) => "SurfaceRoot",
        (_, Some((_, Shape::Planned(name)))) => name,
        (_, Some((_, Shape::List(_)))) => "Page",
        (_, Some((_, Shape::Draft))) => "IntentDraft",
        (_, Some((_, Shape::Write { .. }))) => "WriteResult",
        (_, Some((kind, Shape::Get))) => match kind {
            ResourceKind::Clients => "Client",
            ResourceKind::Groups => "Group",
            ResourceKind::Accounts => "Account",
            ResourceKind::UpstreamIdps => "UpstreamIdp",
            ResourceKind::Settings => "Settings",
            ResourceKind::Hooks => "Hook",
            ResourceKind::Webhooks => "Webhook",
            ResourceKind::Signals => "Signals",
            ResourceKind::Analytics => "Analytics",
            ResourceKind::Deliveries
            | ResourceKind::AgentSponsors
            | ResourceKind::VaultResources
            | ResourceKind::ProtectedResources
            | ResourceKind::TrustAnchors
            | ResourceKind::RelayUndelivered
            | ResourceKind::SamlSps
            | ResourceKind::CustomDomains
            | ResourceKind::SshHostGroups
            | ResourceKind::Proxies
            | ResourceKind::ExportSinks
            | ResourceKind::LinuxHosts
            | ResourceKind::HrSources
            | ResourceKind::HrConnectors 
            | ResourceKind::SignalSources => "Page",
            ResourceKind::SocialProviders => "SocialProvider",
            ResourceKind::Organizations => "Organization",
            ResourceKind::Agents => "Agent",
            ResourceKind::SsoEnforcementPreviews => "SsoEnforcementPreview",
        },
        _ => "ExerciseRef",
    }
}

/// The path parameters other than the slug: natural keys, never a server-internal id.
fn path_params(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .filter(|p| *p != "slug")
        .map(|p| {
            json!({
                "name": p,
                "in": "path",
                "required": true,
                "schema": { "type": "string", "maxLength": 255 },
                "description": "The resource's natural key.",
            })
        })
        .collect()
}

fn operation(row: &Route) -> Value {
    let write = row.access == Access::Write;
    let mut params = vec![r("parameters", "Traceparent")];
    if row.surface == Surface::Realm {
        params.push(r("parameters", "Slug"));
    }
    params.extend(path_params(row.path));
    for q in row.query {
        let name = match *q {
            PAGE_SIZE => "PageSize",
            CURSOR => "Cursor",
            _ => "Filter",
        };
        params.push(r("parameters", name));
    }
    if write {
        params.push(r("parameters", "IdempotencyKey"));
        params.push(r("parameters", "Ais"));
    }
    let mut ok_headers = common_headers(&[]);
    if row.query.contains(&CURSOR) {
        ok_headers.insert("Link".to_owned(), r("headers", "Link"));
    }
    if row.lifecycle.is_some() {
        ok_headers.insert("Deprecation".to_owned(), r("headers", "Deprecation"));
        ok_headers.insert("Sunset".to_owned(), r("headers", "Sunset"));
    }
    let creates = matches!(
        super::realm::spec(row.operation_id),
        Some((_, super::realm::Shape::Write { creates: true, .. }))
    ) || matches!(
        super::platform::spec(row.operation_id),
        Some((_, super::platform::Shape::Create))
    );
    let mut responses = Map::new();
    responses.insert(
        if creates { "201" } else { "200" }.to_owned(),
        json!({
            "description": if write { "Committed: the Exercise record (TN-110)." } else { "The resource." },
            "headers": ok_headers,
            "content": { "application/json": { "schema": r("schemas", body_of(row)) } },
        }),
    );
    let mut errors = vec![
        ("400", "BadRequest"),
        ("401", "Unauthorized"),
        ("404", "NotFound"),
        ("429", "TooManyRequests"),
        ("503", "Unavailable"),
    ];
    if write || row.visibility == Visibility::Forbidden {
        errors.push(("403", "Forbidden"));
    }
    if write {
        errors.extend([("409", "Conflict"), ("422", "Unprocessable")]);
    }
    // OP-154 m.4
    if super::realm::planned(row.operation_id) {
        errors.push(("501", "NotYetServed"));
    }
    for (status, name) in errors {
        responses.insert(status.to_owned(), r("responses", name));
    }
    let (security, scope) = match row.access {
        Access::Read { scope } => (json!([{ "read_token": [scope] }]), json!(scope)),
        Access::Write => (json!([{ "ais": [] }]), Value::Null),
    };
    let request_body = match (
        super::realm::spec(row.operation_id),
        super::platform::spec(row.operation_id),
    ) {
        (Some((_, super::realm::Shape::Draft)), _)
        | (_, Some((_, super::platform::Shape::Draft))) => Some("DraftRequest"),
        (Some((_, super::realm::Shape::Write { .. })), _) => Some("WriteBody"),
        (Some((_, super::realm::Shape::Planned(_))), _) if write => Some("WriteBody"),
        (_, Some((super::ports::PlatformKind::Tenants, super::platform::Shape::Create))) => {
            Some("TenantCreate")
        }
        (_, Some((_, super::platform::Shape::Create))) => Some("RealmCreate"),
        _ => None,
    };
    let mut op = json!({
        "operationId": row.operation_id,
        "summary": row.summary,
        "tags": [row.surface.name()],
        "security": security,
        "parameters": params,
        "responses": responses,
        "deprecated": row.lifecycle.is_some(),
        "x-access-surface": row.surface.name(),
        "x-access-scope": scope,
        "x-access-visibility": match row.visibility { Visibility::Hidden => "hidden", Visibility::Forbidden => "forbidden" },
    });
    if let (Some(name), Some(o)) = (request_body, op.as_object_mut()) {
        o.insert(
            "requestBody".to_owned(),
            json!({ "required": true, "content": { "application/json": { "schema": r("schemas", name) } } }),
        );
    }
    op
}

/// The document.
#[must_use]
pub fn openapi() -> Value {
    let mut paths = Map::new();
    for row in MANIFEST {
        let item = paths
            .entry(row.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(o) = item.as_object_mut() {
            o.insert(row.verb.name().to_owned(), operation(row));
        }
    }
    json!({
        "openapi": "3.1.1",
        "info": {
            "title": "Access management API",
            "version": VERSION,
            "description": "Realm-admin (`/admin/v1/realms/{slug}`) and platform-admin (`/admin/v1/platform`) surfaces on the management listener. Reads take a holder-bound DPoP token of the surface's audience living at most 60 minutes; writes take the caller's AIS and compile to an Exercise; there is no bearer management token (TN-110, TN-119, TN-130). Field names are snake_case, times RFC 3339 UTC, 64-bit integers strings (OP-65).",
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
        },
        "tags": [
            { "name": "realm", "description": format!("Realm administration; audience `{REALM_AUDIENCE_PREFIX}<slug>`, scopes `realm.*`.") },
            { "name": "platform", "description": format!("Platform administration; audience `{PLATFORM_AUDIENCE}`, scopes `platform.*`.") },
        ],
        "paths": paths,
        "components": {
            "schemas": with_workload_clients(schemas()),
            "headers": headers(),
            "parameters": parameters(),
            "responses": responses(),
            "securitySchemes": {
                "read_token": {
                    "type": "http",
                    "scheme": "DPoP",
                    "description": "A DPoP-bound access token (RFC 9449) whose one audience is the surface's and whose scopes include the operation's; at most 60 minutes; with its `DPoP` proof (TN-27, OP-151 m.3 (c)).",
                },
                "ais": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Access-AIS",
                    "description": "The caller's AIS signed with a live Instance key of the surface's governing domain (PI-7, TN-110).",
                },
            },
        },
    })
}
