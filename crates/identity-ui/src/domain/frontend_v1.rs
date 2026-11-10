//! The hosted Frontend API route table (TN-133, OP-65, OP-153 m.4): every realm-scoped route
//! the hosted pages and the embedded components call, served under the realm's host and under
//! `/realms/{slug}`. The table is the source of `sdks/openapi/frontend-v1.json`; a route not
//! yet served answers `501 not-yet-served` until its lane fills its handler and marks it live.

use serde_json::{Map, Value, json};

/// Contract version of the document.
pub const VERSION: &str = "1.0.0";

/// A route's method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`: a soft delete or a cancellation (OP-73).
    Delete,
    /// `PATCH`: the SCIM PATCH operation (RFC 7644 §3.5.2).
    Patch,
}

impl Verb {
    /// The method in lower case.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
            Self::Put => "put",
            Self::Delete => "delete",
            Self::Patch => "patch",
        }
    }
}

/// Who serves a route (OP-153 m.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// Served before Stage 8.
    Served,
    /// Account creation, enumeration and migration.
    N1,
    /// Recovery and credential reset.
    N2,
    /// B2B organizations.
    N3,
    /// Social login, linking and connected apps.
    N4,
    /// Hosted pages, DBSC, CSP reports.
    N5,
    /// Privacy and data-subject rights.
    N7,
    /// Stage 9 L2: device code (OP-154 m.2).
    L2,
    /// Stage 9 L3: agent identity and `did:web`.
    L3,
    /// Stage 9 L5: token vault.
    L5,
    /// Stage 9 L6: Access Executor and Web Bot Auth.
    L6,
    /// Stage 9 L1b: the hosted consent of clients the realm did not register.
    L1,
    /// Stage 9 L4: workload Instances and runtime attestation.
    L4,
    /// Stage 10 P2: the SAML 2.0 identity provider and WS-Federation, forwarded to the SAML gateway
    /// (OP-155 m.2).
    P2,
    /// Stage 10 P3: the SCIM 2.0 server.
    P3,
    /// Stage 10 P4: enterprise upstream federation.
    P4,
    /// Stage 10 P5: the organization's SSO setup portal.
    P5,
    /// Stage 10 P6: OpenID Federation.
    P6,
    /// Stage 10 P8: CIBA approval.
    P8,
    /// Stage 10 P9: certificate sign-in.
    P9,
    /// Stage 10 P10: directory app passwords for the LDAP gateway.
    P10,
    /// Stage 10 P12: the OID4VCI person-attribute issuer and credential offers.
    P12,
}

/// One route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// Method.
    pub verb: Verb,
    /// Path below the realm, `{name}` for a parameter.
    pub path: &'static str,
    /// `operationId`.
    pub operation: &'static str,
    /// What it does.
    pub summary: &'static str,
    /// Its lane.
    pub owner: Owner,
    /// Whether a handler serves it; otherwise it answers `501 not-yet-served`.
    pub live: bool,
}

const fn served(
    verb: Verb,
    path: &'static str,
    operation: &'static str,
    summary: &'static str,
) -> Route {
    Route {
        verb,
        path,
        operation,
        summary,
        owner: Owner::Served,
        live: true,
    }
}

const fn live(
    owner: Owner,
    verb: Verb,
    path: &'static str,
    operation: &'static str,
    summary: &'static str,
) -> Route {
    Route {
        verb,
        path,
        operation,
        summary,
        owner,
        live: true,
    }
}

const fn planned(
    owner: Owner,
    verb: Verb,
    path: &'static str,
    operation: &'static str,
    summary: &'static str,
) -> Route {
    Route {
        verb,
        path,
        operation,
        summary,
        owner,
        live: false,
    }
}

/// A Stage 8 route its lane serves now (OP-153 m.9 (e)).
const fn lane(
    owner: Owner,
    verb: Verb,
    path: &'static str,
    operation: &'static str,
    summary: &'static str,
) -> Route {
    Route {
        verb,
        path,
        operation,
        summary,
        owner,
        live: true,
    }
}

/// Every route, served ones first.
pub const ROUTES: &[Route] = &[
    served(
        Verb::Post,
        "/v1/login/flows",
        "createFlow",
        "Starts a flow; its kind is login unless the body names another.",
    ),
    served(
        Verb::Get,
        "/v1/login/flows/{flow}",
        "getFlow",
        "The flow's current step.",
    ),
    served(
        Verb::Post,
        "/v1/login/flows/{flow}",
        "submitFlow",
        "Submits one method of the current step.",
    ),
    served(
        Verb::Post,
        "/v1/login/step-up",
        "stepUp",
        "Starts a step-up for an exact action and reason (X29).",
    ),
    served(
        Verb::Post,
        "/v1/login/link/preview",
        "previewLink",
        "What a sign-in link would do, before it is confirmed.",
    ),
    served(
        Verb::Post,
        "/v1/login/link/confirm",
        "confirmLink",
        "Confirms a sign-in link on the device that asked for it.",
    ),
    served(
        Verb::Get,
        "/v1/sessions/current",
        "getCurrentSignIn",
        "This device's sign-in.",
    ),
    served(
        Verb::Get,
        "/v1/sessions",
        "listSignIns",
        "Where the account is signed in.",
    ),
    served(
        Verb::Post,
        "/v1/sessions/current/sign-out",
        "signOut",
        "Signs out on this device.",
    ),
    served(
        Verb::Post,
        "/v1/sessions/sign-out-everywhere",
        "signOutEverywhere",
        "Signs out on every device; delegations remain.",
    ),
    served(
        Verb::Post,
        "/v1/account/totp",
        "beginTotp",
        "Starts adding an authenticator app.",
    ),
    served(
        Verb::Post,
        "/v1/account/totp/{enrollment}",
        "confirmTotp",
        "Confirms an authenticator app with its first code.",
    ),
    served(
        Verb::Post,
        "/v1/account/recovery-codes",
        "regenerateRecoveryCodes",
        "Makes new recovery codes, shown once.",
    ),
    live(
        Owner::N1,
        Verb::Post,
        "/v1/account/credential-export",
        "exportCredentials",
        "The owner's password hash and authenticator app seeds, after a fresh step-up (TN-86).",
    ),
    live(
        Owner::N1,
        Verb::Post,
        "/v1/account/recovery-codes/acknowledgement",
        "acknowledgeRecoveryCodes",
        "Records the owner's \"I saved them\" for the newest recovery codes (TN-59).",
    ),
    served(
        Verb::Post,
        "/v1/account/passkeys",
        "beginPasskey",
        "Starts adding a passkey.",
    ),
    served(
        Verb::Post,
        "/v1/account/passkeys/{registration}",
        "finishPasskey",
        "Finishes adding a passkey.",
    ),
    served(
        Verb::Get,
        "/v1/account/preferences",
        "getPreferences",
        "The person's channel and topic preferences.",
    ),
    served(
        Verb::Put,
        "/v1/account/preferences",
        "setPreferences",
        "Replaces the person's preferences.",
    ),
    served(
        Verb::Get,
        "/v1/account/documents",
        "listDocuments",
        "The documents the person accepted and those awaiting acceptance.",
    ),
    served(
        Verb::Post,
        "/v1/account/documents",
        "acceptDocument",
        "Accepts one version of a document.",
    ),
    served(
        Verb::Get,
        "/v1/account/security-history",
        "getSecurityHistory",
        "The account's security history, 90 days, address prefixes only.",
    ),
    served(
        Verb::Get,
        "/v1/account/deletion",
        "getDeletion",
        "Whether the account is scheduled for deletion, and when.",
    ),
    served(
        Verb::Delete,
        "/v1/account/deletion",
        "cancelDeletion",
        "Cancels a scheduled deletion inside its window.",
    ),
    served(
        Verb::Get,
        "/v1/account/data-requests",
        "listDataRequests",
        "The person's export and deletion requests.",
    ),
    planned(
        Owner::N1,
        Verb::Post,
        "/v1/login/guest",
        "createGuest",
        "Opens a guest sign-in for a client that allows guests (OP-153 m.3 (k)).",
    ),
    live(
        Owner::N1,
        Verb::Post,
        "/v1/account/email",
        "startEmailChange",
        "Starts changing the e-mail address after a step-up (OP-153 m.3 (i)).",
    ),
    live(
        Owner::N1,
        Verb::Post,
        "/v1/account/email/{change}",
        "confirmEmailChange",
        "Confirms the new address with its out-of-band code.",
    ),
    lane(
        Owner::N2,
        Verb::Post,
        "/v1/recovery",
        "startRecovery",
        "Starts a recovery attempt; the answer is the same whether or not an account exists (OP-153 m.3 (d)).",
    ),
    lane(
        Owner::N2,
        Verb::Get,
        "/v1/recovery/{attempt}",
        "getRecovery",
        "A recovery attempt's state.",
    ),
    lane(
        Owner::N2,
        Verb::Post,
        "/v1/recovery/{attempt}",
        "proveRecovery",
        "Submits one proof to a recovery attempt.",
    ),
    live(
        Owner::N1,
        Verb::Post,
        "/v1/recovery/{attempt}/extension",
        "extendRecovery",
        "Extends the attempt's recovery contact codes once by 24 hours (OP-153 m.3 (d)).",
    ),
    lane(
        Owner::N2,
        Verb::Post,
        "/v1/recovery/intents/{token}",
        "redeemResetIntent",
        "Opens the credential-only sign-in of a reset intent (TN-61).",
    ),
    lane(
        Owner::N2,
        Verb::Get,
        "/v1/account/recovery-contacts",
        "getRecoveryContacts",
        "The account's recovery contacts, at most three.",
    ),
    lane(
        Owner::N2,
        Verb::Put,
        "/v1/account/recovery-contacts",
        "setRecoveryContacts",
        "Replaces the account's recovery contacts.",
    ),
    lane(
        Owner::N2,
        Verb::Post,
        "/v1/account/link-codes",
        "createLinkCode",
        "Makes a cross-device link code, never sent by e-mail (OP-153 m.3 (d)).",
    ),
    live(
        Owner::N3,
        Verb::Get,
        "/v1/invitations/{code}",
        "getInvitation",
        "An invitation's organization and role, as text; a scanner's GET does not consume it.",
    ),
    live(
        Owner::N3,
        Verb::Post,
        "/v1/invitations/{code}",
        "acceptInvitation",
        "Accepts an invitation (OP-153 m.3 (o)).",
    ),
    live(
        Owner::N3,
        Verb::Get,
        "/v1/account/organizations",
        "listOrganizations",
        "The organizations the person belongs to.",
    ),
    planned(
        Owner::N3,
        Verb::Post,
        "/v1/organizations",
        "createOrganization",
        "Creates an organization: party_register and idp.org.create (OP-153 m.3 (b)).",
    ),
    live(
        Owner::N3,
        Verb::Get,
        "/v1/organizations/{organization}/sign-in",
        "getOrganizationSignIn",
        "Home realm discovery by organization id (TN-3, TN-98): the target to confirm, only when the organization turned it on and holds a verified domain; the realm's sign-in policy still decides.",
    ),
    live(
        Owner::N3,
        Verb::Post,
        "/v1/organizations/{organization}/access-requests",
        "requestAccess",
        "Asks an organization's administrators for access.",
    ),
    live(
        Owner::N3,
        Verb::Get,
        "/v1/account/handovers",
        "listHandovers",
        "The open ownership handovers the person receives or, as an owner, may cancel (TN-91).",
    ),
    live(
        Owner::N3,
        Verb::Post,
        "/v1/organizations/{organization}/handovers/{handover}/contribution",
        "contributeHandover",
        "The recipient's own contribution to an ownership handover: the ExerciseID of its accept_root contribute Exercise; it still waits for its delay and the owner's signed completion (TN-91, L0-META-20).",
    ),
    live(
        Owner::N3,
        Verb::Delete,
        "/v1/organizations/{organization}/handovers/{handover}",
        "cancelHandover",
        "Cancels an open ownership handover: any owner or the recipient, until it commits; the record is kept (TN-91).",
    ),
    live(
        Owner::N3,
        Verb::Post,
        "/v1/account/guardian-consents",
        "askGuardianConsent",
        "A ward asks its guardian for consent to what the purpose digest names; the guardian is told through Relay and the request lapses after 72 hours. Silence is not consent (E53, E47).",
    ),
    live(
        Owner::N3,
        Verb::Get,
        "/v1/account/guardian-consents/{consent}",
        "getGuardianConsent",
        "What a consent answers now, to its ward or guardian: allow, deny or require_action (E47).",
    ),
    live(
        Owner::N3,
        Verb::Post,
        "/v1/account/guardian-consents/{consent}",
        "decideGuardianConsent",
        "The guardian approves or declines once, before the request lapses (E53, E47).",
    ),
    live(
        Owner::N4,
        Verb::Get,
        "/v1/login/social/{provider}",
        "startSocial",
        "Starts sign-in with a social provider (OP-153 m.3 (l)).",
    ),
    live(
        Owner::N4,
        Verb::Get,
        "/v1/login/social/{provider}/callback",
        "finishSocial",
        "The provider's redirect back; checked in the back end.",
    ),
    live(
        Owner::N4,
        Verb::Get,
        "/v1/account/linked",
        "listLinkedSignIns",
        "The account's linked sign-ins.",
    ),
    live(
        Owner::N4,
        Verb::Post,
        "/v1/account/linked",
        "startLink",
        "Links another sign-in after re-authentication (OP-153 m.3 (m)).",
    ),
    live(
        Owner::N4,
        Verb::Delete,
        "/v1/account/linked/{link}",
        "unlink",
        "Ends a linked sign-in; the record is kept.",
    ),
    live(
        Owner::N4,
        Verb::Post,
        "/v1/account/combine",
        "combineAccounts",
        "Combines two re-authenticated accounts, irreversibly (OP-153 m.3 (m)).",
    ),
    live(
        Owner::N4,
        Verb::Get,
        "/v1/account/connected-apps",
        "listConnectedApps",
        "The apps the person shares claims with (OP-153 m.3 (z)).",
    ),
    live(
        Owner::N4,
        Verb::Delete,
        "/v1/account/connected-apps/{client}",
        "stopSharing",
        "Stops sharing claims with an app.",
    ),
    live(
        Owner::N4,
        Verb::Post,
        "/v1/account/connected-apps/preview",
        "previewSharing",
        "What a waiting third-party request asks the person to share (OP-153 m.3 (z)).",
    ),
    live(
        Owner::N4,
        Verb::Post,
        "/v1/account/connected-apps",
        "shareWithApp",
        "Shares the claims a waiting third-party request asks for (OP-153 m.3 (z)).",
    ),
    live(
        Owner::N4,
        Verb::Post,
        "/v1/account/connect/preview",
        "previewConnect",
        "The S1 draft a waiting third-party request's typed bounds open (§8.17.4.3, X27).",
    ),
    live(
        Owner::N4,
        Verb::Get,
        "/v1/account/bindings",
        "listBindings",
        "This realm's halves of the account's cross-realm bindings (§12.1.3).",
    ),
    live(
        Owner::N4,
        Verb::Post,
        "/v1/account/bindings",
        "offerBinding",
        "Offers to bind the account to one in another realm, after re-authentication (§12.1.3, TN-65).",
    ),
    live(
        Owner::N4,
        Verb::Post,
        "/v1/account/bindings/accept",
        "acceptBinding",
        "Commits this realm's half with the other realm's offer token (§12.1.3).",
    ),
    live(
        Owner::N4,
        Verb::Post,
        "/v1/account/bindings/complete",
        "completeBinding",
        "Commits the offering realm's half with the accepting realm's token (§12.1.3).",
    ),
    live(
        Owner::N5,
        Verb::Post,
        "/v1/sessions/{session}/end",
        "endSignIn",
        "Ends another device's sign-in; names the device Instance whose instance.terminate the page then signs (OP-153 m.3 (y)).",
    ),
    live(
        Owner::N5,
        Verb::Post,
        "/v1/dbsc/register",
        "registerBoundSignIn",
        "Ties this sign-in to the device (DBSC, OP-153 m.3 (y)).",
    ),
    live(
        Owner::N5,
        Verb::Post,
        "/v1/dbsc/refresh",
        "refreshBoundSignIn",
        "Refreshes a device-tied sign-in.",
    ),
    live(
        Owner::N5,
        Verb::Post,
        "/csp-reports",
        "reportCsp",
        "Receives CSP reports, 100 a minute per realm (OP-153 m.3 (t)).",
    ),
    live(
        Owner::N5,
        Verb::Get,
        "/v1/login/branding",
        "getBranding",
        "The realm's branding record as the hosted pages draw it: name and logo URL (TN-106, OP-153 m.3 (t)).",
    ),
    live(
        Owner::N5,
        Verb::Get,
        "/v1/login/messages",
        "getMessageOverrides",
        "The realm's own texts for unprotected message keys, by locale and key, which the hosted pages draw in place of Access's (X35, OP-153 m.22 (k)).",
    ),
    live(
        Owner::N5,
        Verb::Post,
        "/v1/account/connected-apps/decline",
        "declineSharing",
        "The person chose not to share: the waiting request goes back to the app with access_denied (X-L8).",
    ),
    live(
        Owner::N5,
        Verb::Get,
        "/v1/account/methods",
        "listSignInMethods",
        "The account's sign-in methods for S11: password, passkeys, authenticator apps, recovery codes (TN-99, OP-148).",
    ),
    live(
        Owner::N5,
        Verb::Delete,
        "/v1/account/methods/{credential}",
        "removeSignInMethod",
        "Removes a sign-in method after a recent re-authentication; never the last one (TN-68).",
    ),
    live(
        Owner::N5,
        Verb::Put,
        "/v1/account/password",
        "setPassword",
        "Sets or changes the password after a recent re-authentication; other sign-ins end (TN-50).",
    ),
    planned(
        Owner::N7,
        Verb::Post,
        "/v1/account/data-requests",
        "requestExport",
        "Asks for the person's export: idp.account.export (OP-153 m.3 (cc)).",
    ),
    live(
        Owner::L2,
        Verb::Get,
        "/device",
        "deviceVerificationPage",
        "The RFC 8628 verification page, a trusted surface of its own: the person enters the code a device shows (OP-154 m.3 (p)).",
    ),
    live(
        Owner::L2,
        Verb::Post,
        "/v1/device/preview",
        "previewDeviceCode",
        "What a user code asks for: the client's name, the scope, and the IP prefix and country the request came from; five wrong codes wait 15 minutes (OP-154 m.3 (p)).",
    ),
    live(
        Owner::L2,
        Verb::Post,
        "/v1/device/approval",
        "approveDeviceCode",
        "Approves or declines a user code with the person's AAS; the token it releases is DPoP-bound (OP-154 m.3 (p)).",
    ),
    live(
        Owner::L3,
        Verb::Get,
        "/v1/account/agent-connections",
        "listAgentConnections",
        "The person's agents (those they sponsor and those that used their accounts) and their connected accounts: name, kind, status, sponsor, last use; never a token or authority (OP-154 m.3 (e), (t)).",
    ),
    live(
        Owner::L5,
        Verb::Get,
        "/v1/account/vault/connections",
        "listVaultConnections",
        "The person's connected accounts for agents, each with its upstream, scopes and state; never a token (OP-154 m.3 (t)).",
    ),
    live(
        Owner::L5,
        Verb::Post,
        "/v1/account/vault/connections",
        "startVaultConnection",
        "Starts connecting an upstream account after the person's AAS for that client (AS-M15, OP-154 m.3 (t)).",
    ),
    live(
        Owner::L5,
        Verb::Get,
        "/v1/account/vault/connections/{connection}",
        "getVaultConnection",
        "One connected account: upstream, scopes, state (`active` or `needs_reconnect`); never a token.",
    ),
    live(
        Owner::L5,
        Verb::Delete,
        "/v1/account/vault/connections/{connection}",
        "disconnectVaultConnection",
        "Disconnects an account: the TokenSet ends and is revoked upstream where it can be; nothing is deleted (OP-73).",
    ),
    live(
        Owner::L5,
        Verb::Post,
        "/v1/vault/releases",
        "releaseVaultToken",
        "Releases an upstream token only for an allowed Exercise whose PEP is the calling registered executor Instance, once per step, expiring by the horizon (G59, EI-26, OP-154 m.3 (t)).",
    ),
    planned(
        Owner::L6,
        Verb::Get,
        "/.well-known/http-message-signatures-directory",
        "webBotAuthDirectory",
        "The Web Bot Auth key directory: the Ed25519 keys bound to live agent Instances; revoking an Instance removes its key (RFC 9421, OP-154 m.3 (u)).",
    ),
    live(
        Owner::L1,
        Verb::Post,
        "/v1/login/approval/preview",
        "previewApproval",
        "What the consent screen of a client the realm did not register shows: hostnames, the client's own claims, the resource, the scopes, the grant.issue the person's device Instance signs, and the CSRF token (§11.6, AS-M14, OP-154 m.3 (k)).",
    ),
    live(
        Owner::L1,
        Verb::Post,
        "/v1/login/approval",
        "approveClient",
        "Keeps the consent record once the named Exercise is the person's own allowed grant.issue, then sends the browser back to the request (EI-18, P58).",
    ),
    live(
        Owner::L1,
        Verb::Post,
        "/v1/login/approval/decline",
        "declineClient",
        "The person declined: the waiting request goes back to the client with access_denied and nothing is kept (X-L8).",
    ),
    live(
        Owner::L3,
        Verb::Get,
        "/u/{party}/did.json",
        "didWebDocument",
        "The did:web document of a person or agent: verification keys and service endpoints; an identifier, never authority (OP-154 m.3 (aa)).",
    ),
    live(
        Owner::L4,
        Verb::Post,
        "/v1/workloads/instances",
        "openWorkloadInstance",
        "A workload's key opens its own Instance of its agent with a self-signed instance_create; it stands only on the realm issuer's identity_binding_workload Claim about that key and still needs a Grant to act (OP-154 m.3 (d)).",
    ),
    live(
        Owner::L4,
        Verb::Post,
        "/v1/workloads/attestations",
        "attestWorkload",
        "Android key or TPM 2.0 evidence that an Instance's own key lives in hardware, for the challenge of that Instance and time; the realm issuer's attestation_runtime Claim bound to the Instance follows and grants nothing (§5.9, OP-154 m.3 (s)).",
    ),
    live(
        Owner::P3,
        Verb::Get,
        "/scim/v2/Users",
        "scimListUsers",
        "SCIM: lists or filters Users; filter depth ≤ 32 and length ≤ 4 KB, at most 1000 results, pages of at most 200 with an HMAC'd RFC 9865 cursor (OP-155 m.3 (g)).",
    ),
    live(
        Owner::P3,
        Verb::Post,
        "/scim/v2/Users",
        "scimCreateUser",
        "SCIM: creates a User; the writes go through the account use cases and the client is a Claim source, never a grantor (IDP-23).",
    ),
    live(
        Owner::P3,
        Verb::Get,
        "/scim/v2/Users/{id}",
        "scimGetUser",
        "SCIM: one User; a deleted one answers 404.",
    ),
    live(
        Owner::P3,
        Verb::Put,
        "/scim/v2/Users/{id}",
        "scimReplaceUser",
        "SCIM: replaces a User.",
    ),
    live(
        Owner::P3,
        Verb::Patch,
        "/scim/v2/Users/{id}",
        "scimPatchUser",
        "SCIM: PATCH of a User, atomic: one failed operation fails them all.",
    ),
    live(
        Owner::P3,
        Verb::Delete,
        "/scim/v2/Users/{id}",
        "scimDeleteUser",
        "SCIM: soft-deletes a User with a tombstone; its id and externalId are never reused (INV-32, OP-73).",
    ),
    live(
        Owner::P3,
        Verb::Get,
        "/scim/v2/Groups",
        "scimListGroups",
        "SCIM: lists or filters Groups; filter depth ≤ 32 and length ≤ 4 KB, at most 1000 results, pages of at most 200 with an HMAC'd RFC 9865 cursor (OP-155 m.3 (g)).",
    ),
    live(
        Owner::P3,
        Verb::Post,
        "/scim/v2/Groups",
        "scimCreateGroup",
        "SCIM: creates a Group; the writes go through the account use cases and the client is a Claim source, never a grantor (IDP-23).",
    ),
    live(
        Owner::P3,
        Verb::Get,
        "/scim/v2/Groups/{id}",
        "scimGetGroup",
        "SCIM: one Group; a deleted one answers 404.",
    ),
    live(
        Owner::P3,
        Verb::Put,
        "/scim/v2/Groups/{id}",
        "scimReplaceGroup",
        "SCIM: replaces a Group.",
    ),
    live(
        Owner::P3,
        Verb::Patch,
        "/scim/v2/Groups/{id}",
        "scimPatchGroup",
        "SCIM: PATCH of a Group, atomic: one failed operation fails them all.",
    ),
    live(
        Owner::P3,
        Verb::Delete,
        "/scim/v2/Groups/{id}",
        "scimDeleteGroup",
        "SCIM: soft-deletes a Group with a tombstone; its id and externalId are never reused (INV-32, OP-73).",
    ),
    live(
        Owner::P3,
        Verb::Get,
        "/scim/v2/Devices",
        "scimListDevices",
        "SCIM: lists or filters Devices; filter depth ≤ 32 and length ≤ 4 KB, at most 1000 results, pages of at most 200 with an HMAC'd RFC 9865 cursor (OP-155 m.3 (g)).",
    ),
    live(
        Owner::P3,
        Verb::Post,
        "/scim/v2/Devices",
        "scimCreateDevice",
        "SCIM: creates a Device; the writes go through the account use cases and the client is a Claim source, never a grantor (IDP-23).",
    ),
    live(
        Owner::P3,
        Verb::Get,
        "/scim/v2/Devices/{id}",
        "scimGetDevice",
        "SCIM: one Device; a deleted one answers 404.",
    ),
    live(
        Owner::P3,
        Verb::Put,
        "/scim/v2/Devices/{id}",
        "scimReplaceDevice",
        "SCIM: replaces a Device.",
    ),
    live(
        Owner::P3,
        Verb::Patch,
        "/scim/v2/Devices/{id}",
        "scimPatchDevice",
        "SCIM: PATCH of a Device, atomic: one failed operation fails them all.",
    ),
    live(
        Owner::P3,
        Verb::Delete,
        "/scim/v2/Devices/{id}",
        "scimDeleteDevice",
        "SCIM: soft-deletes a Device with a tombstone; its id and externalId are never reused (INV-32, OP-73).",
    ),
    live(
        Owner::P3,
        Verb::Get,
        "/scim/v2/ServiceProviderConfig",
        "scimServiceProviderConfig",
        "SCIM: what the server supports; bulk.supported is false.",
    ),
    live(
        Owner::P3,
        Verb::Get,
        "/scim/v2/ResourceTypes",
        "scimResourceTypes",
        "SCIM: the resource types, User, Group and Device.",
    ),
    live(
        Owner::P3,
        Verb::Get,
        "/scim/v2/Schemas",
        "scimSchemas",
        "SCIM: the schemas and extensions the server knows.",
    ),
    live(
        Owner::P3,
        Verb::Post,
        "/scim/v2/Bulk",
        "scimBulk",
        "SCIM Bulk is not offered and always answers 501 (OP-155 m.3 (g)).",
    ),
    live(
        Owner::P2,
        Verb::Get,
        "/saml/metadata",
        "samlMetadata",
        "The SAML IdP metadata, signed with the realm's saml key (OP-155 m.3 (e)).",
    ),
    live(
        Owner::P2,
        Verb::Get,
        "/saml/sso",
        "samlSsoRedirect",
        "SAML SSO, HTTP-Redirect binding: access-server keeps the cookies and forwards the AuthnRequest to the SAML gateway with session_attest (OP-155 m.3 (c)).",
    ),
    live(
        Owner::P2,
        Verb::Post,
        "/saml/sso",
        "samlSsoPost",
        "SAML SSO, HTTP-POST binding.",
    ),
    live(
        Owner::P2,
        Verb::Get,
        "/saml/sso/{sp}",
        "samlIdpInitiated",
        "IdP-initiated SSO to one service provider, only when its registration allows it; the assertion lives 2 minutes.",
    ),
    live(
        Owner::P2,
        Verb::Get,
        "/saml/slo",
        "samlSloRedirect",
        "SAML single logout, HTTP-Redirect binding.",
    ),
    live(
        Owner::P2,
        Verb::Post,
        "/saml/slo",
        "samlSloPost",
        "SAML single logout, HTTP-POST binding.",
    ),
    live(
        Owner::P2,
        Verb::Post,
        "/saml/ecp",
        "samlEcp",
        "SAML ECP (PAOS) with a per-application credential, never Basic authentication with the account's password (OP-155 m.3 (e)).",
    ),
    live(
        Owner::P2,
        Verb::Get,
        "/wsfed",
        "wsfedPassive",
        "WS-Federation passive requestor: wsignin1.0 and wsignout1.0 with a SAML 1.1 or 2.0 token per relying party (OP-155 m.3 (f)).",
    ),
    live(
        Owner::P2,
        Verb::Post,
        "/wsfed",
        "wsfedPassivePost",
        "WS-Federation passive requestor, POST form.",
    ),
    live(
        Owner::P2,
        Verb::Get,
        "/wsfed/metadata",
        "wsfedMetadata",
        "The WS-Federation metadata document.",
    ),
    planned(
        Owner::P4,
        Verb::Get,
        "/v1/login/upstream/{connection}",
        "startUpstreamSignIn",
        "Starts sign-in at an enterprise upstream identity provider (OIDC or SAML); home realm discovery confirms the organization first when it is on (OP-155 m.3 (h)).",
    ),
    planned(
        Owner::P4,
        Verb::Get,
        "/v1/login/upstream/{connection}/callback",
        "upstreamCallback",
        "The OIDC upstream's redirect back; its subject key is the connection's own, sub or [tid, oid].",
    ),
    planned(
        Owner::P4,
        Verb::Post,
        "/v1/login/upstream/{connection}/saml/acs",
        "upstreamSamlAcs",
        "The SAML upstream's assertion consumer service; an unsolicited Response is refused unless the connection opens it, and the raw assertion is sealed under the subject's DEK.",
    ),
    planned(
        Owner::P4,
        Verb::Get,
        "/v1/login/upstream/{connection}/saml/metadata",
        "upstreamSamlMetadata",
        "Access's SP metadata for one SAML upstream connection.",
    ),
    planned(
        Owner::P5,
        Verb::Get,
        "/v1/sso-setup/{link}",
        "getSsoSetup",
        "What a one-use, 72-hour organization setup link opens: the organization and the wizard's steps (OP-155 m.3 (i)).",
    ),
    planned(
        Owner::P5,
        Verb::Post,
        "/v1/sso-setup/{link}",
        "submitSsoSetup",
        "Submits a wizard step: the identity provider's metadata or a test sign-in; enacting the connection stays the organization root's idp.upstream.register.",
    ),
    live(
        Owner::P6,
        Verb::Get,
        "/.well-known/openid-federation",
        "oidfEntityConfiguration",
        "The realm issuer's OpenID Federation entity configuration, signed with its federation key (OP-155 m.3 (j)).",
    ),
    live(
        Owner::P6,
        Verb::Get,
        "/federation/fetch",
        "oidfFetch",
        "Fetches a subordinate statement; served only in the intermediate or trust anchor role.",
    ),
    live(
        Owner::P6,
        Verb::Get,
        "/federation/list",
        "oidfList",
        "Lists subordinates; served only in the intermediate or trust anchor role.",
    ),
    planned(
        Owner::P6,
        Verb::Get,
        "/federation/resolve",
        "oidfResolve",
        "Resolves an entity's metadata through its trust chain, at most 8 links; rate-limited.",
    ),
    planned(
        Owner::P6,
        Verb::Post,
        "/federation/trust_mark_status",
        "oidfTrustMarkStatus",
        "Whether a trust mark is still active.",
    ),
    planned(
        Owner::P6,
        Verb::Post,
        "/federation/register",
        "oidfRegister",
        "Explicit OIDF client registration, when the realm opened it.",
    ),
    live(
        Owner::P8,
        Verb::Post,
        "/v1/ciba/preview",
        "previewCiba",
        "What a CIBA request asks: the client's name, the binding message and the scope, for the person's Approval Surface (OP-155 m.3 (l)).",
    ),
    live(
        Owner::P8,
        Verb::Post,
        "/v1/ciba/approval",
        "approveCiba",
        "Approves or declines a CIBA request with the person's AAS; the client learns it by poll or ping.",
    ),
    live(
        Owner::P9,
        Verb::Get,
        "/login/certificate",
        "certificateLoginPage",
        "Certificate, PIV and CAC sign-in on the mTLS listener: trust comes only from TLS that ends at access-server, never from a forwarded header (OP-155 m.3 (k), (m)).",
    ),
    planned(
        Owner::P10,
        Verb::Get,
        "/v1/account/ldap-credentials",
        "listLdapCredentials",
        "The person's directory app passwords: application, created, last used; never the password (OP-155 m.3 (n)).",
    ),
    planned(
        Owner::P10,
        Verb::Post,
        "/v1/account/ldap-credentials",
        "createLdapCredential",
        "Creates a directory app password for one application, shown once and kept as Argon2id.",
    ),
    planned(
        Owner::P10,
        Verb::Post,
        "/v1/account/ldap-credentials/{credential}/revoke",
        "revokeLdapCredential",
        "Revokes a directory app password; nothing is deleted (OP-73).",
    ),
    planned(
        Owner::P12,
        Verb::Get,
        "/.well-known/openid-credential-issuer",
        "oid4vciIssuerMetadata",
        "The OID4VCI issuer metadata of the person-attribute issuer (OP-155 m.3 (p)).",
    ),
    planned(
        Owner::P12,
        Verb::Post,
        "/oid4vci/credential",
        "oid4vciCredential",
        "Issues one person-attribute credential bound to the holder's device key or agent KeyBinding; other types are refused.",
    ),
    planned(
        Owner::P12,
        Verb::Post,
        "/oid4vci/nonce",
        "oid4vciNonce",
        "A fresh c_nonce for the holder's key proof.",
    ),
    planned(
        Owner::P12,
        Verb::Get,
        "/v1/account/credential-offers",
        "listCredentialOffers",
        "The credential types the person may add to a wallet.",
    ),
    planned(
        Owner::P12,
        Verb::Post,
        "/v1/account/credential-offers",
        "createCredentialOffer",
        "Makes a pre-authorized credential offer for one type, after the person's AAS.",
    ),
];

fn parameters(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } }))
        .collect()
}

/// `sdks/openapi/frontend-v1.json`.
#[must_use]
pub fn openapi() -> Value {
    let mut paths = Map::new();
    for r in ROUTES {
        let mut responses = Map::new();
        if r.live {
            responses.insert(
                String::from("200"),
                json!({ "description": "OK", "content": { "application/json": { "schema": { "type": "object" } } } }),
            );
        } else {
            responses.insert(
                String::from("501"),
                json!({ "$ref": "#/components/responses/NotYetServed" }),
            );
        }
        responses.insert(
            String::from("default"),
            json!({ "$ref": "#/components/responses/Problem" }),
        );
        let mut op = Map::new();
        op.insert(String::from("operationId"), Value::from(r.operation));
        op.insert(String::from("summary"), Value::from(r.summary));
        op.insert(String::from("responses"), Value::Object(responses));
        let params = parameters(r.path);
        if !params.is_empty() {
            op.insert(String::from("parameters"), Value::Array(params));
        }
        if matches!(r.verb, Verb::Post | Verb::Put) {
            op.insert(
                String::from("requestBody"),
                json!({ "content": { "application/json": { "schema": { "type": "object" } } } }),
            );
        }
        if !r.live {
            op.insert(String::from("x-suiss-status"), Value::from("planned"));
        }
        let op = Value::Object(op);
        let entry = paths
            .entry(String::from(r.path))
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(m) = entry {
            m.insert(String::from(r.verb.name()), op);
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Access hosted Frontend API",
            "version": VERSION,
            "description": "The realm-scoped routes of the hosted pages and embedded components (TN-133), served under the realm's host and under /realms/{slug}. A planned route answers 501 not-yet-served.",
        },
        "paths": Value::Object(paths),
        "components": {
            "schemas": {
                "Problem": {
                    "type": "object",
                    "required": ["type", "title", "status", "code"],
                    "properties": {
                        "type": { "type": "string" },
                        "title": { "type": "string" },
                        "status": { "type": "integer" },
                        "code": { "type": "string" },
                        "reason": { "type": "string" },
                    },
                },
            },
            "responses": {
                "Problem": {
                    "description": "An RFC 9457 problem.",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
                },
                "NotYetServed": {
                    "description": "The route is declared and not served yet (OP-153 m.4).",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } },
                },
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    // OP-153 m.4, OP-65
    #[test]
    fn every_route_and_operation_is_declared_once() {
        let ops: BTreeSet<_> = ROUTES.iter().map(|r| r.operation).collect();
        assert_eq!(ops.len(), ROUTES.len());
        let keys: BTreeSet<_> = ROUTES.iter().map(|r| (r.verb.name(), r.path)).collect();
        assert_eq!(keys.len(), ROUTES.len());
        assert!(ROUTES.iter().all(|r| r.live || r.owner != Owner::Served));
    }
}
