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
    planned(
        Owner::N2,
        Verb::Post,
        "/v1/recovery",
        "startRecovery",
        "Starts a recovery attempt; the answer is the same whether or not an account exists (OP-153 m.3 (d)).",
    ),
    planned(
        Owner::N2,
        Verb::Get,
        "/v1/recovery/{attempt}",
        "getRecovery",
        "A recovery attempt's state.",
    ),
    planned(
        Owner::N2,
        Verb::Post,
        "/v1/recovery/{attempt}",
        "proveRecovery",
        "Submits one proof to a recovery attempt.",
    ),
    planned(
        Owner::N2,
        Verb::Post,
        "/v1/recovery/intents/{token}",
        "redeemResetIntent",
        "Opens the credential-only sign-in of a reset intent (TN-61).",
    ),
    planned(
        Owner::N2,
        Verb::Get,
        "/v1/account/recovery-contacts",
        "getRecoveryContacts",
        "The account's recovery contacts, at most three.",
    ),
    planned(
        Owner::N2,
        Verb::Put,
        "/v1/account/recovery-contacts",
        "setRecoveryContacts",
        "Replaces the account's recovery contacts.",
    ),
    planned(
        Owner::N2,
        Verb::Post,
        "/v1/account/link-codes",
        "createLinkCode",
        "Makes a cross-device link code, never sent by e-mail (OP-153 m.3 (d)).",
    ),
    planned(
        Owner::N3,
        Verb::Get,
        "/v1/invitations/{code}",
        "getInvitation",
        "An invitation's organization and inviter, as text; a scanner's GET does not consume it.",
    ),
    planned(
        Owner::N3,
        Verb::Post,
        "/v1/invitations/{code}",
        "acceptInvitation",
        "Accepts an invitation (OP-153 m.3 (o)).",
    ),
    planned(
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
    planned(
        Owner::N3,
        Verb::Post,
        "/v1/organizations/{organization}/access-requests",
        "requestAccess",
        "Asks an organization's administrators for access.",
    ),
    planned(
        Owner::N4,
        Verb::Get,
        "/v1/login/social/{provider}",
        "startSocial",
        "Starts sign-in with a social provider (OP-153 m.3 (l)).",
    ),
    planned(
        Owner::N4,
        Verb::Get,
        "/v1/login/social/{provider}/callback",
        "finishSocial",
        "The provider's redirect back; checked in the back end.",
    ),
    planned(
        Owner::N4,
        Verb::Get,
        "/v1/account/linked",
        "listLinkedSignIns",
        "The account's linked sign-ins.",
    ),
    planned(
        Owner::N4,
        Verb::Post,
        "/v1/account/linked",
        "startLink",
        "Links another sign-in after re-authentication (OP-153 m.3 (m)).",
    ),
    planned(
        Owner::N4,
        Verb::Delete,
        "/v1/account/linked/{link}",
        "unlink",
        "Ends a linked sign-in; the record is kept.",
    ),
    planned(
        Owner::N4,
        Verb::Post,
        "/v1/account/combine",
        "combineAccounts",
        "Combines two re-authenticated accounts, irreversibly (OP-153 m.3 (m)).",
    ),
    planned(
        Owner::N4,
        Verb::Get,
        "/v1/account/connected-apps",
        "listConnectedApps",
        "The apps the person shares claims with (OP-153 m.3 (z)).",
    ),
    planned(
        Owner::N4,
        Verb::Delete,
        "/v1/account/connected-apps/{client}",
        "stopSharing",
        "Stops sharing claims with an app.",
    ),
    planned(
        Owner::N5,
        Verb::Post,
        "/v1/sessions/{instance}/end",
        "endSignIn",
        "Ends another device's sign-in: instance.terminate (OP-153 m.3 (y)).",
    ),
    planned(
        Owner::N5,
        Verb::Post,
        "/v1/dbsc/register",
        "registerBoundSignIn",
        "Ties this sign-in to the device (DBSC, OP-153 m.3 (y)).",
    ),
    planned(
        Owner::N5,
        Verb::Post,
        "/v1/dbsc/refresh",
        "refreshBoundSignIn",
        "Refreshes a device-tied sign-in.",
    ),
    planned(
        Owner::N5,
        Verb::Post,
        "/csp-reports",
        "reportCsp",
        "Receives CSP reports, 100 a minute per realm (OP-153 m.3 (t)).",
    ),
    planned(
        Owner::N7,
        Verb::Post,
        "/v1/account/data-requests",
        "requestExport",
        "Asks for the person's export: idp.account.export (OP-153 m.3 (cc)).",
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
