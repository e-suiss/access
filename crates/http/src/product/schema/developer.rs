//! The ADP search route and its developer-surface kinds (L1-ADP-16, §8.17.10, §5.4, §16.5.1):
//! `schema-publications`, `change-impact`, `revocation-impact`, `compromise-impact` and
//! `bulk-impact`, and the management kinds `roles`, `role`, `admin-grant`, `holdings` and
//! `changes` (§8.17.9, IA-2, IA-5), and the hub kinds `inventory` and
//! `activity` (§8.17.7.1, S6), which answer only the reading Party about itself (XI-9, XI-22). Each answers one advisory page; none of them writes, and none
//! carries an accept or any other action (X21). Schema publication (§8.17.10.2, X21) and the
//! JSON form of meta-action payloads (L1-ADP-17) are here too.

use serde_json::{Map, Value, json};

use super::{object, path, r, text};

fn b64(description: &str) -> Value {
    json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]+$", "description": description })
}

fn uint(description: &str) -> Value {
    json!({ "type": "integer", "minimum": 0, "description": description })
}

fn list(items: &Value, description: &str) -> Value {
    json!({ "type": "array", "items": items, "description": description })
}

/// The search request and the developer report schemas.
pub(super) fn components() -> Value {
    let mut all = queries();
    for more in [
        reports(),
        management(),
        sources(),
        publications(),
        hub(),
        incarnations(),
        discovered(),
    ] {
        if let (Value::Object(m), Value::Object(more)) = (&mut all, more) {
            m.extend(more);
        }
    }
    if let Value::Object(m) = &mut all {
        for (name, schema) in crate::adp::payload::schemas() {
            m.insert(name.to_owned(), schema);
        }
    }
    all
}

fn meta_line() -> Value {
    object(
        &json!({
            "action": text("The core meta-action (L0-META-1); the console shows its plain label, never this id."),
            "tier_when_widening": { "type": "string", "enum": ["ct0", "ct1", "ct2", "ct3"] },
            "grant_quorum": uint("Contributions the Grant's own requirements ask for."),
            "joint_root_quorum": uint("Further `co_root` contributions a joint root needs at CT3 (§13.7.3)."),
        }),
        &[
            "action",
            "tier_when_widening",
            "grant_quorum",
            "joint_root_quorum",
        ],
    )
}

/// The Sources kind (§8.17.9.3, §5.13).
fn sources() -> Value {
    json!({
        "Sources": object(
            &json!({
                "type": { "const": "sources" },
                "sources": list(&json!({ "type": "object" }), "`{acceptance, use, issuer: {party}|{foreign}, classes, namespace, since, protected, dependents}`: each live Acceptance by its canonical use; `dependents` is its blast radius, the live Grants that depend on it (§8.17.9.3, INV-15)."),
                "partners": list(&json!({ "type": "object" }), "`{domain, acceptances, ceilings: [{grant, class, actions, resource, until}]}`: each partner domain and the ceilings of the bridging Grants that recognize its authority (§5.13)."),
                "advisory": { "const": true },
            }),
            &["type", "sources", "partners", "advisory"],
        ),
    })
}

/// The management kinds (§8.17.9, IA-2, IA-5, E17).
fn management() -> Value {
    json!({
        "RolesQuery": object(&json!({}), &[]),
        "RoleQuery": object(
            &json!({
                "name": text("The Named AuthoritySet."),
                "version": uint("The version; the latest when absent."),
            }),
            &["name"],
        ),
        "AdminGrantQuery": object(&json!({ "grant": b64("The Grant.") }), &["grant"]),
        "HoldingsQuery": object(&json!({}), &[]),
        "ChangesQuery": object(&json!({ "before": uint("Only changes recorded before this position; the newest when absent.") }), &[]),
        "BulkImpactQuery": object(
            &json!({ "revoke": { "type": "array", "minItems": 1, "maxItems": 100, "uniqueItems": true, "items": b64("A Grant the job revokes, one Exercise each.") } }),
            &["revoke"],
        ),
        "Roles": object(
            &json!({
                "type": { "const": "roles" },
                "roles": list(&object(&json!({ "name": text("Name."), "latest": uint("Latest version.") }), &["name", "latest"]), "The domain's Named AuthoritySets."),
                "advisory": { "const": true },
            }),
            &["type", "roles", "advisory"],
        ),
        "RoleVersion": object(
            &json!({
                "type": { "const": "role" },
                "name": text("Name."),
                "version": uint("This version."),
                "latest": uint("The latest version of the name."),
                "digest": b64("The digest a Grant pins it by."),
                "since": uint("The position that defined it."),
                "authority": r("AuthoritySet"),
                "not_included": object(
                    &json!({
                        "reserved": list(&r("KernelActionRef"), "Reserved actions of its prefix namespaces it does not name: only a delegation that names one includes it."),
                        "catalogs": list(&json!({ "type": "object" }), "`{namespace, catalog, catalog_version, newer}`: a catalog-pinned prefix (\"as of catalog vN\") and the actions accepted after it, not included (E11)."),
                    }),
                    &["reserved", "catalogs"],
                ),
                "advisory": { "const": true },
            }),
            &["type", "name", "version", "latest", "digest", "since", "authority", "not_included", "advisory"],
        ),
        "AdminGrant": object(
            &json!({
                "type": { "const": "admin_grant" },
                "grant": b64("The Grant."),
                "role": { "type": ["object", "null"], "description": "`{name, version}`: its role pin." },
                "actions": list(&meta_line(), "Covered meta-actions that are not reserved, one by one; only what it covers."),
                "reserved": list(&meta_line(), "Covered reserved meta-actions (`acceptance.*`, `anchor.*`), shown apart: only a pinned Grant that names them covers them."),
                "advisory": { "const": true },
            }),
            &["type", "grant", "actions", "reserved", "advisory"],
        ),
        "Holding": object(
            &json!({
                "type": { "const": "holding" },
                "grant": b64("The Grant."),
                "holder": b64("The viewer's own Party."),
                "since": uint("The position that opened the holding episode; with `grant` and `holder` it is an ADP `holding` basis."),
                "actions": list(&r("KernelActionRef"), "The actions it covers now."),
                "resource": r("KernelResourceSelector"),
                "advisory": { "const": true },
            }),
            &["type", "grant", "holder", "since", "actions", "resource", "advisory"],
        ),
        "Change": object(
            &json!({
                "type": { "const": "change" },
                "position": r("Position"),
                "at": uint("Its trusted time, Unix ms."),
                "kind": { "type": "string", "enum": ["grant", "anchor", "party", "instance", "mandate", "acceptance", "policy", "authority_set", "key_event"] },
                "id": text("The object: an id in base64url, or a role's name; for a key event, the Claim."),
                "class": text("For a key event: the Claim class (U26, SI-13)."),
                "issuer": b64("For a key event: who signed it."),
                "version": { "type": ["integer", "null"], "description": "For a role: the version defined." },
                "ended": { "type": "boolean", "description": "The change ended the object." },
                "own": { "type": "boolean", "description": "The viewer's own Instance made it." },
                "advisory": { "const": true },
            }),
            &["type", "position", "at", "kind", "id", "ended", "own", "advisory"],
        ),
        "BulkImpact": object(
            &json!({
                "type": { "const": "bulk_impact" },
                "revoke": list(&b64("Grant"), "The Grants of the job."),
                "items": list(&r("RevocationImpact"), "Each item's own preview, in order."),
                "subtree": list(&b64("Grant"), "Every Grant that ends with the job, once."),
                "aftermath": { "type": "object", "description": "`{grants_ending, projections_open, honoured_until_ms, running_copies, confirmed_applied}` over the job (XI-3)." },
                "max_exposure_ms": uint("The longest window of any item."),
                "advisory": { "const": true },
            }),
            &["type", "revoke", "items", "subtree", "aftermath", "max_exposure_ms", "advisory"],
        ),
    })
}

/// Schema publication (§8.17.10.2, E10–E12, X21).
fn publications() -> Value {
    json!({
        "PublicationDraft": object(
            &json!({
                "namespace": text("The action namespace."),
                "catalog_version": uint("The catalog version; after the publisher's latest one (E10)."),
                "actions": list(&r("KernelActionSchema"), "The typed Action Schemas."),
                "classes": list(
                    &object(
                        &json!({
                            "action": text("Action name."),
                            "parameter": text("Parameter name."),
                            "class": { "type": "string", "enum": ["opaque", "recipient", "amount", "count", "choice", "flag"], "description": "`opaque`, or what an authority-relevant parameter decides (E12)." },
                        }),
                        &["action", "parameter", "class"],
                    ),
                    "The class of every declared parameter (§9.13.3).",
                ),
                "retirements": list(&r("KernelActionRef"), "Retired actions."),
                "core_spec_min": uint("Lowest core spec version it needs."),
                "compatibility": object(
                    &json!({
                        "from": uint("An earlier published version."),
                        "relation": { "type": "string", "enum": ["representation-equivalent", "narrowing", "broadening", "incompatible"] },
                    }),
                    &["from", "relation"],
                ),
            }),
            &["namespace", "catalog_version", "actions", "classes"],
        ),
        "PublishRequest": object(
            &json!({
                "context": { "type": "object", "description": "The publisher's `check` context (L1-ADP-5…9): the intent's action is `access`/`publish`, its resource `access.publication` with the path `[namespace]`, and `opaque.package` the digest of `package` (L1-ADP-18). Its AIS makes the publisher known." },
                "package": r("PublicationDraft"),
                "domains": { "type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true, "items": b64("A domain the package is offered to."), "description": "Where it is offered; each keeps it in its own scope (TN-20)." },
            }),
            &["context", "package", "domains"],
        ),
        "Published": object(
            &json!({
                "fingerprint": b64("The exact digest a `schema-definition` Acceptance pins (E10)."),
                "publisher": b64("The publisher Party: the actor of the AIS."),
                "namespace": text("The namespace."),
                "catalog_version": uint("The catalog version."),
                "new": { "type": "boolean", "description": "Kept now; `false` when every domain already had this exact package." },
                "existing_grants_unchanged": { "const": true },
                "new_actions": list(&json!({ "type": "string" }), "Not included in delegations whose catalog is pinned (E11)."),
                "text": list(&json!({ "type": "string" }), "Text keys, in order."),
            }),
            &["fingerprint", "publisher", "namespace", "catalog_version", "new", "existing_grants_unchanged", "new_actions", "text"],
        ),
        "PublicationWarnings": object(
            &json!({
                "warnings": list(
                    &object(
                        &json!({
                            "action": text("Action name."),
                            "parameter": text("Parameter name."),
                            "reason": { "type": "string", "enum": ["affects_recipient", "affects_amount", "affects_count", "affects_choice", "affects_flag"] },
                            "suggestion": text("The parameter type to map it to."),
                        }),
                        &["action", "parameter", "reason", "suggestion"],
                    ),
                    "Authority-relevant parameters without a closed type (E12); nothing was kept.",
                ),
            }),
            &["warnings"],
        ),
        "PublicationStatusRequest": object(
            &json!({
                "context": { "type": "object", "description": "The publisher's `check` context: `access`/`read` on `access.publication` with the path `[namespace]`." },
                "fingerprint": b64("The publication."),
                "domains": { "type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true, "items": b64("A domain it was offered to.") },
            }),
            &["context", "fingerprint", "domains"],
        ),
        "PublicationStatus": object(
            &json!({
                "fingerprint": b64("The publication."),
                "pending_acceptance": list(&b64("Domain"), "\"Pending acceptance in: …\": domains that accept the publisher for the namespace, but not this fingerprint."),
                "accepted_in": list(&b64("Domain"), "Domains whose `schema-definition` Acceptance pins this fingerprint."),
                "existing_grants_unchanged": { "const": true },
                "new_actions": list(&json!({ "type": "string" }), "Not included in delegations whose catalog is pinned (E11)."),
                "text": list(&json!({ "type": "string" }), "Text keys, in order."),
            }),
            &["fingerprint", "pending_acceptance", "accepted_in", "existing_grants_unchanged", "new_actions", "text"],
        ),
    })
}

fn queries() -> Value {
    json!({
        "SearchRequest": object(
            &json!({
                "context": {
                    "type": "object",
                    "description": "The reader's `check` context (L1-ADP-5…9) with `query`: the intent's action is `access`/`read` and its first resource `access.search` with the path `[kind]`.",
                },
                "page": object(&json!({ "token": text("The `next_token` of the previous page.") }), &[]),
            }),
            &["context"],
        ),
        "SchemaPublicationsQuery": object(
            &json!({ "namespace": text("The action namespace.") }),
            &["namespace"],
        ),
        "ChangeImpactQuery": {
            "oneOf": [
                object(
                    &json!({
                        "role": text("The Named AuthoritySet."),
                        "from": uint("The version the Grants pin now."),
                        "to": uint("The version to move them to."),
                    }),
                    &["role", "from", "to"],
                ),
                object(
                    &json!({
                        "policy": b64("The restriction policy replaced; absent for a new one."),
                        "candidate": b64("The candidate `policy_set` content, dCBOR."),
                    }),
                    &["candidate"],
                ),
            ],
        },
        "RevocationImpactQuery": object(
            &json!({
                "grant": b64("A Grant; its lineage subtree ends with it."),
                "instance": b64("An Instance."),
                "at": uint("When, Unix ms; now when absent."),
            }),
            &[],
        ),
        "HubQuery": object(
            &json!({ "party": b64("The reading Party; any other Party gets an empty page (XI-9, XI-22).") }),
            &["party"],
        ),
        "CompromiseImpactQuery": object(
            &json!({
                "instance": b64("A compromised Instance."),
                "issuer": b64("A compromised Claim issuer Party."),
                "key": b64("A compromised key's thumbprint; resolved to its Instance now."),
                "window": object(&json!({ "from": uint("Unix ms."), "until": uint("Unix ms.") }), &["from", "until"]),
            }),
            &["window"],
        ),
    })
}

fn hub() -> Value {
    json!({
        "HubHolding": object(
            &json!({
                "type": { "const": "holding" },
                "grant": b64("The Grant."),
                "groups": list(&json!({ "type": "string", "enum": ["acting_for_you", "shared_from_you", "your_authority"] }), "The groups it shows in (§8.17.7.1); never empty: every Grant the reader gave shows in at least one (XI-10)."),
                "holder": { "type": "object", "description": "`{party}`, `{public: true}`, `{group: [claim classes]}` (rule-shaped) or `{foreign: true}`." },
                "source": { "type": "object", "description": "`{anchor}` or `{grant, holder}`: where it derives from." },
                "capacities": list(&json!({}), "Its agency: `own` or `{for: Party}` (XI-10)."),
                "actions": list(&json!({ "type": "object" }), "The actions it names exactly."),
                "resource": { "type": "object", "description": "The resources it covers." },
                "validity": object(&json!({ "from": uint("Unix ms."), "until": uint("Unix ms.") }), &["from", "until"]),
                "budget": list(&json!({ "type": "object" }), "Its authority limits (XI-14); a financial limit is another owner's row."),
                "conditions": uint("How many while-conditions it carries."),
                "commitment": object(
                    &json!({
                        "ref": b64("The CommitmentRef digest the holding ends with (\"Ends with Work commitment X\", §8.17.7.2)."),
                        "state": { "type": "string", "enum": ["active", "lapsed", "ended"], "description": "`active` while the coordinator's current Claim says so, `lapsed` until one does, `ended` for good once it said the commitment ended (EI-5)." },
                        "owner": { "const": "coordinator" },
                    }),
                    &["ref", "state", "owner"],
                ),
                "named": object(&json!({ "name": text("Role."), "version": uint("Version.") }), &["name", "version"]),
                "since": uint("Issuing position."),
                "revision": uint("Revision, 0 at issue."),
                "selection": {
                    "type": "object",
                    "description": "For a rule-shaped holder the reader was ever selected by, from the membership episode (XI-15, C13, INV-31): `current` and `stale` (the episode is open; an exercise asks for a fresher statement, never \"removed\") carry the episode's first position `since`, so a rejoin shows its new episode; `ended` (a cutoff, a disqualifying statement or an expired membership Claim) carries the closing position `pos` and time `at` when known. `by` and `stated_at` name the statement behind it, the explanation's second part.",
                    "properties": {
                        "state": { "type": "string", "enum": ["current", "stale", "ended"] },
                        "since": uint("The episode's first position (`current`, `stale`)."),
                        "pos": uint("The closing record's position (`ended`)."),
                        "at": uint("When it closed, Unix ms (`ended`)."),
                        "by": { "type": "string", "description": "Who says so (XI-15, §8.17.5.7): the issuer Party of the statement that selects the reader, or of the last one that did when `ended`." },
                        "stated_at": uint("When that statement was made, Unix ms."),
                    },
                    "required": ["state"],
                    "additionalProperties": false,
                },
            }),
            &["type", "grant", "groups", "holder", "source", "capacities", "actions", "resource", "validity", "budget", "conditions", "since", "revision"],
        ),
        "HubRoot": object(
            &json!({
                "type": { "const": "root" },
                "anchor": b64("An Anchor the reader roots."),
                "sole": { "type": "boolean", "description": "Whether the reader is its sole root (§13.8)." },
                "quorum": uint("How many roots act together."),
                "since": uint("Creating position."),
            }),
            &["type", "anchor", "sole", "quorum", "since"],
        ),
        "HubUse": object(
            &json!({
                "type": { "const": "use" },
                "pos": uint("The decision record."),
                "at": uint("Its trusted time, Unix ms."),
                "intent": b64("The intent digest."),
                "basis": { "type": "object", "description": "`{anchor}` or `{grant}`." },
                "capacity": { "description": "`own` or `{for: Party}`." },
                "instance": b64("The acting Instance."),
                "by_viewer": { "type": "boolean", "description": "The reader acted; otherwise someone acted for the reader." },
            }),
            &["type", "pos", "intent", "basis", "capacity", "instance", "by_viewer"],
        ),
    })
}

/// AG-43, OP-156 m.4 Q20
fn discovered() -> Value {
    json!({
        "DiscoveredApp": object(
            &json!({
                "type": { "const": "discovery" },
                "connector": { "type": "string", "enum": ["google-workspace", "microsoft-graph"] },
                "app": text("The application's client id in the connected service."),
                "name": { "type": ["string", "null"], "description": "Its display name, when a connector gave one." },
                "scopes": list(&json!({ "type": "string" }), "Every scope any report named."),
                "grants": uint("How many accesses were reported."),
                "registered": { "type": "boolean", "description": "Whether a live agent or system Party of the domain accounts for it." },
                "accounted_by": list(&json!({ "type": "string" }), "Those Parties."),
                "claims": list(&json!({ "type": "string" }), "The `discovered_app` Claims."),
                "advisory": { "const": true },
            }),
            &["type", "connector", "app", "name", "scopes", "grants", "registered", "accounted_by", "claims", "advisory"],
        )
    })
}

/// OP-156 m.3 (k), INV-32
fn incarnations() -> Value {
    json!({
        "ResourceIncarnations": object(
            &json!({
                "type": { "const": "resource-incarnation" },
                "namespace": text("The resource's namespace."),
                "path": list(&json!({ "type": "string" }), "The resource's path."),
                "highest": { "type": ["integer", "null"], "minimum": 0, "description": "The highest incarnation any admitted `resource_lifecycle` Claim named; a create or reincarnate must go above it. `null` when none was declared." },
                "facts": list(&json!({ "type": "object" }), "`{incarnation, event, claim, issuer, position}` in record order; `event` `create`, `delete` or `reincarnate`."),
                "advisory": { "const": true },
            }),
            &["type", "namespace", "path", "highest", "facts", "advisory"],
        )
    })
}

fn reports() -> Value {
    json!({
        "SchemaPublication": object(
            &json!({
                "type": { "const": "schema_publication" },
                "fingerprint": b64("The exact digest a `schema-definition` Acceptance pins (E10)."),
                "publisher": b64("The publisher Party."),
                "namespace": text("The namespace."),
                "catalog_version": uint("The catalog version."),
                "standing": { "type": "string", "enum": ["accepted", "pending_acceptance", "unreferenced"] },
                "accepted_version": { "type": ["integer", "null"], "description": "The version this domain accepts now." },
                "diff": object(
                    &json!({
                        "added": list(&json!({ "type": "string" }), "Actions it adds."),
                        "removed": list(&json!({ "type": "string" }), "Actions it drops."),
                        "changed": list(&json!({ "type": "string" }), "Actions whose schema changed."),
                        "reserved_added": list(&json!({ "type": "string" }), "Newly reserved."),
                        "reserved_removed": list(&json!({ "type": "string" }), "No longer reserved: broadening (E11)."),
                    }),
                    &["added", "removed", "changed", "reserved_added", "reserved_removed"],
                ),
                "reserved": list(&json!({ "type": "string" }), "Reserved actions."),
                "parameters": list(&json!({ "type": "object" }), "`{action, parameter, class, affects?}`; `class` is `authority-relevant` or `authority-opaque`."),
                "compatibility": { "type": ["object", "null"], "description": "The publisher's declaration `{from, relation}` (§9.13.4); a Claim, not a mapping in force." },
                "existing_grants_unchanged": { "const": true },
                "new_actions": list(&json!({ "type": "string" }), "Not included in delegations whose catalog is pinned (E11)."),
                "text": list(&json!({ "type": "string" }), "Text keys, in order."),
                "advisory": { "const": true },
            }),
            &["type", "fingerprint", "publisher", "namespace", "catalog_version", "standing", "diff", "existing_grants_unchanged", "advisory"],
        ),
        "ChangeImpact": object(
            &json!({
                "type": { "const": "change_impact" },
                "role": { "type": "object", "description": "`{name, from, to}` for a role move." },
                "pin": { "type": "object", "description": "The pin each `grant.amend` of the move carries." },
                "policy": { "type": ["string", "null"], "description": "For a policy candidate: the policy replaced." },
                "relation": { "type": "string", "enum": ["equivalent", "narrowing", "widening", "incomparable", "may_error", "unknown"] },
                "structural": { "type": "string", "enum": ["narrowing", "widening"], "description": "For a policy candidate: the Kernel's structural reading (OP-157 m.3 (b)); a narrowing is CT1 unless the analysis answers anything but narrowing or equivalent." },
                "refused": { "type": ["string", "null"], "description": "The candidate's compile error." },
                "moves": list(&b64("Grant"), "The Grants to amend, one Exercise each."),
                "amends": list(&r("MetaPayload"), "The `grant_amend` payload of each move, in the order of `moves` (L1-ADP-17): the Grant's own constraints, requirements and agency kept, the authority set and pin of the new version; the console drafts, shows and signs each as its own Exercise (X20, §8.17.9.8)."),
                "holders": { "type": "object", "description": "`{parties, everyone, upper_bound}`." },
                "abilities": list(&json!({ "type": "object" }), "`{ability: {action, bounds}, holders_gaining, holders_losing}`."),
                "expansion": { "type": ["object", "null"], "description": "What a widening move needs (INV-10): `{tier, joint_root_quorum, delay_s, requirements}`." },
                "orphans": { "type": "object", "description": "`{empty_scopes, unselecting}` (TN-121)." },
                "capped": { "type": "boolean" },
                "advisory": { "const": true },
            }),
            &["type", "relation", "advisory"],
        ),
        "RevocationImpact": object(
            &json!({
                "type": { "const": "revocation_impact" },
                "revoked": { "type": "object" },
                "at": uint("When."),
                "subtree": list(&b64("Grant"), "Grants that end with it."),
                "exposed": list(&json!({ "type": "object" }), "`{exercise, holder, class, horizon_ms, window_ms, pep, applied_at}`: projections whose contract outlives it; `applied_at` is when its PEP acknowledged applying the revocation, `null` when unknown (E30)."),
                "max_exposure_ms": uint("The longest window."),
                "index_lag": uint("Positions the derived index is behind."),
                "orphan_tuples": uint("Index rows live for an ended Grant (§5.4)."),
                "acknowledged": list(&json!({ "type": "object" }), "`{pep, applied_at, basis}`: PEPs whose authority-state acknowledgement applies the recorded revocation (§9.12.3, E30); a missing PEP is unknown, not unapplied."),
                "aftermath": { "type": "object", "description": "`{grants_ending, projections_open, honoured_until_ms, running_copies, confirmed_applied}` (XI-3, E30)." },
                "advisory": { "const": true },
            }),
            &["type", "revoked", "at", "subtree", "exposed", "orphan_tuples", "aftermath", "advisory"],
        ),
        "CompromiseImpact": object(
            &json!({
                "type": { "const": "compromise_impact" },
                "compromised": { "type": "object" },
                "window": { "type": "object" },
                "instance": { "type": ["string", "null"] },
                "exercises": list(&json!({ "type": "object" }), "`{pos, intent, outcome}`."),
                "grants": list(&b64("Grant"), "Grants allowed Exercises changed."),
                "contributions": list(&b64("Contribution"), "Contributions recorded."),
                "projections": list(&b64("ExerciseID"), "Projections issued."),
                "claims": list(&b64("Claim"), "Claims of the issuer."),
                "capped": { "type": "boolean" },
                "advisory": { "const": true },
            }),
            &["type", "compromised", "window", "exercises", "grants", "contributions", "projections", "claims", "advisory"],
        ),
        // L6, OP-154 m.3 (u), E64, EI-10
        "Outcome": object(
            &json!({
                "type": { "const": "outcome" },
                "exercise": b64("ExerciseID"),
                "allowed_at": { "type": ["integer", "null"], "description": "The position of the allowing decision, as recorded; a report never changes it (EI-10). `null` when the domain allowed no such Exercise, or for a reporter that is not its actor." },
                "status": { "type": "string", "enum": ["attested", "unattested"] },
                "attested": list(&json!({ "type": "object" }), "`{position, claim, reporter, executor, disposition, step, idempotency_key, outcome, evidence, at, conformance}`: each effect_attestation, `outcome` `done`, `not-done` or `unknown` as reported (never truth, INV-18), `conformance` `conforming`, or outside authority as `outside-envelope`, `outside-window` or `no-exercise` (INV-19)."),
                "control": list(&json!({ "type": "object" }), "`{position, state, reporter}`: each executor_control, `paused` or `stopped_confirmed` (U5)."),
                "advisory": { "const": true },
            }),
            &["type", "exercise", "allowed_at", "status", "attested", "control", "advisory"],
        ),
    })
}

/// `POST /access/v1/search/{kind}`.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    paths.insert(
        "/access/v1/search/{kind}".into(),
        json!({ "post": {
            "operationId": "search",
            "summary": "One advisory search page (L1-ADP-16). Graph kinds `subject`, `resource`, `action`; management kinds `roles` and `role` (a role version with its computed \"Not included\" block, §8.17.9.2, E11), `admin-grant` (an admin Grant's meta-actions one by one, reserved ones apart), `holdings` (the viewer's own holdings, each a usable ADP `holding` basis, IA-5) and `changes` (information only, IA-2: an auditor sees every change, anyone else only those about them); `bulk-impact` (each Grant revoke of a bulk job and their sum, E17); `sources` (each live Acceptance by use with its blast radius, and the partners whose authority bridging Grants recognize up to their ceilings; §8.17.9.3, §5.13); developer kinds `schema-publications` (a namespace's published versions and where each stands here: there is no accept, a domain accepts only by its own `acceptance.amend` with the exact fingerprint, X21), `change-impact` (a role move or a `policy.set` candidate: abilities gained and lost per holder count, expansion requirements, orphan rows; X20, TN-121, §5.8; the SMT relation is `unknown` until proved), `revocation-impact` (subtree, staleness exposure, index lag, orphan tuples; §5.4) and `compromise-impact` (Exercises, Grants, contributions, projections and Claims in a window; SEC15). Developer kinds answer only the domain's auditors, and `revocation-impact` of a Grant also whoever stands above it in its lineage: the root of its Anchor or a holder of a Grant it derives from (XI-5); anyone else gets an empty page. `changes` also lists Grants whose agency names the reader and ingested regime key-events about the reader (`kind: key_event` with `class` and `issuer`; SI-21, SI-13, U26). Hub kinds `inventory` (holdings in the groups acting for you, shared from you and your authority, with the Anchors the reader roots) and `activity` (allowed uses by or for the reader; a DENY is not a use) answer only the reading Party about itself (XI-9, XI-22). The agent kind `agent-status` answers an agent Instance about itself only: whether it is live, its Mandate, and the Grants its Party holds with their actions, horizon and budget left; nothing about any other Party's delegations (A-11, E26). `outcome` (`{exercise, intent}`: what executors reported about one Exercise, compared with the allowed intent; only its actor Party, and a reporter for its own reports; OP-154 m.3 (u), E64, EI-10). `resource-incarnation` (`{namespace, path}`: the lifecycle facts domain products declared for one resource and its highest incarnation; the domain's auditors only; OP-156 m.3 (k), INV-32). `eligible-set` (`{gate_class, resource, digest}`: the named holders of `approve:<class>` now, as `eligibility:set` answers it; OP-156 m.3 (t), E41). `discovery` (`{unregistered?}`: each third-party application discovery connectors reported with `discovered_app` Claims, and the live agent or system Parties that account for it; only the unaccounted ones with `unregistered: true`; the domain's auditors only; AG-43, OP-156 m.4). Nothing is recorded.",
            "parameters": [path("kind", &json!({ "type": "string", "enum": [
                "subject", "resource", "action",
                "roles", "role", "admin-grant", "holdings", "changes", "bulk-impact", "sources",
                "schema-publications", "change-impact", "revocation-impact", "compromise-impact",
                "inventory", "activity", "agent-status", "outcome", "resource-incarnation", "eligible-set",
                "discovery",
            ] }))],
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("SearchRequest") } } },
            "responses": {
                "200": {
                    "description": "`results`, `page` and `context.advisory: true`. A developer kind's results hold one report.",
                    "content": { "application/json": { "schema": object(
                        &json!({
                            "results": list(&json!({ "oneOf": [
                                { "type": "object" },
                                r("SchemaPublication"),
                                r("ChangeImpact"),
                                r("RevocationImpact"),
                                r("CompromiseImpact"),
                                r("Roles"),
                                r("RoleVersion"),
                                r("AdminGrant"),
                                r("Holding"),
                                r("Change"),
                                r("BulkImpact"),
                                r("Sources"),
                                r("HubHolding"),
                                r("HubRoot"),
                                r("HubUse"),
                                r("Outcome"),
                                r("ResourceIncarnations"),
                                r("DiscoveredApp"),
                            ] }), "One page."),
                            "page": { "type": "object" },
                            "context": { "type": "object" },
                        }),
                        &["results", "page", "context"],
                    ) } },
                },
                "400": { "description": "Not a search of this kind (a protocol error, L1-ADP-3)." },
                "429": { "description": "Over the search rate (§13.7.4)." },
                "503": { "description": "No answer within the search deadline, never a partial list." },
            },
        }}),
    );
    paths.insert(
        "/access/v1/publications".into(),
        json!({ "post": {
            "operationId": "publishSchema",
            "summary": "Publishes a Schema Publication Package and offers it to the named domains (§8.17.10.2, E10–E12, X21). The publisher is the actor of the `check` AIS; a package whose authority-relevant parameter has no closed type is refused with its warnings and nothing is kept. A kept package changes no domain: each domain accepts only with its own reserved `acceptance.amend` naming the exact fingerprint, and there is no accept here, not even for a publisher who administers a target domain.",
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("PublishRequest") } } },
            "responses": {
                "201": { "description": "Kept (or already kept with the same fingerprint).", "content": { "application/json": { "schema": r("Published") } } },
                "400": { "description": "Not a publish request (a protocol error, L1-ADP-3)." },
                "401": { "description": "No AIS: an anonymous caller publishes nothing." },
                "409": { "description": "`publication-version`: another package was already published as this version (E10)." },
                "422": { "description": "`publication-unmappable` with the warnings, or `publication-invalid`.", "content": { "application/json": { "schema": r("PublicationWarnings") } } },
                "503": { "description": "Temporarily unavailable." },
            },
        }}),
    );
    paths.insert(
        "/access/v1/publications:status".into(),
        json!({ "post": {
            "operationId": "publicationStatus",
            "summary": "Where the caller's own publication stands in the named domains (§8.17.10.2, X21): \"Pending acceptance in: …\" and where it is accepted. Only its publisher reads it; a domain that never accepted the publisher for the namespace is left out. Advisory; nothing is recorded.",
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("PublicationStatusRequest") } } },
            "responses": {
                "200": { "description": "The status.", "content": { "application/json": { "schema": r("PublicationStatus") } } },
                "400": { "description": "Not a status request." },
                "401": { "description": "No AIS." },
                "404": { "description": "No such publication of the caller in those domains." },
                "503": { "description": "Temporarily unavailable." },
            },
        }}),
    );
}
