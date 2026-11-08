//! The ADP search route and its developer-surface kinds (L1-ADP-16, §8.17.10, §5.4, §16.5.1):
//! `schema-publications`, `change-impact`, `revocation-impact` and `compromise-impact`. Each
//! answers one advisory page, only to the domain's auditors; anyone else gets an empty page.
//! None of them writes, and none carries an accept or any other action (X21).

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
    if let (Value::Object(m), Value::Object(more)) = (&mut all, reports()) {
        m.extend(more);
    }
    all
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
                "refused": { "type": ["string", "null"], "description": "The candidate's compile error." },
                "moves": list(&b64("Grant"), "The Grants to amend, one Exercise each."),
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
    })
}

/// `POST /access/v1/search/{kind}`.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    paths.insert(
        "/access/v1/search/{kind}".into(),
        json!({ "post": {
            "operationId": "search",
            "summary": "One advisory search page (L1-ADP-16). Graph kinds `subject`, `resource`, `action`; developer kinds `schema-publications` (a namespace's published versions and where each stands here: there is no accept, a domain accepts only by its own `acceptance.amend` with the exact fingerprint, X21), `change-impact` (a role move or a `policy.set` candidate: abilities gained and lost per holder count, expansion requirements, orphan rows; X20, TN-121, §5.8; the SMT relation is `unknown` until proved), `revocation-impact` (subtree, staleness exposure, index lag, orphan tuples; §5.4) and `compromise-impact` (Exercises, Grants, contributions, projections and Claims in a window; SEC15). Developer kinds answer only the domain's auditors; anyone else gets an empty page. Nothing is recorded.",
            "parameters": [path("kind", &json!({ "type": "string", "enum": [
                "subject", "resource", "action",
                "schema-publications", "change-impact", "revocation-impact", "compromise-impact",
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
}
