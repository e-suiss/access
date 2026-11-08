//! The experience contract (CMP-16, OP-153 m.3 (v), OP-65): the wire types of
//! `/experience/v1/*` and their `OpenAPI` 3.1 document, committed as
//! `sdks/openapi/experience-v1.json`. Every row names its owner and the time it was read
//! (XI-1, XI-16); no row and no answer carries a write, a queued action or "action required"
//! (XI-3, IA-2).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// Version of the contract.
pub const VERSION: &str = "1.0.0";

/// The plan route: the reads to sign.
pub const PLAN_PATH: &str = "/experience/v1/hub/plan";

/// The hub route: the signed reads in, the render data out.
pub const HUB_PATH: &str = "/experience/v1/hub";

/// The real-time route (§17.3.1): server-sent events.
pub const STREAM_PATH: &str = "/experience/v1/stream";

/// A hub read kind, as the ADP search names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Holdings and roots.
    Inventory,
    /// Uses (S6).
    Activity,
    /// Changes (IA-2).
    Changes,
}

impl Kind {
    /// Every kind, in render order.
    pub const ALL: [Self; 3] = [Self::Inventory, Self::Activity, Self::Changes];

    /// The ADP search kind.
    #[must_use]
    pub const fn search(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Activity => "activity",
            Self::Changes => "changes",
        }
    }
}

/// How deep an answer goes (§8.12, X25): each depth explains the one before and never
/// contradicts it; capacity and status are shown at every depth.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Depth {
    /// What most people need.
    #[default]
    Default,
    /// Sources, positions, revisions and roles.
    Expert,
    /// Expert plus the record positions an auditor cites; only as deep as the reader's own
    /// reads went (the domains decide what an audit read returns).
    Audit,
}

/// Who owns a row (XI-1, IA-3): the product whose record it comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    /// Access: authority, decisions, history.
    Access,
    /// A runtime that reports running work.
    Executor,
    /// A verifier that reports what it applied.
    Verifier,
    /// Relay: delivery.
    Relay,
    /// Pay: financial limits.
    Pay,
}

/// One domain the reader knows, as the plan request names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainRef {
    /// `DomainID`, base64url of the 32 bytes.
    pub domain: String,
    /// The reader's own name for it ("Personal", "Acme"), shown only with more than one domain
    /// (IA-6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// `POST /experience/v1/hub/plan`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRequest {
    /// The reader's Party, base64url.
    pub viewer: String,
    /// The domains to read.
    pub domains: Vec<DomainRef>,
    /// The kinds to read; all when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<Kind>>,
}

/// One read to sign: the reader's device Instance signs an AIS over `intent_digest` with
/// `nonce`, mode `check`, capacity `own`, `basis` and the plan's `pep`, and puts it at
/// `body.context.ais`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedRead {
    /// `DomainID`.
    pub domain: String,
    /// The kind.
    pub kind: Kind,
    /// The nonce, base64url.
    pub nonce: String,
    /// The intent digest the AIS signs, base64url.
    pub intent_digest: String,
    /// The basis the AIS names: the domain's meta-anchor, `{anchor}`.
    pub basis: Value,
    /// The ADP search body without `context.ais`.
    pub body: Value,
}

/// The plan answer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// The PEP the AIS names: this service, as Access authenticates it (XI-18, IA-7).
    pub pep: String,
    /// The reads.
    pub reads: Vec<PlannedRead>,
}

/// One signed read.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRead {
    /// `DomainID`.
    pub domain: String,
    /// The reader's label for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The kind.
    pub kind: Kind,
    /// The ADP search body with `context.ais`.
    pub body: Value,
}

/// `POST /experience/v1/hub`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubRequest {
    /// The reader's Party.
    pub viewer: String,
    /// The depth.
    #[serde(default)]
    pub depth: Depth,
    /// The signed reads.
    pub reads: Vec<SignedRead>,
}

/// Whether what a row or domain shows is current (XI-15, XI-16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// Read from its owner just now.
    Current,
    /// Its owner could not be reached: "Current status unknown".
    Unknown,
    /// A rule-shaped holding whose selection lapsed: "Needs refresh — not removed".
    NeedsRefresh,
}

/// A domain as this answer saw it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainStatus {
    /// `DomainID`.
    pub domain: String,
    /// The reader's label, when more than one domain is shown (IA-6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Owner.
    pub owner: Owner,
    /// Current or unknown.
    pub freshness: Freshness,
    /// When it was read, Unix ms; absent when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<u64>,
    /// The text key.
    pub text: String,
}

/// Who a row is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Who {
    /// `party`, `everyone`, `group` or `foreign`.
    pub kind: String,
    /// The Party, when one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party: Option<String>,
    /// The claim classes of a rule-shaped holder (XI-15).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<String>,
}

/// In whose name a holding is used, apart from where it came from (XI-10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityLabel {
    /// `capacity.own_use`, `capacity.on_behalf_of` or `capacity.as_yourself`.
    pub text: String,
    /// The Party acted for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party: Option<String>,
}

/// One limit row (XI-14): an authority limit and a financial limit are two rows with two owners.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limit {
    /// `authority` or `financial`.
    pub kind: String,
    /// Owner.
    pub owner: Owner,
    /// The term as its owner states it.
    pub term: Value,
}

/// How long a holding is good for, without naming the contract (§8.8, §8.9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    /// Valid until, Unix ms.
    pub valid_until: u64,
    /// The text key: `validity.valid_until`.
    pub text: String,
}

/// An action a row offers (XI-11): shown even when the reader cannot take it, then with who can.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// `revoke`, `narrow` or `suspend`.
    pub action: String,
    /// Whether the reader can take it.
    pub available: bool,
    /// Who can, when the reader cannot: a text key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub who_can: Option<String>,
    /// How many steps from this row it takes; never more than two (XI-5).
    pub steps: u8,
}

/// What an expert sees in addition (§8.12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expert {
    /// Where it derives from: `{anchor}` or `{grant, holder}`.
    pub source: Value,
    /// Issuing position.
    pub since: u64,
    /// Revision.
    pub revision: u64,
    /// Role pinned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Value>,
}

/// One holding row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// `DomainID`.
    pub domain: String,
    /// The reader's domain label, with more than one domain (IA-6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The Grant.
    pub grant: String,
    /// Owner (XI-1).
    pub owner: Owner,
    /// When it was read (XI-16).
    pub as_of: u64,
    /// Current, or needs refresh.
    pub freshness: Freshness,
    /// The status text key.
    pub status: String,
    /// The holder.
    pub who: Who,
    /// Capacity (XI-10).
    pub capacity: Vec<CapacityLabel>,
    /// What it covers: action names.
    pub what: Vec<String>,
    /// Validity.
    pub validity: Validity,
    /// Limits, one row each (XI-14).
    pub limits: Vec<Limit>,
    /// Actions (XI-11, XI-5).
    pub offers: Vec<Offer>,
    /// The expert part, at `expert` or `audit` depth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expert: Option<Expert>,
}

/// An Anchor the reader roots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRow {
    /// `DomainID`.
    pub domain: String,
    /// The reader's domain label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The Anchor.
    pub anchor: String,
    /// Owner.
    pub owner: Owner,
    /// Whether the reader roots it alone.
    pub sole: bool,
    /// How a root change is confirmed: for a sole root, `root.sole_confirm` (§13.8).
    pub confirm: String,
}

/// One use (S6): a record, not a feed; a DENY is not a use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityRow {
    /// `DomainID`.
    pub domain: String,
    /// The reader's domain label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Owner.
    pub owner: Owner,
    /// The record's position.
    pub pos: u64,
    /// Its time, Unix ms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
    /// `activity.by_you` or `activity.for_you`.
    pub text: String,
    /// Capacity (XI-10).
    pub capacity: CapacityLabel,
    /// The Grant it rested on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// The acting Instance, at `expert` depth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

/// One change (IA-2): information only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeRow {
    /// `DomainID`.
    pub domain: String,
    /// The reader's domain label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Owner.
    pub owner: Owner,
    /// The record's position.
    pub pos: u64,
    /// Its time, Unix ms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
    /// `grant_to_you`, `grant_for_you`, `instance_added`, `acceptance` or `key_event`.
    pub kind: String,
    /// The text key.
    pub text: String,
    /// What it is about: the Grant, Instance, Acceptance or Claim.
    pub about: String,
    /// For a key event: the Claim class and who signed it (U26, SI-13).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_event: Option<Value>,
    /// Always derived.
    pub derived: bool,
}

/// The hub answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hub {
    /// When it was assembled, Unix ms.
    pub as_of: u64,
    /// The depth.
    pub depth: Depth,
    /// The domains as seen.
    pub domains: Vec<DomainStatus>,
    /// Whether rows carry domain labels (IA-6).
    pub show_domains: bool,
    /// Acting for you.
    pub acting_for_you: Vec<Row>,
    /// Shared from you.
    pub shared_from_you: Vec<Row>,
    /// Your authority.
    pub your_authority: Vec<Row>,
    /// Anchors the reader roots.
    pub roots: Vec<RootRow>,
    /// Activity (S6).
    pub activity: Vec<ActivityRow>,
    /// Changes (IA-2).
    pub changes: Vec<ChangeRow>,
    /// Notices, always including `hub.not_shown_unconnected` (§8.17.7.2).
    pub notices: Vec<String>,
}

/// One server-sent event (OP-153 m.3 (v)): a hint to read again, never the data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// `authority`.
    pub kind: SignalKind,
    /// The position the next read reflects at least.
    pub at_least: u64,
}

/// What a signal is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// Authority state moved.
    Authority,
}

fn r(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

fn text(d: &str) -> Value {
    json!({ "type": "string", "description": d })
}

fn uint(d: &str) -> Value {
    json!({ "type": "integer", "minimum": 0, "description": d })
}

fn list(items: &Value, d: &str) -> Value {
    json!({ "type": "array", "items": items, "description": d })
}

fn object(properties: &Value, required: &[&str]) -> Value {
    json!({ "type": "object", "additionalProperties": false, "required": required, "properties": properties })
}

fn owner() -> Value {
    json!({ "type": "string", "enum": ["access", "executor", "verifier", "relay", "pay"], "description": "Whose record the row is (XI-1)." })
}

fn label() -> Value {
    text("The reader's label of the domain; present only with more than one domain (IA-6).")
}

fn requests() -> Map<String, Value> {
    let kind = json!({ "type": "string", "enum": ["inventory", "activity", "changes"] });
    let mut m = Map::new();
    m.insert("Kind".into(), kind);
    m.insert(
        "DomainRef".into(),
        object(
            &json!({ "domain": text("DomainID, base64url."), "label": label() }),
            &["domain"],
        ),
    );
    m.insert(
        "PlanRequest".into(),
        object(
            &json!({
                "viewer": text("The reader's Party, base64url."),
                "domains": list(&r("DomainRef"), "The domains the reader knows."),
                "kinds": list(&r("Kind"), "All kinds when absent."),
            }),
            &["viewer", "domains"],
        ),
    );
    m.insert(
        "PlannedRead".into(),
        object(
            &json!({
                "domain": text("DomainID."),
                "kind": r("Kind"),
                "nonce": text("Nonce, base64url."),
                "intent_digest": text("The digest the AIS signs, base64url."),
                "basis": { "type": "object", "description": "`{anchor}`: the basis the AIS names." },
                "body": { "type": "object", "description": "The ADP search body without `context.ais`." },
            }),
            &["domain", "kind", "nonce", "intent_digest", "basis", "body"],
        ),
    );
    m.insert(
        "Plan".into(),
        object(
            &json!({
                "pep": text("The PEP the AIS names: this service, as Access authenticates it (XI-18)."),
                "reads": list(&r("PlannedRead"), "The reads to sign."),
            }),
            &["pep", "reads"],
        ),
    );
    m.insert(
        "SignedRead".into(),
        object(
            &json!({
                "domain": text("DomainID."),
                "label": label(),
                "kind": r("Kind"),
                "body": { "type": "object", "description": "The ADP search body with `context.ais`." },
            }),
            &["domain", "kind", "body"],
        ),
    );
    m.insert(
        "HubRequest".into(),
        object(
            &json!({
                "viewer": text("The reader's Party."),
                "depth": { "type": "string", "enum": ["default", "expert", "audit"], "default": "default", "description": "§8.12: each depth explains the one before; capacity and status show at every depth." },
                "reads": list(&r("SignedRead"), "The signed reads."),
            }),
            &["viewer", "reads"],
        ),
    );
    m
}

fn rows() -> Map<String, Value> {
    let freshness = json!({ "type": "string", "enum": ["current", "unknown", "needs_refresh"] });
    let capacity = object(
        &json!({
            "text": { "type": "string", "enum": ["capacity.own_use", "capacity.on_behalf_of", "capacity.as_yourself"] },
            "party": text("The Party acted for."),
        }),
        &["text"],
    );
    let mut m = Map::new();
    m.insert("Freshness".into(), freshness);
    m.insert("CapacityLabel".into(), capacity);
    m.insert(
        "DomainStatus".into(),
        object(
            &json!({
                "domain": text("DomainID."),
                "label": label(),
                "owner": owner(),
                "freshness": r("Freshness"),
                "as_of": uint("When it was read; absent when unknown (XI-16)."),
                "text": text("`domain.current` or `domain.unreachable`."),
            }),
            &["domain", "owner", "freshness", "text"],
        ),
    );
    m.insert(
        "Row".into(),
        object(
            &json!({
                "domain": text("DomainID."),
                "label": label(),
                "grant": text("The Grant."),
                "owner": owner(),
                "as_of": uint("When it was read (XI-16)."),
                "freshness": r("Freshness"),
                "status": text("`status.current` or `status.needs_refresh` (XI-15: never \"removed\")."),
                "who": object(&json!({
                    "kind": { "type": "string", "enum": ["party", "everyone", "group", "foreign"] },
                    "party": text("Party."),
                    "classes": list(&json!({ "type": "string" }), "Claim classes of a rule-shaped holder."),
                }), &["kind"]),
                "capacity": list(&r("CapacityLabel"), "In whose name, apart from where it came from (XI-10); never empty."),
                "what": list(&json!({ "type": "string" }), "`namespace:name` of each action."),
                "validity": object(&json!({ "valid_until": uint("Unix ms."), "text": { "const": "validity.valid_until" } }), &["valid_until", "text"]),
                "limits": list(&object(&json!({
                    "kind": { "type": "string", "enum": ["authority", "financial"] },
                    "owner": owner(),
                    "term": { "type": "object" },
                }), &["kind", "owner", "term"]), "One row per limit and owner (XI-14)."),
                "offers": list(&object(&json!({
                    "action": { "type": "string", "enum": ["revoke", "narrow", "suspend"] },
                    "available": { "type": "boolean" },
                    "who_can": text("A text key naming who can, when the reader cannot (XI-11)."),
                    "steps": { "type": "integer", "minimum": 1, "maximum": 2, "description": "XI-5." },
                }), &["action", "available", "steps"]), "Actions; one the reader cannot take is shown with who can."),
                "expert": object(&json!({
                    "source": { "type": "object" },
                    "since": uint("Issuing position."),
                    "revision": uint("Revision."),
                    "role": { "type": "object" },
                }), &["source", "since", "revision"]),
            }),
            &["domain", "grant", "owner", "as_of", "freshness", "status", "who", "capacity", "what", "validity", "limits", "offers"],
        ),
    );
    m.insert(
        "RootRow".into(),
        object(
            &json!({
                "domain": text("DomainID."),
                "label": label(),
                "anchor": text("The Anchor."),
                "owner": owner(),
                "sole": { "type": "boolean" },
                "confirm": text("`root.sole_confirm` or `root.joint_confirm` (§13.8)."),
            }),
            &["domain", "anchor", "owner", "sole", "confirm"],
        ),
    );
    m.insert(
        "ActivityRow".into(),
        object(
            &json!({
                "domain": text("DomainID."),
                "label": label(),
                "owner": owner(),
                "pos": uint("The record."),
                "at": uint("Unix ms."),
                "text": { "type": "string", "enum": ["activity.by_you", "activity.for_you"] },
                "capacity": r("CapacityLabel"),
                "grant": text("The Grant it rested on."),
                "instance": text("The acting Instance, at expert depth."),
            }),
            &["domain", "owner", "pos", "text", "capacity"],
        ),
    );
    m.insert(
        "ChangeRow".into(),
        object(
            &json!({
                "domain": text("DomainID."),
                "label": label(),
                "owner": owner(),
                "pos": uint("The record."),
                "at": uint("Unix ms."),
                "kind": { "type": "string", "enum": ["grant_to_you", "grant_for_you", "instance_added", "acceptance", "key_event"] },
                "text": text("The text key; none asks for an action (IA-2)."),
                "about": text("The Grant, Instance, Acceptance or Claim."),
                "key_event": { "type": "object", "description": "`{class, issuer}` (U26, SI-13)." },
                "derived": { "const": true },
            }),
            &["domain", "owner", "pos", "kind", "text", "about", "derived"],
        ),
    );
    m.insert(
        "Hub".into(),
        object(
            &json!({
                "as_of": uint("When it was assembled."),
                "depth": { "type": "string", "enum": ["default", "expert", "audit"] },
                "domains": list(&r("DomainStatus"), "The domains as seen."),
                "show_domains": { "type": "boolean", "description": "IA-6." },
                "acting_for_you": list(&r("Row"), "Holdings whose agency names the reader."),
                "shared_from_you": list(&r("Row"), "Holdings from the reader's holding or root, not for the reader."),
                "your_authority": list(&r("Row"), "The reader's holdings."),
                "roots": list(&r("RootRow"), "Anchors the reader roots."),
                "activity": list(&r("ActivityRow"), "Uses (S6)."),
                "changes": list(&r("ChangeRow"), "Changes (IA-2)."),
                "notices": list(&json!({ "type": "string" }), "Always includes `hub.not_shown_unconnected`."),
            }),
            &["as_of", "depth", "domains", "show_domains", "acting_for_you", "shared_from_you", "your_authority", "roots", "activity", "changes", "notices"],
        ),
    );
    m.insert(
        "Signal".into(),
        object(
            &json!({
                "kind": { "const": "authority" },
                "at_least": uint("Read again; the answer reflects at least this position."),
            }),
            &["kind", "at_least"],
        ),
    );
    m
}

fn paths() -> Value {
    json!({
        PLAN_PATH: { "post": {
            "operationId": "planHub",
            "summary": "The reads to sign for the Authority hub. Nothing is read or written.",
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("PlanRequest") } } },
            "responses": {
                "200": { "description": "The plan.", "content": { "application/json": { "schema": r("Plan") } } },
                "400": { "description": "Malformed." },
            },
        }},
        HUB_PATH: { "post": {
            "operationId": "readHub",
            "summary": "The hub's render data, read with the reader's own signed reads (S2, S6, IA-2). A domain that does not answer is `unknown`, never empty and never pending (XI-16). No write path exists here.",
            "requestBody": { "required": true, "content": { "application/json": { "schema": r("HubRequest") } } },
            "responses": {
                "200": { "description": "The hub.", "content": { "application/json": { "schema": r("Hub") } } },
                "400": { "description": "Malformed." },
            },
        }},
        STREAM_PATH: { "get": {
            "operationId": "streamSignals",
            "summary": "Server-sent events: `{kind, at_least}` hints to read again; never the data (§17.3.1).",
            "responses": {
                "200": { "description": "`text/event-stream` of `Signal` events.", "content": { "text/event-stream": { "schema": r("Signal") } } },
            },
        }},
    })
}

/// The contract as an `OpenAPI` 3.1 document.
#[must_use]
pub fn openapi() -> Value {
    let mut schemas = requests();
    schemas.extend(rows());
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Suiss Access Experience",
            "version": VERSION,
            "description": "The Authority hub's render data (CMP-16). Read with the reader's own AIS from Access's public endpoints, as any third-party experience could (XI-18, IA-7). It holds and writes no authority.",
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
        },
        "paths": paths(),
        "components": { "schemas": Value::Object(schemas) },
    })
}
