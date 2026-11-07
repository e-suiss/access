//! Realm configuration as code (§12.5.3, TN-122…TN-124): the document `export` writes and
//! `diff`/`apply` read, and the plan between a desired document and the runtime state.
//!
//! - Deterministic (TN-123 item 1): resources sorted by natural key, keys sorted, server-generated
//!   members (`readOnly` in the contract) and retired resources left out unless asked for.
//! - Secrets by reference only (item 2): a member whose name says secret must be a `*_ref`
//!   holding a `secret://` pointer; a value is refused on export and on read.
//! - Desired and runtime apart (item 4): only the members the desired document sets are
//!   compared, so an unset member is never drift.
//! - Direction (TN-124): a resource retired at runtime is a restriction; the plan never brings
//!   it back. Every write is one Exercise; reserved writes (CT3) are only proposed (TN-122).

use serde_json::{Map, Value};

use crate::api::{self, Contract};

/// The document's resource lists and their API shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Kind {
    /// The document member.
    pub(crate) member: &'static str,
    /// The API resource name.
    pub(crate) resource: &'static str,
    /// The natural key.
    pub(crate) key: &'static str,
    /// The contract schema.
    pub(crate) schema: &'static str,
    /// Create without a key (server-generated key), if any.
    pub(crate) create: Option<&'static str>,
    /// Replace by key.
    pub(crate) put: &'static str,
    /// Retire by key (CT1, narrowing).
    pub(crate) retire: &'static str,
}

/// The resource lists of a realm's configuration. Accounts and memberships are data, not
/// configuration, and are not exported.
pub(crate) const KINDS: [Kind; 3] = [
    Kind {
        member: "clients",
        resource: "clients",
        key: "client_id",
        schema: "Client",
        create: Some("createClient"),
        put: "putClient",
        retire: "retireClient",
    },
    Kind {
        member: "groups",
        resource: "groups",
        key: "name",
        schema: "Group",
        create: None,
        put: "putGroup",
        retire: "retireGroup",
    },
    Kind {
        member: "upstream_idps",
        resource: "upstream-idps",
        key: "name",
        schema: "UpstreamIdp",
        create: None,
        put: "putUpstreamIdp",
        retire: "retireUpstreamIdp",
    },
];

/// The settings sections a write exists for, and their operation.
pub(crate) const SECTIONS: [(&str, &str); 6] = [
    ("signin_policy", "putSigninPolicy"),
    ("session_policy", "putSessionPolicy"),
    ("branding", "putBranding"),
    ("rp_id", "putRpId"),
    ("cimd", "putCimdPolicy"),
    ("protection_mode", "putProtectionMode"),
];

/// Settings members exported but without a REST write yet.
pub(crate) const READ_ONLY_SETTINGS: [&str; 2] = ["argon2", "managed"];

/// The member that marks a resource as managed by the reconciler, when the contract has it
/// (TN-124: the console shows managed members read-only).
pub(crate) const MANAGED_BY: &str = "managed_by";

/// Why a document is refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DocError {
    /// Not a mapping with the expected members.
    #[error("document: {0}")]
    Shape(String),
    /// A secret value instead of a reference (TN-123 item 2).
    #[error("secret value at {0}: use a `*_ref` member with a `secret://` reference")]
    Secret(String),
    /// Another realm's document.
    #[error("the document is for realm {0}")]
    Realm(String),
}

fn secret_like(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("secret") || n.contains("password") || n == "private_key"
}

/// Refuses any secret value under `v` (TN-123 item 2).
pub(crate) fn check_secrets(v: &Value, at: &str) -> Result<(), DocError> {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                let here = format!("{at}.{k}");
                if secret_like(k) {
                    let is_ref = k.ends_with("_ref")
                        && (x.is_null() || x.as_str().is_some_and(|s| s.starts_with("secret://")));
                    if !is_ref {
                        return Err(DocError::Secret(here));
                    }
                }
                check_secrets(x, &here)?;
            }
            Ok(())
        }
        Value::Array(a) => a
            .iter()
            .enumerate()
            .try_for_each(|(i, x)| check_secrets(x, &format!("{at}[{i}]"))),
        _ => Ok(()),
    }
}

/// What `export` keeps.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ExportOptions {
    /// Keep server-generated members and retired resources.
    pub(crate) generated: bool,
}

fn strip(contract: &Contract, schema: &str, item: &Value, opts: ExportOptions) -> Value {
    let Value::Object(o) = item else {
        return item.clone();
    };
    let kept: Map<String, Value> = o
        .iter()
        .filter(|(k, _)| opts.generated || !contract.read_only(schema, k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Value::Object(kept)
}

fn key_of<'v>(item: &'v Value, kind: &Kind) -> Option<&'v str> {
    item.get(kind.key).and_then(Value::as_str)
}

fn retired(item: &Value) -> bool {
    item.get("status").and_then(Value::as_str) == Some("retired")
}

/// The runtime state as read from the API.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Runtime {
    /// Items per kind member, as the API lists them.
    pub(crate) lists: Map<String, Value>,
    /// `GET settings`.
    pub(crate) settings: Value,
    /// `ETag`s by `kind/key` and `settings`.
    pub(crate) etags: Map<String, Value>,
}

/// The export document of `runtime` (TN-123 item 1).
pub(crate) fn export(
    contract: &Contract,
    realm: &str,
    runtime: &Runtime,
    opts: ExportOptions,
) -> Result<Value, DocError> {
    let mut doc = Map::new();
    doc.insert(String::from("realm"), Value::String(realm.to_owned()));
    for kind in KINDS {
        let mut items: Vec<Value> = runtime
            .lists
            .get(kind.member)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter(|i| opts.generated || !retired(i))
                    .map(|i| strip(contract, kind.schema, i, opts))
                    .collect()
            })
            .unwrap_or_default();
        items.sort_by(|a, b| key_of(a, &kind).cmp(&key_of(b, &kind)));
        doc.insert(kind.member.to_owned(), Value::Array(items));
    }
    let mut settings = runtime.settings.clone();
    if let Some(Value::Array(m)) = settings.get_mut("mappers") {
        m.sort_by(|a, b| {
            a.get("claim")
                .and_then(Value::as_str)
                .cmp(&b.get("claim").and_then(Value::as_str))
        });
    }
    doc.insert(String::from("settings"), settings);
    let doc = Value::Object(doc);
    check_secrets(&doc, "")?;
    Ok(doc)
}

/// One step of a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// A write: one Exercise.
    Write {
        operation: String,
        key: Option<String>,
        body: Map<String, Value>,
        if_match: Option<String>,
        /// The runtime already has the resource.
        exists: bool,
        /// What changes, for the listing.
        what: String,
    },
    /// Something the plan will not do, and why.
    Conflict { at: String, reason: String },
    /// A runtime resource the document does not name; left alone unless pruning.
    Unmanaged { at: String },
}

impl Step {
    /// Whether this write is reserved and therefore only proposed (TN-122).
    pub(crate) fn reserved(&self) -> bool {
        match self {
            Self::Write {
                operation, exists, ..
            } => api::reserved(operation, *exists),
            _ => false,
        }
    }
}

/// How the plan is made.
#[derive(Clone, Debug, Default)]
pub(crate) struct PlanOptions {
    /// Retire runtime resources the document does not name (TN-123 item 3, CT1).
    pub(crate) prune: bool,
    /// The marker value when the contract has [`MANAGED_BY`].
    pub(crate) managed_by: Option<String>,
}

fn changed(desired: &Map<String, Value>, runtime: &Value, skip: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = desired
        .iter()
        .filter(|(k, _)| !skip.contains(&k.as_str()))
        .filter(|(k, v)| runtime.get(k.as_str()) != Some(*v))
        .map(|(k, _)| k.clone())
        .collect();
    out.sort();
    out
}

fn merged(
    contract: &Contract,
    schema: &str,
    runtime: &Value,
    desired: &Map<String, Value>,
    drop: &[&str],
    managed_by: Option<&String>,
) -> Map<String, Value> {
    let mut body: Map<String, Value> = runtime
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| !contract.read_only(schema, k) && !drop.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    for (k, v) in desired {
        if !drop.contains(&k.as_str()) {
            body.insert(k.clone(), v.clone());
        }
    }
    if let Some(m) = managed_by
        && contract.declares(schema, MANAGED_BY)
    {
        body.insert(MANAGED_BY.to_owned(), Value::String(m.clone()));
    }
    body
}

fn etag(runtime: &Runtime, at: &str) -> Option<String> {
    runtime
        .etags
        .get(at)
        .and_then(Value::as_str)
        .map(String::from)
}

fn doc_list<'d>(desired: &'d Value, kind: &Kind) -> Result<Vec<&'d Map<String, Value>>, DocError> {
    match desired.get(kind.member) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|i| {
                i.as_object()
                    .ok_or_else(|| DocError::Shape(format!("{}: items are mappings", kind.member)))
            })
            .collect(),
        Some(_) => Err(DocError::Shape(format!("{} is a list", kind.member))),
    }
}

fn plan_kind(
    contract: &Contract,
    kind: &Kind,
    desired: &Value,
    runtime: &Runtime,
    opts: &PlanOptions,
    out: &mut Vec<Step>,
) -> Result<(), DocError> {
    let empty = Vec::new();
    let live: &Vec<Value> = runtime
        .lists
        .get(kind.member)
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let wanted = doc_list(desired, kind)?;
    let mut named = Vec::new();
    for item in &wanted {
        let key = item.get(kind.key).and_then(Value::as_str);
        let Some(key) = key else {
            if let Some(create) = kind.create {
                let mut body: Map<String, Value> = (*item).clone();
                if let Some(m) = &opts.managed_by
                    && contract.declares(kind.schema, MANAGED_BY)
                {
                    body.insert(MANAGED_BY.to_owned(), Value::String(m.clone()));
                }
                out.push(Step::Write {
                    operation: create.to_owned(),
                    key: None,
                    body,
                    if_match: None,
                    exists: false,
                    what: format!("create {} (the server assigns {})", kind.member, kind.key),
                });
                continue;
            }
            return Err(DocError::Shape(format!(
                "{}: every item needs `{}`",
                kind.member, kind.key
            )));
        };
        if named.contains(&key) {
            return Err(DocError::Shape(format!("{}: `{key}` twice", kind.member)));
        }
        named.push(key);
        let at = format!("{}/{key}", kind.member);
        let current = live.iter().find(|i| key_of(i, kind) == Some(key));
        match current {
            None if kind.create.is_some() => out.push(Step::Conflict {
                at,
                reason: format!(
                    "no such {}; it is server-generated and never reused: drop it to create a new one",
                    kind.key
                ),
            }),
            None => out.push(Step::Write {
                operation: kind.put.to_owned(),
                key: Some(key.to_owned()),
                body: merged(
                    contract,
                    kind.schema,
                    &Value::Null,
                    item,
                    &[kind.key],
                    opts.managed_by.as_ref(),
                ),
                if_match: None,
                exists: false,
                what: format!("create {at}"),
            }),
            // TN-124: a retired resource is a restriction; the reconciler does not undo it
            Some(c) if retired(c) => out.push(Step::Conflict {
                at,
                reason: String::from(
                    "retired at runtime; the reconciler does not undo a restriction (TN-124)",
                ),
            }),
            Some(c) => {
                let fields = changed(item, c, &[kind.key]);
                if fields.is_empty() {
                    continue;
                }
                out.push(Step::Write {
                    operation: kind.put.to_owned(),
                    key: Some(key.to_owned()),
                    body: merged(
                        contract,
                        kind.schema,
                        c,
                        item,
                        &[kind.key],
                        opts.managed_by.as_ref(),
                    ),
                    if_match: etag(runtime, &at),
                    exists: true,
                    what: format!("update {at}: {}", fields.join(", ")),
                });
            }
        }
    }
    unnamed(kind, live, &named, opts.prune, out);
    Ok(())
}

/// Runtime resources the document does not name: retired with `--prune`, else reported.
fn unnamed(kind: &Kind, live: &[Value], named: &[&str], prune: bool, out: &mut Vec<Step>) {
    for item in live.iter().filter(|i| !retired(i)) {
        let Some(key) = key_of(item, kind) else {
            continue;
        };
        if named.contains(&key) {
            continue;
        }
        let at = format!("{}/{key}", kind.member);
        if prune {
            out.push(Step::Write {
                operation: kind.retire.to_owned(),
                key: Some(key.to_owned()),
                body: Map::new(),
                if_match: None,
                exists: true,
                what: format!("retire {at} (not in the document)"),
            });
        } else {
            out.push(Step::Unmanaged { at });
        }
    }
}

fn plan_settings(desired: &Value, runtime: &Runtime, out: &mut Vec<Step>) -> Result<(), DocError> {
    let Some(wanted) = desired.get("settings") else {
        return Ok(());
    };
    let wanted = wanted
        .as_object()
        .ok_or_else(|| DocError::Shape(String::from("settings is a mapping")))?;
    let live = &runtime.settings;
    let tag = etag(runtime, "settings");
    for (name, value) in wanted {
        let at = format!("settings/{name}");
        let current = live.get(name.as_str());
        if READ_ONLY_SETTINGS.contains(&name.as_str()) {
            if current != Some(value) {
                out.push(Step::Conflict {
                    at,
                    reason: String::from("no management API write exists for this setting yet"),
                });
            }
            continue;
        }
        if name == "mappers" {
            plan_mappers(value, current, out)?;
            continue;
        }
        if name == "jose_alg" {
            if current != Some(value) {
                let mut body = Map::new();
                body.insert(String::from("alg"), value.clone());
                out.push(Step::Write {
                    operation: String::from("putJoseAlg"),
                    key: None,
                    body,
                    if_match: tag.clone(),
                    exists: true,
                    what: String::from("change the JOSE signing algorithm"),
                });
            }
            continue;
        }
        let Some((_, op)) = SECTIONS.iter().find(|(s, _)| s == name) else {
            return Err(DocError::Shape(format!("unknown setting `{name}`")));
        };
        if name == "rp_id" {
            if current != Some(value) {
                let mut body = Map::new();
                body.insert(String::from("rp_id"), value.clone());
                out.push(Step::Write {
                    operation: (*op).to_owned(),
                    key: None,
                    body,
                    if_match: tag.clone(),
                    exists: true,
                    what: String::from("change the RP ID (irreversible; passkeys stop working)"),
                });
            }
            continue;
        }
        let section = value
            .as_object()
            .ok_or_else(|| DocError::Shape(format!("{at} is a mapping")))?;
        let current = current.cloned().unwrap_or(Value::Null);
        let fields = changed(section, &current, &[]);
        if fields.is_empty() {
            continue;
        }
        let mut body: Map<String, Value> = current.as_object().cloned().unwrap_or_default();
        for (k, v) in section {
            body.insert(k.clone(), v.clone());
        }
        // OP-151 m.3 (o): a protection mode change names the tier the server compiles it to
        let what = if name == "protection_mode" {
            format!(
                "update {at}: {} ({})",
                fields.join(", "),
                api::protection_action(&current, &Value::Object(body.clone())).label()
            )
        } else {
            format!("update {at}: {}", fields.join(", "))
        };
        out.push(Step::Write {
            operation: (*op).to_owned(),
            key: None,
            body,
            if_match: tag.clone(),
            exists: true,
            what,
        });
    }
    Ok(())
}

fn plan_mappers(
    wanted: &Value,
    current: Option<&Value>,
    out: &mut Vec<Step>,
) -> Result<(), DocError> {
    let wanted = wanted
        .as_array()
        .ok_or_else(|| DocError::Shape(String::from("settings.mappers is a list")))?;
    let live: Vec<&Value> = current
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    for m in wanted {
        let claim = m
            .get("claim")
            .and_then(Value::as_str)
            .ok_or_else(|| DocError::Shape(String::from("a mapper needs `claim`")))?;
        let source = m.get("source").cloned().unwrap_or(Value::Null);
        let now = live
            .iter()
            .find(|x| x.get("claim").and_then(Value::as_str) == Some(claim))
            .and_then(|x| x.get("source").cloned())
            .unwrap_or(Value::Null);
        if now == source {
            continue;
        }
        let mut body = Map::new();
        body.insert(String::from("source"), source);
        out.push(Step::Write {
            operation: String::from("putMapper"),
            key: Some(claim.to_owned()),
            body,
            if_match: None,
            exists: !now.is_null(),
            what: format!("set mapper {claim}"),
        });
    }
    Ok(())
}

/// The plan from `runtime` to `desired`.
pub(crate) fn plan(
    contract: &Contract,
    realm: &str,
    desired: &Value,
    runtime: &Runtime,
    opts: &PlanOptions,
) -> Result<Vec<Step>, DocError> {
    if !desired.is_object() {
        return Err(DocError::Shape(String::from("the document is a mapping")));
    }
    check_secrets(desired, "")?;
    match desired.get("realm").and_then(Value::as_str) {
        Some(r) if r == realm => {}
        Some(r) => return Err(DocError::Realm(r.to_owned())),
        None => return Err(DocError::Shape(String::from("`realm` is required"))),
    }
    if let Some(Value::Object(o)) = Some(desired)
        && let Some(k) = o.keys().find(|k| {
            k.as_str() != "realm"
                && k.as_str() != "settings"
                && !KINDS.iter().any(|kind| kind.member == k.as_str())
        })
    {
        return Err(DocError::Shape(format!("unknown member `{k}`")));
    }
    let mut out = Vec::new();
    for kind in &KINDS {
        plan_kind(contract, kind, desired, runtime, opts, &mut out)?;
    }
    plan_settings(desired, runtime, &mut out)?;
    Ok(out)
}

/// The proposal document for reserved writes and emergency releases (TN-122, TN-124): what a
/// quorum would sign, never applied by the reconciler.
pub(crate) fn proposal(step: &Step, tier: &str, reason: &str) -> Value {
    let mut m = Map::new();
    if let Step::Write {
        operation,
        key,
        body,
        what,
        ..
    } = step
    {
        m.insert(String::from("operation"), Value::String(operation.clone()));
        if let Some(k) = key {
            m.insert(String::from("key"), Value::String(k.clone()));
        }
        m.insert(String::from("body"), Value::Object(body.clone()));
        m.insert(String::from("change"), Value::String(what.clone()));
    }
    m.insert(String::from("tier"), Value::String(tier.to_owned()));
    m.insert(String::from("reason"), Value::String(reason.to_owned()));
    Value::Object(m)
}

/// The emergency escape for `kind_member/key` (TN-124): the resource's retire, a CT1
/// restriction Exercise, as a proposal. It is not an "unmanage" switch: once retired, the plan
/// reports the resource as retired and never brings it back.
pub(crate) fn release(target: &str) -> Result<Step, DocError> {
    let (member, key) = target
        .split_once('/')
        .filter(|(_, k)| !k.is_empty())
        .ok_or_else(|| DocError::Shape(String::from("--release takes <kind>/<key>")))?;
    let kind = KINDS
        .iter()
        .find(|k| k.member == member || k.resource == member)
        .ok_or_else(|| DocError::Shape(format!("no resource kind `{member}`")))?;
    Ok(Step::Write {
        operation: kind.retire.to_owned(),
        key: Some(key.to_owned()),
        body: Map::new(),
        if_match: None,
        exists: true,
        what: format!("emergency release: retire {}/{key}", kind.member),
    })
}

#[cfg(test)]
mod tests;
