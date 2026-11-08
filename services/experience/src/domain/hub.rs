//! The hub's rows from the domains' answers (§8.17.7.1, §8.17.7.2, §6.4): owner and time on
//! every row (XI-1, XI-16), capacity apart from provenance (XI-10), one row per limit and owner
//! (XI-14), offered actions with who can (XI-11) at most two steps away (XI-5), a lapsed
//! selection as "needs refresh" (XI-15), and only what is about the reader (XI-9, XI-22). A
//! domain that did not answer is unknown, never empty and never pending.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::contract::{
    ActivityRow, CapacityLabel, ChangeRow, Depth, DomainRef, DomainStatus, Expert, Freshness, Hub,
    Kind, Limit, Offer, Owner, RootRow, Row, Validity, Who,
};
use crate::domain::texts;

/// What one read of one domain came back as.
#[derive(Clone, Debug, PartialEq)]
pub enum Read {
    /// The search page: its `results`.
    Answered(Vec<Value>),
    /// No usable answer: the domain is unknown for this read.
    Unknown,
}

/// One domain's reads.
#[derive(Clone, Debug, PartialEq)]
pub struct DomainReads {
    /// The domain and the reader's label.
    pub domain: DomainRef,
    /// Each kind read, with what came back.
    pub reads: Vec<(Kind, Read)>,
}

/// The results of an ADP search answer, when it is one.
#[must_use]
pub fn results(answer: &Value) -> Option<Vec<Value>> {
    answer.get("results")?.as_array().cloned()
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(String::from)
}

/// The capacity labels of a holding (XI-10): never empty, absent agency being `own` (INV-4).
fn capacities(row: &Value, yours: bool) -> Vec<CapacityLabel> {
    let own = || CapacityLabel {
        text: String::from(if yours {
            texts::CAPACITY_AS_YOURSELF
        } else {
            texts::CAPACITY_OWN_USE
        }),
        party: None,
    };
    let mut out: Vec<CapacityLabel> = row["capacities"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|c| match c {
                    Value::String(s) if s == "own" => Some(own()),
                    Value::Object(m) => m.get("for").and_then(text).map(|p| CapacityLabel {
                        text: String::from(texts::CAPACITY_ON_BEHALF),
                        party: Some(p),
                    }),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if out.is_empty() {
        out.push(own());
    }
    out
}

fn capacity_of(c: &Value) -> CapacityLabel {
    match c.get("for").and_then(text) {
        Some(p) => CapacityLabel {
            text: String::from(texts::CAPACITY_ON_BEHALF),
            party: Some(p),
        },
        None => CapacityLabel {
            text: String::from(texts::CAPACITY_AS_YOURSELF),
            party: None,
        },
    }
}

fn who(holder: &Value) -> Who {
    if let Some(p) = holder.get("party").and_then(text) {
        return Who {
            kind: String::from("party"),
            party: Some(p),
            classes: Vec::new(),
        };
    }
    if let Some(classes) = holder.get("group").and_then(Value::as_array) {
        return Who {
            kind: String::from("group"),
            party: None,
            classes: classes.iter().filter_map(text).collect(),
        };
    }
    let kind = if holder.get("public").is_some() {
        "everyone"
    } else {
        "foreign"
    };
    Who {
        kind: String::from(kind),
        party: None,
        classes: Vec::new(),
    }
}

/// Whether the reader gave the holding: it derives from the reader's holding, or from an Anchor
/// the reader roots.
fn given_by(row: &Value, viewer: &str, roots: &BTreeSet<String>) -> bool {
    let source = &row["source"];
    source.get("holder").and_then(Value::as_str) == Some(viewer)
        || source
            .get("anchor")
            .and_then(Value::as_str)
            .is_some_and(|a| roots.contains(a))
}

/// The actions a holding offers (XI-11, XI-5, §8.17.7.1): Revoke and Narrow for whoever gave
/// it, Suspend only for a root of its Anchor; one the reader cannot take shows who can.
fn offers(row: &Value, viewer: &str, roots: &BTreeSet<String>) -> Vec<Offer> {
    let gave = given_by(row, viewer, roots);
    let mut out = Vec::new();
    for action in ["revoke", "narrow"] {
        out.push(Offer {
            action: String::from(action),
            available: gave,
            who_can: (!gave).then(|| String::from(texts::WHO_CAN_GRANTOR)),
            steps: 2,
        });
    }
    // §8.17.7.3
    if row["source"]
        .get("anchor")
        .and_then(Value::as_str)
        .is_some_and(|a| roots.contains(a))
    {
        out.push(Offer {
            action: String::from("suspend"),
            available: true,
            who_can: None,
            steps: 2,
        });
    }
    out
}

/// One holding row, or `None` when the answer is not a holding about the reader.
fn row(
    v: &Value,
    viewer: &str,
    (domain, label): (&str, Option<&String>),
    as_of: u64,
    depth: Depth,
    roots: &BTreeSet<String>,
) -> Option<(Vec<String>, Row)> {
    if v["type"] != "holding" {
        return None;
    }
    let groups: Vec<String> = v["groups"].as_array()?.iter().filter_map(text).collect();
    if groups.is_empty() {
        return None;
    }
    let yours = groups.iter().any(|g| g == "your_authority");
    // XI-15
    let lapsed = v.get("member") == Some(&Value::Bool(false));
    let row = Row {
        domain: String::from(domain),
        label: label.cloned(),
        grant: text(&v["grant"])?,
        owner: Owner::Access,
        as_of,
        freshness: if lapsed {
            Freshness::NeedsRefresh
        } else {
            Freshness::Current
        },
        status: String::from(if lapsed {
            texts::STATUS_NEEDS_REFRESH
        } else {
            texts::STATUS_CURRENT
        }),
        who: who(&v["holder"]),
        capacity: capacities(v, yours),
        what: v["actions"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| {
                        Some(format!(
                            "{}:{}",
                            x["namespace"].as_str()?,
                            x["name"].as_str()?
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        validity: Validity {
            valid_until: v.pointer("/validity/until").and_then(Value::as_u64)?,
            text: String::from(texts::VALID_UNTIL),
        },
        // XI-14
        limits: v["budget"]
            .as_array()
            .map(|b| {
                b.iter()
                    .map(|t| Limit {
                        kind: String::from("authority"),
                        owner: Owner::Access,
                        term: t.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        offers: offers(v, viewer, roots),
        expert: (depth != Depth::Default).then(|| Expert {
            source: v["source"].clone(),
            since: v["since"].as_u64().unwrap_or(0),
            revision: v["revision"].as_u64().unwrap_or(0),
            role: v.get("named").cloned(),
        }),
    };
    Some((groups, row))
}

fn activity(
    v: &Value,
    viewer: &str,
    (domain, label): (&str, Option<&String>),
    depth: Depth,
) -> Option<ActivityRow> {
    if v["type"] != "use" {
        return None;
    }
    let by_viewer = v["by_viewer"].as_bool()?;
    let capacity = &v["capacity"];
    // XI-22
    if !by_viewer && capacity.get("for").and_then(Value::as_str) != Some(viewer) {
        return None;
    }
    Some(ActivityRow {
        domain: String::from(domain),
        label: label.cloned(),
        owner: Owner::Access,
        pos: v["pos"].as_u64()?,
        at: v["at"].as_u64(),
        text: String::from(if by_viewer {
            texts::ACTIVITY_BY_YOU
        } else {
            texts::ACTIVITY_FOR_YOU
        }),
        capacity: capacity_of(capacity),
        grant: v["basis"].get("grant").and_then(text),
        instance: (depth != Depth::Default)
            .then(|| text(&v["instance"]))
            .flatten(),
    })
}

/// The object kinds of the domain's Changes feed (IA-2).
const CHANGE_KINDS: [&str; 9] = [
    "grant",
    "anchor",
    "party",
    "instance",
    "mandate",
    "acceptance",
    "policy",
    "authority_set",
    "key_event",
];

fn change(v: &Value, (domain, label): (&str, Option<&String>)) -> Option<ChangeRow> {
    if v["type"] != "change" {
        return None;
    }
    let kind = text(&v["kind"])?;
    if !CHANGE_KINDS.contains(&kind.as_str()) {
        return None;
    }
    let ended = v["ended"].as_bool().unwrap_or(false);
    Some(ChangeRow {
        domain: String::from(domain),
        label: label.cloned(),
        owner: Owner::Access,
        pos: v["position"].as_str()?.parse().ok()?,
        at: v["at"].as_u64(),
        text: texts::change(&kind, ended),
        key_event: (kind == "key_event")
            .then(|| json!({ "class": v["class"], "issuer": v["issuer"] })),
        about: text(&v["id"])?,
        ended,
        own: v["own"].as_bool().unwrap_or(false),
        kind,
        derived: true,
    })
}

/// How one domain was seen (XI-16): unknown when any read of it got no usable answer.
fn status(d: &DomainReads, label: Option<&String>, now: u64) -> DomainStatus {
    let unknown = d.reads.iter().any(|(_, r)| *r == Read::Unknown) || d.reads.is_empty();
    DomainStatus {
        domain: d.domain.domain.clone(),
        label: label.cloned(),
        owner: Owner::Access,
        freshness: if unknown {
            Freshness::Unknown
        } else {
            Freshness::Current
        },
        as_of: (!unknown).then_some(now),
        text: String::from(if unknown {
            texts::DOMAIN_UNREACHABLE
        } else {
            texts::DOMAIN_CURRENT
        }),
    }
}

/// The hub of `viewer` at `depth` from each domain's reads, assembled at `now`.
#[must_use]
pub fn assemble(viewer: &str, depth: Depth, now: u64, domains: &[DomainReads]) -> Hub {
    // IA-6
    let show = domains.len() > 1;
    let mut hub = Hub {
        as_of: now,
        depth,
        domains: Vec::new(),
        show_domains: show,
        acting_for_you: Vec::new(),
        shared_from_you: Vec::new(),
        your_authority: Vec::new(),
        roots: Vec::new(),
        activity: Vec::new(),
        changes: Vec::new(),
        notices: vec![String::from(texts::NOT_SHOWN)],
    };
    for d in domains {
        let label = d.domain.label.as_ref().filter(|_| show);
        let at = (d.domain.domain.as_str(), label);
        hub.domains.push(status(d, label, now));
        let empty = Vec::new();
        let of = |k: Kind| {
            d.reads
                .iter()
                .find(|(kind, _)| *kind == k)
                .map_or(&empty, |(_, r)| match r {
                    Read::Answered(v) => v,
                    Read::Unknown => &empty,
                })
        };
        let roots: BTreeSet<String> = of(Kind::Inventory)
            .iter()
            .filter(|v| v["type"] == "root")
            .filter_map(|v| text(&v["anchor"]))
            .collect();
        for v in of(Kind::Inventory) {
            if v["type"] == "root" {
                let sole = v["sole"].as_bool().unwrap_or(false);
                if let Some(anchor) = text(&v["anchor"]) {
                    hub.roots.push(RootRow {
                        domain: d.domain.domain.clone(),
                        label: label.cloned(),
                        anchor,
                        owner: Owner::Access,
                        sole,
                        confirm: String::from(if sole {
                            texts::ROOT_SOLE_CONFIRM
                        } else {
                            texts::ROOT_JOINT_CONFIRM
                        }),
                    });
                }
                continue;
            }
            let Some((groups, r)) = row(v, viewer, at, now, depth, &roots) else {
                continue;
            };
            for g in &groups {
                let into = match g.as_str() {
                    "acting_for_you" => &mut hub.acting_for_you,
                    "shared_from_you" => &mut hub.shared_from_you,
                    "your_authority" => &mut hub.your_authority,
                    _ => continue,
                };
                into.push(r.clone());
            }
        }
        hub.activity.extend(
            of(Kind::Activity)
                .iter()
                .filter_map(|v| activity(v, viewer, at, depth)),
        );
        hub.changes
            .extend(of(Kind::Changes).iter().filter_map(|v| change(v, at)));
    }
    if hub
        .domains
        .iter()
        .any(|d| d.freshness == Freshness::Unknown)
    {
        hub.notices.push(String::from(texts::SOME_UNKNOWN));
    }
    hub.activity
        .sort_by(|a, b| b.at.cmp(&a.at).then(b.pos.cmp(&a.pos)));
    hub.changes
        .sort_by(|a, b| b.at.cmp(&a.at).then(b.pos.cmp(&a.pos)));
    hub
}

#[cfg(test)]
mod tests;
