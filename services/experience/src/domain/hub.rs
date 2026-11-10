//! The hub's rows from the domains' answers (§8.17.7.1, §8.17.7.2, §6.4): owner and time on
//! every row (XI-1, XI-16), capacity apart from provenance (XI-10), one row per limit and owner
//! (XI-14), offered actions with who can (XI-11) at most two steps away (XI-5), a stale
//! selection apart from an ended one (XI-15), and only what is about the reader (XI-9, XI-22). A
//! domain that did not answer is unknown, never empty and never pending.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::contract::{
    ActivityRow, CapacityLabel, ChangeRow, Delivery, Depth, DomainRef, DomainStatus, Expert,
    Financial, Freshness, Hub, Kind, Limit, Offer, Owner, RootRow, Row, Selection, SelectionState,
    SourceLabel, Validity, Who,
};
use crate::domain::{Malformed, texts};

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

/// The reader's selection by a rule-shaped holder and its status text (XI-15, OP-153 m.25 (d)).
fn selection(v: &Value) -> (Option<Selection>, &'static str) {
    let s = &v["selection"];
    let state = match s["state"].as_str() {
        Some("current") => SelectionState::Current,
        Some("stale") => SelectionState::Stale,
        Some("ended") => SelectionState::Ended,
        _ => return (None, texts::STATUS_CURRENT),
    };
    let at = s["at"].as_u64();
    let status = match state {
        SelectionState::Current => texts::STATUS_CURRENT,
        SelectionState::Stale => texts::STATUS_STALE,
        SelectionState::Ended if at.is_some() => texts::STATUS_ENDED,
        SelectionState::Ended => texts::STATUS_ENDED_UNDATED,
    };
    let ended = state == SelectionState::Ended;
    let by = text(&s["by"]);
    // XI-15, §8.17.5.7
    let reason = by.as_ref().map(|_| {
        String::from(if ended {
            texts::SELECTION_NO_LONGER
        } else {
            texts::SELECTION_BECAUSE
        })
    });
    (
        Some(Selection {
            state,
            since: s["since"].as_u64().filter(|_| !ended),
            pos: s["pos"].as_u64().filter(|_| ended),
            at: at.filter(|_| ended),
            stated_at: s["stated_at"].as_u64().filter(|_| by.is_some()),
            by,
            reason,
        }),
        status,
    )
}

/// The HR membership classes a Suiss HR source states (SCIM HR classes, OP-155 m.9 (c)).
pub const HR_CLASSES: [&str; 6] = [
    "hr_department",
    "hr_title",
    "hr_manager",
    "hr_start",
    "hr_end",
    "hr_employment_status",
];

/// "Sync from HR (*issuer*)" for a rule-shaped holder over HR classes only whose selection of
/// the reader an issuer stated (§8.17.9.8, INV-16): the accepted source's normal effect.
fn hr_source(holder: &Who, selection: Option<&Selection>) -> Option<SourceLabel> {
    let hr = holder.kind == "group"
        && !holder.classes.is_empty()
        && holder
            .classes
            .iter()
            .all(|c| HR_CLASSES.contains(&c.as_str()));
    let issuer = selection?.by.clone()?;
    hr.then(|| SourceLabel {
        text: String::from(texts::SOURCE_SYNC_FROM_HR),
        issuer,
    })
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
    let (selection, status) = selection(v);
    let holder = who(&v["holder"]);
    let source = hr_source(&holder, selection.as_ref());
    let row = Row {
        domain: String::from(domain),
        label: label.cloned(),
        grant: text(&v["grant"])?,
        owner: Owner::Access,
        as_of,
        freshness: Freshness::Current,
        status: String::from(status),
        selection,
        who: holder,
        source,
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
                        as_of: None,
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
        attention: None,
        delivery: None,
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
    // §8.13, OP-156 m.6 (d)
    if !hub.domains.is_empty()
        && hub
            .domains
            .iter()
            .all(|d| d.freshness == Freshness::Unknown)
    {
        hub.notices.push(String::from(texts::ACCESS_UNAVAILABLE));
    }
    hub.activity
        .sort_by(|a, b| b.at.cmp(&a.at).then(b.pos.cmp(&a.pos)));
    hub.changes
        .sort_by(|a, b| b.at.cmp(&a.at).then(b.pos.cmp(&a.pos)));
    hub
}

/// Pay's `pay-limit` body (`product-seam.cddl`) as stated, or `None` when it is not one.
#[must_use]
pub fn pay_limit(v: &Value) -> Option<Value> {
    let m = v.as_object()?;
    if m.keys().any(|k| {
        !matches!(
            k.as_str(),
            "currency" | "limit_minor" | "period" | "held_minor"
        )
    }) {
        return None;
    }
    let currency = m.get("currency")?.as_str()?;
    let ok = currency.len() == 3 && currency.bytes().all(|b| b.is_ascii_uppercase());
    m.get("limit_minor")?.as_u64()?;
    let period = m.get("period")?.as_str()?;
    let held = m.get("held_minor").is_none_or(|h| h.as_u64().is_some());
    (ok && held && matches!(period, "transaction" | "day" | "month")).then(|| v.clone())
}

/// Places Pay's financial limits beside the Grants they are about (XI-14, E21, F9): each is a
/// Pay-owned row of its own, after the Grant's authority limits; nothing is added up, compared
/// or derived from the other owner's figure. A limit about a Grant the hub does not show is left
/// out.
///
/// # Errors
/// [`Malformed`] when a statement is not a `pay-limit` body.
pub fn place_financial(hub: &mut Hub, facts: &[Financial]) -> Result<(), Malformed> {
    let mut checked = Vec::with_capacity(facts.len());
    for f in facts {
        checked.push((f, pay_limit(&f.pay_limit).ok_or(Malformed("financial"))?));
    }
    for rows in [
        &mut hub.acting_for_you,
        &mut hub.shared_from_you,
        &mut hub.your_authority,
    ] {
        for r in rows.iter_mut() {
            for (f, term) in &checked {
                if f.grant == r.grant {
                    r.limits.push(Limit {
                        kind: String::from("financial"),
                        owner: Owner::Pay,
                        term: term.clone(),
                        as_of: Some(f.as_of),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Relay's delivery from Access's `relay-status` answer `{relay_lag_ms, notifications_delayed}`
/// (OP-156 m.11 (e)); `None` for anything else.
#[must_use]
pub fn delivery(answer: &Value) -> Option<Delivery> {
    let lag = answer.get("relay_lag_ms")?;
    let lag_ms = if lag.is_null() {
        None
    } else {
        Some(lag.as_u64()?)
    };
    Some(Delivery {
        owner: Owner::Relay,
        delayed: answer.get("notifications_delayed")?.as_bool()?,
        lag_ms,
    })
}

/// Shows Relay's delivery (§8.13 "Relay delayed"): a delay adds one notice and changes no row,
/// no change and no outcome; authority never waits on delivery (INV-24, E30).
pub fn show_delivery(hub: &mut Hub, d: Delivery) {
    if d.delayed {
        hub.notices.push(String::from(texts::NOTIFICATIONS_DELAYED));
    }
    hub.delivery = Some(d);
}

pub mod attention;

#[cfg(test)]
mod tests;
