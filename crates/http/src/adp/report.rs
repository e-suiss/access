//! Developer-surface reports as ADP search results (§8.17.10, §5.4, §16.5.1): the structured
//! fields the console turns into text. Each carries `advisory: true`; none carries an accept or
//! any other action (X21).

use access_authority_core::app::impact::{
    AbilityChange, CompromiseImpact, Compromised, PolicyChange, RevocationImpact, Revoked,
    RoleChange,
};
use access_authority_core::app::management::{BulkImpact, Change, Changed, Holding};
use access_authority_core::app::publishing::{Offer, ParamClass, Standing};
use access_authority_core::app::roles::{AdminGrant, MetaLine, RoleVersion, tier_word};
use access_authority_core::app::sources::{Issuer, Sources};
use access_authority_core::query::Report;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::model::Id;
use serde_json::{Value as Out, json};

use crate::adp::domain::json_of;

fn id(i: &Id) -> Out {
    Out::from(b64url_encode(&i.0))
}

fn ids(list: &[Id]) -> Out {
    Out::Array(list.iter().map(id).collect())
}

fn digest(d: &Digest) -> Out {
    Out::from(b64url_encode(&d.0))
}

/// One report as JSON.
#[must_use]
pub fn encode(report: &Report) -> Out {
    match report {
        Report::Publication(o) => publication(o),
        Report::RoleChange(c) => role_change(c),
        Report::PolicyChange(c) => policy_change(c),
        Report::Revocation(r) => revocation(r),
        Report::Compromise(c) => compromise(c),
        Report::Roles(r) => json!({
            "type": "roles",
            "roles": r.iter().map(|(name, latest)| json!({ "name": name, "latest": latest })).collect::<Vec<_>>(),
            "advisory": true,
        }),
        Report::Role(r) => role(r),
        Report::AdminGrant(g) => admin_grant(g),
        Report::Holding(h) => holding(h),
        Report::Change(c) => change(c),
        Report::Bulk(b) => bulk(b),
        Report::Sources(s) => sources(s),
        Report::AgentStatus(s) => agent_status(s),
    }
}

/// A-11, E26
fn agent_status(s: &access_authority_core::app::agent_status::AgentStatus) -> Out {
    let names = |actions: &[access_kernel::model::ActionRef]| {
        actions
            .iter()
            .map(|a| Out::from(format!("{}:{}", a.namespace, a.name)))
            .collect::<Vec<_>>()
    };
    let holdings: Vec<Out> = s
        .holdings
        .iter()
        .map(|h| {
            json!({
                "grant": id(&h.grant),
                "actions": names(&h.actions),
                "until": h.until,
                "budgets": h.budgets.iter().map(|b| json!({
                    "dimension": b.dimension,
                    "capacity": b.capacity,
                    "remaining": b.remaining,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut out = serde_json::Map::new();
    out.insert(String::from("type"), Out::from("agent_status"));
    out.insert(String::from("instance"), id(&s.instance));
    out.insert(String::from("party"), id(&s.party));
    out.insert(String::from("live"), Out::Bool(s.live));
    if let Some((actions, until)) = &s.mandate {
        out.insert(
            String::from("mandate"),
            json!({ "actions": names(actions), "until": until }),
        );
    }
    out.insert(String::from("holdings"), Out::Array(holdings));
    out.insert(String::from("advisory"), Out::Bool(true));
    Out::Object(out)
}

fn kernel_json(v: Result<Out, crate::adp::payload::PayloadError>) -> Out {
    v.unwrap_or(Out::Null)
}

fn role(r: &RoleVersion) -> Out {
    let catalogs: Vec<Out> = r
        .not_included
        .catalogs
        .iter()
        .map(|c| {
            json!({
                "namespace": c.namespace,
                "catalog": digest(&c.catalog),
                "catalog_version": c.catalog_version,
                "newer": c.newer.iter().map(|a| json_of(&a.to_value())).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "type": "role",
        "name": r.name,
        "version": r.version,
        "latest": r.latest,
        "digest": digest(&r.digest),
        "since": r.since,
        "authority": kernel_json(crate::adp::payload::authority_set_to_json(&r.authority)),
        "not_included": {
            "reserved": r.not_included.reserved.iter().map(|a| json_of(&a.to_value())).collect::<Vec<_>>(),
            "catalogs": catalogs,
        },
        "advisory": true,
    })
}

fn meta_line(l: &MetaLine) -> Out {
    json!({
        "action": l.action,
        "tier_when_widening": tier_word(l.tier_when_widening),
        "grant_quorum": l.grant_quorum,
        "joint_root_quorum": l.joint_root_quorum,
    })
}

fn admin_grant(g: &AdminGrant) -> Out {
    json!({
        "type": "admin_grant",
        "grant": id(&g.grant),
        "role": g.role.as_ref().map(|(name, version)| json!({ "name": name, "version": version })),
        "actions": g.actions.iter().map(meta_line).collect::<Vec<_>>(),
        "reserved": g.reserved.iter().map(meta_line).collect::<Vec<_>>(),
        "advisory": true,
    })
}

fn sources(s: &Sources) -> Out {
    let list: Vec<Out> = s
        .sources
        .iter()
        .map(|x| {
            let issuer = match &x.issuer {
                Issuer::Party(p) => json!({ "party": id(p) }),
                Issuer::Foreign(d) => json!({ "foreign": digest(d) }),
            };
            json!({
                "acceptance": id(&x.acceptance),
                "use": x.use_,
                "issuer": issuer,
                "classes": x.classes,
                "namespace": x.namespace,
                "since": x.since.to_string(),
                "protected": x.protected,
                "dependents": x.dependents,
            })
        })
        .collect();
    let partners: Vec<Out> = s
        .partners
        .iter()
        .map(|p| {
            json!({
                "domain": digest(&p.domain),
                "acceptances": ids(&p.acceptances),
                "ceilings": p.ceilings.iter().map(|c| json!({
                    "grant": id(&c.grant),
                    "class": c.class,
                    "actions": c.actions.iter().map(|a| json_of(&a.to_value())).collect::<Vec<_>>(),
                    "resource": json_of(&c.resource.to_value()),
                    "until": c.until,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({ "type": "sources", "sources": list, "partners": partners, "advisory": true })
}

fn holding(h: &Holding) -> Out {
    json!({
        "type": "holding",
        "grant": id(&h.grant),
        "holder": id(&h.holder),
        "since": h.since,
        "actions": h.actions.iter().map(|a| json_of(&a.to_value())).collect::<Vec<_>>(),
        "resource": json_of(&h.resource.to_value()),
        "advisory": true,
    })
}

fn change(c: &Change) -> Out {
    let (object, version) = match &c.changed {
        Changed::Object(i) | Changed::KeyEvent { claim: i, .. } => (id(i), None),
        Changed::Role { name, version } => (Out::from(name.as_str()), Some(*version)),
    };
    let mut out = json!({
        "type": "change",
        "position": c.position.to_string(),
        "at": c.at,
        "kind": c.kind.word(),
        "id": object,
        "version": version,
        "ended": c.ended,
        "own": c.own,
        "advisory": true,
    });
    // U26, SI-13
    if let (Changed::KeyEvent { class, issuer, .. }, Some(m)) = (&c.changed, out.as_object_mut()) {
        m.insert("class".into(), Out::from(class.as_str()));
        m.insert("issuer".into(), id(issuer));
    }
    out
}

fn bulk(b: &BulkImpact) -> Out {
    json!({
        "type": "bulk_impact",
        "revoke": ids(&b.revoke),
        "items": b.items.iter().map(revocation).collect::<Vec<_>>(),
        "subtree": ids(&b.subtree),
        "aftermath": {
            "grants_ending": b.aftermath.grants_ending,
            "projections_open": b.aftermath.projections_open,
            "honoured_until_ms": b.aftermath.honoured_until_ms,
            "running_copies": b.aftermath.running_copies,
            "confirmed_applied": b.aftermath.confirmed_applied,
        },
        "max_exposure_ms": b.max_exposure_ms,
        "advisory": true,
    })
}

fn publication(o: &Offer) -> Out {
    let accepted_version = match o.standing {
        Standing::Pending { accepted_version } => accepted_version,
        _ => None,
    };
    let parameters: Vec<Out> = o
        .classes
        .iter()
        .map(|(a, p, c)| match c {
            ParamClass::Opaque => {
                json!({ "action": a, "parameter": p, "class": "authority-opaque" })
            }
            ParamClass::Relevant(x) => json!({
                "action": a, "parameter": p, "class": "authority-relevant", "affects": x.word(),
            }),
        })
        .collect();
    json!({
        "type": "schema_publication",
        "fingerprint": digest(&o.fingerprint),
        "publisher": id(&o.publisher),
        "namespace": o.namespace,
        "catalog_version": o.catalog_version,
        "standing": o.standing.word(),
        "accepted_version": accepted_version,
        "diff": {
            "added": o.diff.added,
            "removed": o.diff.removed,
            "changed": o.diff.changed,
            "reserved_added": o.diff.reserved_added,
            "reserved_removed": o.diff.reserved_removed,
        },
        "reserved": o.reserved,
        "parameters": parameters,
        "compatibility": o.compatibility.map(|c| json!({
            "from": c.from, "relation": c.relation.word(),
        })),
        "existing_grants_unchanged": o.notes.existing_grants_unchanged,
        "new_actions": o.notes.new_actions,
        "text": o.notes.text,
        "advisory": true,
    })
}

fn ability(a: &AbilityChange) -> Out {
    json!({
        "ability": {
            "action": json_of(&a.ability.action.to_value()),
            "bounds": json_of(&a.ability.bounds.to_value()),
        },
        "holders_gaining": a.holders_gaining,
        "holders_losing": a.holders_losing,
    })
}

fn role_change(c: &RoleChange) -> Out {
    let (name, version, pin) = &c.pin;
    json!({
        "type": "change_impact",
        "role": { "name": c.name, "from": c.from, "to": c.to },
        "pin": { "name": name, "version": version, "digest": digest(pin) },
        "relation": c.relation.word(),
        "moves": ids(&c.moves),
        "amends": c.amends.iter().map(|b| {
            access_kernel::meta::Payload::from_bytes(b)
                .ok()
                .and_then(|p| crate::adp::payload::to_json_value(&p).ok())
                .unwrap_or(Out::Null)
        }).collect::<Vec<_>>(),
        "holders": {
            "parties": c.holders.parties,
            "everyone": c.holders.everyone,
            "upper_bound": c.holders.upper_bound,
        },
        "abilities": c.abilities.iter().map(ability).collect::<Vec<_>>(),
        "expansion": c.expansion.as_ref().map(|e| json!({
            "tier": tier_word(e.tier),
            "joint_root_quorum": e.joint_root_quorum,
            "delay_s": e.delay_s,
            "requirements": e.requirements.iter().map(|t| json_of(&t.to_value())).collect::<Vec<_>>(),
        })),
        "orphans": {
            "empty_scopes": ids(&c.orphans.empty_scopes),
            "unselecting": ids(&c.orphans.unselecting),
        },
        "capped": c.capped,
        "advisory": true,
    })
}

fn policy_change(c: &PolicyChange) -> Out {
    json!({
        "type": "change_impact",
        "policy": c.policy.as_ref().map(id),
        "relation": c.relation.word(),
        "refused": c.refused,
        "advisory": true,
    })
}

fn revocation(r: &RevocationImpact) -> Out {
    let revoked = match r.revoked {
        Revoked::Grant(g) => json!({ "grant": id(&g) }),
        Revoked::Instance(i) => json!({ "instance": id(&i) }),
    };
    let exposed: Vec<Out> = r
        .exposed
        .iter()
        .map(|e| {
            json!({
                "exercise": digest(&e.exercise),
                "holder": id(&e.holder),
                "class": e.class,
                "horizon_ms": e.horizon_ms,
                "window_ms": e.window_ms,
                "pep": e.pep,
                "applied_at": e.applied_at,
            })
        })
        .collect();
    let acknowledged: Vec<Out> = r
        .acknowledged
        .iter()
        .map(|a| json!({ "pep": a.pep, "applied_at": a.applied_at, "basis": a.basis }))
        .collect();
    json!({
        "type": "revocation_impact",
        "revoked": revoked,
        "at": r.at,
        "subtree": ids(&r.subtree),
        "exposed": exposed,
        "max_exposure_ms": r.max_exposure_ms,
        "index_lag": r.index_lag,
        "orphan_tuples": r.orphan_tuples,
        "acknowledged": acknowledged,
        "aftermath": {
            "grants_ending": r.aftermath.grants_ending,
            "projections_open": r.aftermath.projections_open,
            "honoured_until_ms": r.aftermath.honoured_until_ms,
            "running_copies": r.aftermath.running_copies,
            "confirmed_applied": r.aftermath.confirmed_applied,
        },
        "advisory": true,
    })
}

fn compromise(c: &CompromiseImpact) -> Out {
    let compromised = match c.compromised {
        Compromised::Instance(i) => json!({ "instance": id(&i) }),
        Compromised::Issuer(p) => json!({ "issuer": id(&p) }),
        Compromised::Key(k) => json!({ "key": b64url_encode(&k) }),
    };
    let exercises: Vec<Out> = c
        .exercises
        .iter()
        .map(|e| json!({ "pos": e.pos, "intent": digest(&e.intent), "outcome": e.outcome }))
        .collect();
    json!({
        "type": "compromise_impact",
        "compromised": compromised,
        "window": { "from": c.window.from, "until": c.window.until },
        "instance": c.instance.as_ref().map(id),
        "exercises": exercises,
        "grants": ids(&c.grants),
        "contributions": ids(&c.contributions),
        "projections": c.projections.iter().map(digest).collect::<Vec<_>>(),
        "claims": ids(&c.claims),
        "capped": c.capped,
        "advisory": true,
    })
}
