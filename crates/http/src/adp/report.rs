//! Developer-surface reports as ADP search results (§8.17.10, §5.4, §16.5.1): the structured
//! fields the console turns into text. Each carries `advisory: true`; none carries an accept or
//! any other action (X21).

use access_authority_core::app::impact::{
    AbilityChange, CompromiseImpact, Compromised, PolicyChange, RevocationImpact, Revoked,
    RoleChange,
};
use access_authority_core::app::publishing::{Offer, ParamClass, Standing};
use access_authority_core::app::roles::tier_word;
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
    }
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
            })
        })
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
        "aftermath": {
            "grants_ending": r.aftermath.grants_ending,
            "projections_open": r.aftermath.projections_open,
            "honoured_until_ms": r.aftermath.honoured_until_ms,
            "running_copies": r.aftermath.running_copies,
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
