//! Authority hub entries as ADP search results (§8.5 S2, S6, §8.17.7.1, IA-2): the structured
//! rows an Experience surface renders. Each answer is advisory and only ever the reader's own
//! (XI-9, XI-22); none carries an action, which the surface derives from the viewer's authority
//! (XI-11).

use access_authority_core::app::hub::{
    Basis, Entry, Holder, Holding, Rooted, Selection, Source, Use,
};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::json::b64url_encode;
use access_kernel::meta::capacity_value;
use access_kernel::model::Id;
use serde_json::{Map, Value as Out, json};

use crate::adp::domain::json_of;

fn id(i: &Id) -> Out {
    Out::from(b64url_encode(&i.0))
}

fn capacity(c: Capacity) -> Out {
    json_of(&capacity_value(c))
}

/// One hub entry as JSON.
#[must_use]
pub fn encode(entry: &Entry) -> Out {
    match entry {
        Entry::Holding(h) => holding(h),
        Entry::Rooted(r) => rooted(r),
        Entry::Use(u) => used(u),
    }
}

fn holding(h: &Holding) -> Out {
    let holder = match &h.holder {
        Holder::Party(p) => json!({ "party": id(p) }),
        Holder::Public => json!({ "public": true }),
        Holder::Group(classes) => json!({ "group": classes }),
        Holder::Foreign => json!({ "foreign": true }),
    };
    let source = match h.source {
        Source::Anchor(a) => json!({ "anchor": id(&a) }),
        Source::Holding { grant, holder } => json!({ "grant": id(&grant), "holder": id(&holder) }),
    };
    let mut m = Map::new();
    m.insert("type".into(), "holding".into());
    m.insert("grant".into(), id(&h.grant));
    m.insert(
        "groups".into(),
        Out::Array(h.groups.iter().map(|g| Out::from(g.word())).collect()),
    );
    m.insert("holder".into(), holder);
    m.insert("source".into(), source);
    m.insert(
        "capacities".into(),
        Out::Array(h.capacities.iter().copied().map(capacity).collect()),
    );
    m.insert(
        "actions".into(),
        Out::Array(h.actions.iter().map(|a| json_of(&a.to_value())).collect()),
    );
    m.insert("resource".into(), json_of(&h.resource.to_value()));
    m.insert(
        "validity".into(),
        json!({ "from": h.validity.from, "until": h.validity.until }),
    );
    m.insert(
        "budget".into(),
        Out::Array(h.budget.iter().map(|b| json_of(&b.to_value())).collect()),
    );
    m.insert("conditions".into(), Out::from(h.conditions));
    if let Some((name, version)) = &h.named {
        m.insert("named".into(), json!({ "name": name, "version": version }));
    }
    m.insert("since".into(), Out::from(h.since));
    m.insert("revision".into(), Out::from(h.revision));
    if let Some(s) = h.selection {
        let mut out = selection(s);
        // XI-15, §8.17.5.7
        if let (Some(said), Out::Object(o)) = (h.said, &mut out) {
            o.insert("by".into(), Out::from(b64url_encode(&said.issuer.0)));
            o.insert("stated_at".into(), Out::from(said.at));
        }
        m.insert("selection".into(), out);
    }
    Out::Object(m)
}

/// XI-15, OP-153 m.25 (d)
fn selection(s: Selection) -> Out {
    match s {
        Selection::Current { since } => json!({ "state": "current", "since": since }),
        Selection::Stale { since } => json!({ "state": "stale", "since": since }),
        Selection::Ended { pos, at } => {
            let mut m = Map::new();
            m.insert("state".into(), "ended".into());
            if let Some(p) = pos {
                m.insert("pos".into(), Out::from(p));
            }
            if let Some(t) = at {
                m.insert("at".into(), Out::from(t));
            }
            Out::Object(m)
        }
    }
}

fn rooted(r: &Rooted) -> Out {
    json!({
        "type": "root",
        "anchor": id(&r.anchor),
        "sole": r.sole,
        "quorum": r.quorum,
        "since": r.since,
    })
}

fn used(u: &Use) -> Out {
    let basis = match u.basis {
        Basis::Anchor(a) => json!({ "anchor": id(&a) }),
        Basis::Grant(g) => json!({ "grant": id(&g) }),
    };
    let mut m = Map::new();
    m.insert("type".into(), "use".into());
    m.insert("pos".into(), Out::from(u.pos));
    if let Some(at) = u.at {
        m.insert("at".into(), Out::from(at));
    }
    m.insert("intent".into(), Out::from(b64url_encode(&u.intent.0)));
    m.insert("basis".into(), basis);
    m.insert("capacity".into(), capacity(u.capacity));
    m.insert("instance".into(), id(&u.instance));
    m.insert("by_viewer".into(), Out::from(u.by_viewer));
    Out::Object(m)
}
