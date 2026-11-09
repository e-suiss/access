//! The just-in-time authority request (§8.17.5.2, §8.18.4, OP-149 m.9, X5): after a DENY or a
//! `REQUIRE_ACTION` the agent hands its coordinator the typed intent in the
//! `authority-request` contract (`conformance/cddl/authority-request.cddl`) together with the
//! typed routes, and then waits. A `REQUIRE_ACTION` names its nonce, which the agent asks again
//! once a proof is in (same nonce); a DENY names none, because only a new nonce after a change of
//! state can be asked (C30).
//!
//! The agent never writes the canonical summary a person sees; that is rendered from the
//! schema. Its own words travel only as the "Requester's note" (`reason`, A-6, §8.17.6.2).

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::contract::{Exercise, Step};
use super::decision::Route;
use crate::authorize::Out;

/// The agent's own note on a request, shown apart as "Requester's note" (A-6): 1 to 1024
/// characters, never rendered as the request itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequesterNote(String);

impl RequesterNote {
    /// The note, when it is 1 to 1024 characters.
    #[must_use]
    pub fn new(note: &str) -> Option<Self> {
        let n = note.chars().count();
        (1..=1024).contains(&n).then(|| Self(String::from(note)))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who asks: the agent Party and the Instance it asks through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requester {
    /// The agent Party.
    pub party: Id,
    /// Its Instance.
    pub instance: Option<Id>,
}

/// The coordinator's references, when the request answers its work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkRefs {
    /// Work item.
    pub work: Option<Digest>,
    /// Commitment.
    pub commitment: Option<Digest>,
    /// Gate.
    pub gate: Option<Digest>,
}

/// What the coordinator gets: the `authority-request` JSON and the routes Access's typed answer
/// gives. `same_nonce` says whether the agent asks again under the same nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handoff {
    /// The `authority-request` JSON.
    pub request: String,
    /// The routes.
    pub routes: Vec<Route>,
    /// Whether the agent asks again under the same nonce: `true` after a `REQUIRE_ACTION`.
    pub same_nonce: bool,
}

/// The authority request for `exercise` after `step`, or `None` when `step` needs none (an
/// ALLOW, or no decision at all).
#[must_use]
pub fn handoff(
    exercise: &Exercise,
    step: &Step,
    requester: Requester,
    note: &RequesterNote,
    refs: WorkRefs,
) -> Option<Handoff> {
    let (routes, same_nonce) = match step {
        Step::Wait(w) => (w.routes.clone(), true),
        Step::Stop(_) => (Vec::from([Route::Coordinator]), false),
        Step::Proceed(_) | Step::Unknown(_) => return None,
    };
    Some(Handoff {
        request: authority_request(exercise, requester, note, refs, same_nonce)?,
        routes,
        same_nonce,
    })
}

/// The `authority-request` JSON for `exercise`; with `require_action`, it names the nonce.
#[must_use]
pub fn authority_request(
    exercise: &Exercise,
    requester: Requester,
    note: &RequesterNote,
    refs: WorkRefs,
    require_action: bool,
) -> Option<String> {
    let e = exercise.envelope();
    let resource = e.resources.first()?;
    let mut out = Out(String::new());
    out.0.push('{');
    out.key("requester");
    out.0.push('{');
    out.key("party");
    out.id(&requester.party);
    if let Some(i) = &requester.instance {
        out.0.push(',');
        out.key("instance");
        out.id(i);
    }
    out.0.push_str("},");
    out.key("action");
    out.action(&e.action);
    out.0.push(',');
    out.key("resource");
    out.resource(resource);
    out.0.push(',');
    out.key("params");
    out.0.push('{');
    let mut first = true;
    for (k, v) in &e.params {
        out.comma(&mut first);
        out.key(k);
        out.param(v);
    }
    out.0.push_str("},");
    out.key("capacity");
    match exercise.capacity() {
        Capacity::Own => out.text("own"),
        Capacity::For(p) => {
            out.0.push('{');
            out.key("for");
            out.id(&p);
            out.0.push('}');
        }
    }
    out.0.push(',');
    out.key("reason");
    out.text(note.as_str());
    for (name, d) in [
        ("work_ref", refs.work),
        ("commitment_ref", refs.commitment),
        ("gate_ref", refs.gate),
    ] {
        if let Some(d) = d {
            out.0.push(',');
            out.key(name);
            out.digest(&d);
        }
    }
    if require_action {
        out.0.push(',');
        out.key("require_action");
        out.0.push('{');
        out.key("domain");
        out.digest(exercise.domain());
        out.0.push(',');
        out.key("nonce");
        out.bytes(exercise.nonce());
        out.0.push(',');
        out.key("intent");
        out.digest(exercise.digest());
        out.0.push('}');
    }
    out.0.push(',');
    out.key("expires_at");
    out.uint(e.validity.until);
    out.0.push('}');
    Some(out.0)
}
