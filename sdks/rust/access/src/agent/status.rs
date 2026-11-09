//! The agent's own status (A-11, §9.7, E26): the ADP search kind `agent-status` answers, to the
//! agent Instance that signs the read, a summary of that Instance only: whether it is live, its
//! Mandate, the Grants its Party holds with what each covers, until when, and the budget left.
//! Nothing about the principal's other delegations is in it. It is advisory like every search
//! and never a credential (A-10); whether one intent would be allowed is [`super::contract::Exercise::check`].

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use access_kernel::ais::Statement;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::meta::{ExerciseBasis, core_action, meta_anchor};
use access_kernel::model::{Id, ResourceRef, Window};

use super::contract::{AgentError, Signs};
use super::decision::Unread;
use super::text::Untrusted;
use crate::authorize::{MAX_BODY, MAX_NONCE, MIN_NONCE, Out};
use crate::transport::{Answer, Clock};

/// The search kind.
pub const KIND: &str = "agent-status";

/// The path the search is posted to.
pub const PATH: &str = "/access/v1/search/agent-status";

/// How long the read intent is valid.
const VALID_MS: u64 = 5 * 60_000;

/// One budget of a holding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Budget {
    /// `count`, or the amount's unit.
    pub dimension: Untrusted,
    /// The window's capacity.
    pub capacity: u64,
    /// What is left in the current window.
    pub remaining: u64,
}

/// One Grant the agent's Party holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holding {
    /// The Grant.
    pub grant: Id,
    /// The actions it covers, `namespace:name`.
    pub actions: Vec<Untrusted>,
    /// Its horizon; `None` when it has none.
    pub until: Option<u64>,
    /// Its budgets.
    pub budgets: Vec<Budget>,
}

/// The agent Instance's summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The Instance.
    pub instance: Id,
    /// Its Party.
    pub party: Id,
    /// Whether the Instance is live.
    pub live: bool,
    /// The actions its Mandate covers, and its horizon, when it has one.
    pub mandate: Option<(Vec<Untrusted>, Option<u64>)>,
    /// The Grants its Party holds.
    pub holdings: Vec<Holding>,
}

/// The search intent, valid around `now`.
#[must_use]
pub fn intent(now: u64) -> IntentEnvelope {
    IntentEnvelope {
        provenance: alloc::collections::BTreeMap::new(),
        action: core_action("read"),
        resources: alloc::vec![ResourceRef {
            namespace: String::from("access.search"),
            path: alloc::vec![String::from(KIND)],
            incarnation: 0,
        }],
        params: alloc::collections::BTreeMap::new(),
        opaque: alloc::collections::BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: now.saturating_sub(60_000),
            until: now.saturating_add(VALID_MS),
        },
    }
}

/// The signed search body for `domain` through `pep` under `nonce`.
///
/// # Errors
/// [`AgentError::Nonce`], [`AgentError::Clock`], [`AgentError::Signature`],
/// [`AgentError::Intent`].
pub fn body(
    domain: &Digest,
    pep: &str,
    nonce: &[u8],
    signer: &impl Signs,
    clock: &impl Clock,
) -> Result<String, AgentError> {
    if !(MIN_NONCE..=MAX_NONCE).contains(&nonce.len()) {
        return Err(AgentError::Nonce);
    }
    let now = clock.now().ok_or(AgentError::Clock)?;
    let envelope = intent(now);
    let digest = intent_digest(&envelope).map_err(|_| AgentError::Intent)?;
    let basis = ExerciseBasis::Anchor(meta_anchor(domain));
    let ais = signer
        .sign(&Statement {
            domain: *domain,
            nonce: nonce.to_vec(),
            intent: digest,
            mode: Mode::Check,
            pep: String::from(pep),
            capacity: Capacity::Own,
            basis,
            iat: now,
            exercise: None,
        })
        .ok_or(AgentError::Signature)?;
    let mut out = Out(String::new());
    out.0.push_str("{\"context\":{");
    out.key("domain");
    out.digest(domain);
    out.0.push_str(",\"mode\":\"check\",");
    out.key("nonce");
    out.bytes(nonce);
    out.0.push(',');
    out.key("ais");
    out.bytes(&ais);
    out.0.push(',');
    out.key("basis");
    out.basis(&basis);
    out.0.push_str(",\"capacity\":\"own\",");
    out.key("intent");
    out.envelope(&envelope);
    let _ = write!(out.0, ",\"query\":{{}}}}}}");
    Ok(out.0)
}

fn id(v: Option<&Json>) -> Result<Id, Unread> {
    v.and_then(Json::as_str)
        .and_then(|s| b64url_decode(s).ok())
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .map(Id)
        .ok_or(Unread::Malformed)
}

fn uint(v: Option<&Json>) -> Result<u64, Unread> {
    v.and_then(Json::as_int)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Unread::Malformed)
}

fn names(v: Option<&Json>) -> Result<Vec<Untrusted>, Unread> {
    match v {
        Some(Json::Array(items)) => items
            .iter()
            .map(|a| a.as_str().map(Untrusted::new).ok_or(Unread::Malformed))
            .collect(),
        _ => Err(Unread::Malformed),
    }
}

fn holding(h: &Json) -> Result<Holding, Unread> {
    let budgets = match h.get("budgets") {
        Some(Json::Array(items)) => items
            .iter()
            .map(|b| {
                Ok(Budget {
                    dimension: b
                        .get("dimension")
                        .and_then(Json::as_str)
                        .map(Untrusted::new)
                        .ok_or(Unread::Malformed)?,
                    capacity: uint(b.get("capacity"))?,
                    remaining: uint(b.get("remaining"))?,
                })
            })
            .collect::<Result<Vec<_>, Unread>>()?,
        _ => return Err(Unread::Malformed),
    };
    Ok(Holding {
        grant: id(h.get("grant"))?,
        actions: names(h.get("actions"))?,
        until: h.get("until").map(|u| uint(Some(u))).transpose()?,
        budgets,
    })
}

/// Reads the answer: exactly one `agent_status` result, marked advisory.
///
/// # Errors
/// [`Unread`]: no status was read; the agent knows nothing more about itself.
pub fn read(answer: &Answer) -> Result<Status, Unread> {
    let response = match answer {
        Answer::Response(r) => r,
        Answer::Unanswered(f) => return Err(Unread::Unavailable(*f)),
    };
    if response.status != 200 {
        return Err(Unread::Status(response.status));
    }
    let body = json::parse(&response.body, MAX_BODY).map_err(|_| Unread::Malformed)?;
    if !matches!(
        body.get("context").and_then(|c| c.get("advisory")),
        Some(Json::Bool(true))
    ) {
        return Err(Unread::Malformed);
    }
    let Some(Json::Array(results)) = body.get("results") else {
        return Err(Unread::Malformed);
    };
    let [r] = results.as_slice() else {
        return Err(Unread::Malformed);
    };
    if r.get("type").and_then(Json::as_str) != Some("agent_status") {
        return Err(Unread::Malformed);
    }
    let mandate = match r.get("mandate") {
        None => None,
        Some(m) => Some((
            names(m.get("actions"))?,
            m.get("until").map(|u| uint(Some(u))).transpose()?,
        )),
    };
    let holdings = match r.get("holdings") {
        Some(Json::Array(items)) => items.iter().map(holding).collect::<Result<_, _>>()?,
        _ => return Err(Unread::Malformed),
    };
    Ok(Status {
        instance: id(r.get("instance"))?,
        party: id(r.get("party"))?,
        live: matches!(r.get("live"), Some(Json::Bool(true))),
        mandate,
        holdings,
    })
}
