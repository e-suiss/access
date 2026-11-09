//! An ADP answer as the agent reads it (§8.18.1, §9.5, §9.6, P15): the outcome, every blocker
//! class with its typed remediation, and every unmet requirement with whether the actor itself
//! can meet it. Anything else is not read: free text, subcodes and labels stay data (A-7).
//!
//! Where an unmet term is routed is read from the term itself (§8.18.3): a term the actor cannot
//! meet goes to the principal, as an approval when it takes a contribution and as "This must be
//! done by you" when it does not; it is never an OAuth `interaction_required` (AGI-4, §9.9.5
//! rule 1).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::combinator::BlockerClass;
use access_kernel::digest::Digest;
use access_kernel::json::{self, Json, b64url_decode};

use super::text::Untrusted;
use crate::authorize::MAX_BODY;
use crate::reason;
use crate::transport::{Answer, Fault};

/// The closed remediation set (§8.18.1, §9.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Remediation {
    /// A person has to contribute or widen authority, through the coordinator.
    RouteToCoordinator,
    /// A fresh Claim from its issuer.
    RefreshClaim,
    /// The actor Instance can authenticate itself.
    SelfAuthenticate,
    /// Nothing until this time (a budget window, a time-lock).
    WaitUntil(u64),
    /// The actor cannot meet it (human presence, AGI-4).
    NotSatisfiableByActor,
    /// Only a new request can change the outcome.
    NewRequestRequired,
}

impl Remediation {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RouteToCoordinator => "route-to-coordinator",
            Self::RefreshClaim => "refresh-claim",
            Self::SelfAuthenticate => "self-authenticate",
            Self::WaitUntil(_) => "wait-until",
            Self::NotSatisfiableByActor => "not-satisfiable-by-actor",
            Self::NewRequestRequired => "new-request-required",
        }
    }

    fn parse(v: &Json) -> Option<Self> {
        match v {
            Json::Str(s) => match s.as_str() {
                "route-to-coordinator" => Some(Self::RouteToCoordinator),
                "refresh-claim" => Some(Self::RefreshClaim),
                "self-authenticate" => Some(Self::SelfAuthenticate),
                "not-satisfiable-by-actor" => Some(Self::NotSatisfiableByActor),
                "new-request-required" => Some(Self::NewRequestRequired),
                _ => None,
            },
            Json::Object(m) => match m.as_slice() {
                [(k, Json::Int(t))] if k == "wait_until" => {
                    u64::try_from(*t).ok().map(Self::WaitUntil)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

/// One blocker: its class, always known, its remediation when the SDK knows it, and the lineage
/// hop it sits at when the requester may see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blocker {
    /// The class (§9.6).
    pub class: BlockerClass,
    /// The remediation; `None` when the code is unknown to this SDK.
    pub remediation: Option<Remediation>,
    /// The lineage hop.
    pub hop: Option<u64>,
}

/// What an unmet term asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TermKind {
    /// A Claim.
    Claim,
    /// An authentication.
    Authentication,
    /// A contribution from an eligible Party.
    Contribution,
    /// A foreign authority.
    ForeignAuthority,
}

impl TermKind {
    /// The wire word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Authentication => "authentication",
            Self::Contribution => "contribution",
            Self::ForeignAuthority => "foreign_authority",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "claim" => Some(Self::Claim),
            "authentication" => Some(Self::Authentication),
            "contribution" => Some(Self::Contribution),
            "foreign_authority" => Some(Self::ForeignAuthority),
            _ => None,
        }
    }
}

/// Where the agent sends an unmet requirement (§8.17.5.2, §8.18.3, §8.18.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Route {
    /// The coordinator, for a contribution or a widening a person gives.
    Coordinator,
    /// The principal's own approval: the actor cannot meet it and it takes a contribution.
    PrincipalApproval,
    /// "This must be done by you": the actor cannot meet it and it takes no contribution.
    PrincipalOwnAction,
    /// The actor Instance authenticates itself.
    SelfAuthenticate,
    /// The Claim's issuer.
    Issuer,
    /// Wait until this time.
    WaitUntil(u64),
    /// A new request.
    NewRequest,
}

impl Route {
    /// The route's name in the agent vectors.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::PrincipalApproval => "principal-approval",
            Self::PrincipalOwnAction => "principal-own-action",
            Self::SelfAuthenticate => "self-authenticate",
            Self::Issuer => "issuer",
            Self::WaitUntil(_) => "wait-until",
            Self::NewRequest => "new-request",
        }
    }

    /// The remediation code this route answers.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::Coordinator => "route-to-coordinator",
            Self::PrincipalApproval | Self::PrincipalOwnAction => "not-satisfiable-by-actor",
            Self::SelfAuthenticate => "self-authenticate",
            Self::Issuer => "refresh-claim",
            Self::WaitUntil(_) => "wait-until",
            Self::NewRequest => "new-request-required",
        }
    }

    /// Whether a person has to act.
    #[must_use]
    pub const fn needs_a_person(self) -> bool {
        matches!(
            self,
            Self::Coordinator | Self::PrincipalApproval | Self::PrincipalOwnAction
        )
    }
}

/// One unmet requirement term (§8.18.1 "Unmet requirements").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unmet {
    /// What it asks for.
    pub kind: TermKind,
    /// Its class, a namespaced identifier kept as data.
    pub class: Untrusted,
    /// How many proofs are still missing.
    pub missing: u64,
    /// Whether the actor itself can meet it.
    pub satisfiable_by_actor: bool,
    /// What a proof must be bound to.
    pub binding: Untrusted,
    /// The assurance floors a proof must reach, a screen surface included (E49).
    pub floors: BTreeMap<String, u64>,
}

impl Unmet {
    /// Where this term goes (§8.18.3): the principal when the actor cannot meet it, otherwise by
    /// what it asks for.
    #[must_use]
    pub const fn route(&self) -> Route {
        match (self.satisfiable_by_actor, self.kind) {
            (false, TermKind::Contribution) => Route::PrincipalApproval,
            (false, _) => Route::PrincipalOwnAction,
            (true, TermKind::Contribution | TermKind::ForeignAuthority) => Route::Coordinator,
            (true, TermKind::Authentication) => Route::SelfAuthenticate,
            (true, TermKind::Claim) => Route::Issuer,
        }
    }
}

/// The outcome Access decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// ALLOW, with the Exercise when Access named it.
    Allow {
        /// The Exercise.
        exercise: Option<Digest>,
    },
    /// DENY with every blocker (§8.18.1: the whole set).
    Deny {
        /// The blockers.
        blockers: Vec<Blocker>,
    },
    /// `REQUIRE_ACTION`: unmet terms, and blockers that only wait (a time-lock).
    RequireAction {
        /// The unmet terms.
        unmet: Vec<Unmet>,
        /// The waiting blockers.
        blockers: Vec<Blocker>,
    },
}

impl Decision {
    /// The routes of a `REQUIRE_ACTION`, one per term or waiting blocker, without repeats.
    #[must_use]
    pub fn routes(&self) -> Vec<Route> {
        let Self::RequireAction { unmet, blockers } = self else {
            return Vec::new();
        };
        let mut out: Vec<Route> = unmet.iter().map(Unmet::route).collect();
        out.extend(blockers.iter().map(|b| match b.remediation {
            Some(Remediation::WaitUntil(t)) => Route::WaitUntil(t),
            Some(Remediation::RefreshClaim) => Route::Issuer,
            Some(Remediation::SelfAuthenticate) => Route::SelfAuthenticate,
            Some(Remediation::NotSatisfiableByActor) => Route::PrincipalOwnAction,
            Some(Remediation::NewRequestRequired) => Route::NewRequest,
            Some(Remediation::RouteToCoordinator) | None => Route::Coordinator,
        }));
        out.sort();
        out.dedup();
        out
    }
}

/// An answer the agent read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answered {
    /// The decision.
    pub decision: Decision,
    /// Whether Access marked it advisory (`check`, §9.7).
    pub advisory: bool,
}

/// Why no decision was read: the agent then has nothing and does nothing (fail closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Unread {
    /// No response.
    #[error("unavailable: {0}")]
    Unavailable(Fault),
    /// A status other than 200.
    #[error("status: {0}")]
    Status(u16),
    /// Not a decision body.
    #[error("malformed")]
    Malformed,
    /// A blocker class outside the closed set (P15).
    #[error("unknown-class")]
    UnknownClass,
}

fn blocker(b: &Json) -> Result<Blocker, Unread> {
    let class_text = b
        .get("class")
        .and_then(Json::as_str)
        .ok_or(Unread::Malformed)?;
    let class = reason::class(class_text).ok_or(Unread::UnknownClass)?;
    let hop = b
        .get("position")
        .and_then(|p| p.get("hop"))
        .and_then(Json::as_int)
        .and_then(|h| u64::try_from(h).ok());
    Ok(Blocker {
        class,
        remediation: b.get("remediation").and_then(Remediation::parse),
        hop,
    })
}

fn unmet(u: &Json) -> Result<Unmet, Unread> {
    let term = u.get("term").ok_or(Unread::Malformed)?;
    let kind = term
        .get("proof_kind")
        .and_then(Json::as_str)
        .and_then(TermKind::parse)
        .ok_or(Unread::Malformed)?;
    let class = term
        .get("class")
        .and_then(Json::as_str)
        .ok_or(Unread::Malformed)?;
    let binding = term.get("binding").and_then(Json::as_str).unwrap_or("none");
    let mut floors = BTreeMap::new();
    match term.get("assurance") {
        None => {}
        Some(Json::Object(m)) => {
            for (dim, level) in m {
                let level = level
                    .as_int()
                    .and_then(|l| u64::try_from(l).ok())
                    .ok_or(Unread::Malformed)?;
                floors.insert(dim.clone(), level);
            }
        }
        Some(_) => return Err(Unread::Malformed),
    }
    let missing = u
        .get("missing")
        .and_then(Json::as_int)
        .and_then(|m| u64::try_from(m).ok())
        .filter(|m| *m > 0)
        .ok_or(Unread::Malformed)?;
    let Some(Json::Bool(satisfiable_by_actor)) = u.get("satisfiable_by_actor") else {
        return Err(Unread::Malformed);
    };
    Ok(Unmet {
        kind,
        class: Untrusted::new(class),
        missing,
        satisfiable_by_actor: *satisfiable_by_actor,
        binding: Untrusted::new(binding),
        floors,
    })
}

fn list<T>(
    context: &Json,
    name: &str,
    each: fn(&Json) -> Result<T, Unread>,
) -> Result<Vec<T>, Unread> {
    match context.get(name) {
        None => Ok(Vec::new()),
        Some(Json::Array(items)) => items.iter().map(each).collect(),
        Some(_) => Err(Unread::Malformed),
    }
}

/// Reads one ADP answer (L1-ADP-10, §9.5 R2): 200, a `decision` that agrees with
/// `context.outcome`, closed blocker classes and well-formed unmet terms.
///
/// # Errors
/// [`Unread`].
pub fn read(answer: &Answer) -> Result<Answered, Unread> {
    let response = match answer {
        Answer::Response(r) => r,
        Answer::Unanswered(f) => return Err(Unread::Unavailable(*f)),
    };
    if response.status != 200 {
        return Err(Unread::Status(response.status));
    }
    let body = json::parse(&response.body, MAX_BODY).map_err(|_| Unread::Malformed)?;
    let Some(Json::Bool(allowed)) = body.get("decision") else {
        return Err(Unread::Malformed);
    };
    let Some(context @ Json::Object(_)) = body.get("context") else {
        return Err(Unread::Malformed);
    };
    let advisory = matches!(context.get("advisory"), Some(Json::Bool(true)));
    let blockers = list(context, "blockers", blocker)?;
    let unmet = list(context, "unmet", unmet)?;
    let decision = match (context.get("outcome").and_then(Json::as_str), *allowed) {
        (Some("allow"), true) if blockers.is_empty() && unmet.is_empty() => Decision::Allow {
            exercise: context
                .get("exercise")
                .and_then(Json::as_str)
                .and_then(|e| b64url_decode(e).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .map(Digest),
        },
        (Some("deny"), false) => Decision::Deny { blockers },
        (Some("require_action"), false) if !unmet.is_empty() || !blockers.is_empty() => {
            Decision::RequireAction { unmet, blockers }
        }
        _ => return Err(Unread::Malformed),
    };
    Ok(Answered { decision, advisory })
}
