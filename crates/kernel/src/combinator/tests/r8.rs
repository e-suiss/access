//! R8 adversarial corpus (OP-128): attacks on the authority model, each tied to the rules that
//! stop it and written as a conformance vector both the Kernel and F0 must agree on.

use super::*;

/// What a scenario expects.
pub(super) enum Expect {
    /// The evaluation's outcome.
    Outcome(Outcome),
    /// The evaluation refuses its input.
    Rejected,
    /// Whether the child authority is within the parent.
    Within(bool),
}

/// One scenario: id, attack class, rules, case, expectation, and whether C14 relaxed it.
pub(super) struct Scenario {
    pub id: &'static str,
    pub attack: &'static str,
    pub rules: &'static [&'static str],
    pub case: Cve,
    pub expect: Expect,
    pub relaxed: bool,
}

const ESCALATION: &str = "delegation-escalation";
const CIRCUMVENTION: &str = "attenuation-circumvention";
const TRANSFER: &str = "mandate-or-approval-transfer";
const REPLAY: &str = "stale-version-replay";
const CONFUSION: &str = "actor-or-domain-confusion";

fn evaluate(
    id: &'static str,
    attack: &'static str,
    rules: &'static [&'static str],
    w: World,
    expect: Expect,
) -> Scenario {
    Scenario {
        id,
        attack,
        rules,
        case: Cve::Evaluate(w, Outcome::Deny, None),
        expect,
        relaxed: false,
    }
}

fn delegation(
    id: &'static str,
    rules: &'static [&'static str],
    child: CanonicalAuthority,
    parent: CanonicalAuthority,
) -> Scenario {
    Scenario {
        id,
        attack: ESCALATION,
        rules,
        case: Cve::Delegate {
            child,
            parent,
            holder: SubjectSelector::Party(party(2)),
            within: false,
        },
        expect: Expect::Within(false),
        relaxed: false,
    }
}

fn contribution(instance: u8) -> (RequirementTerm, Proof) {
    let term = RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: "approve".to_string(),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::DistinctParty,
        consumption: Consumption::SingleUse,
        source: None,
        assurance: BTreeMap::new(),
    };
    let proof = Proof {
        id: Id([4; 16]),
        kind: ProofKind::Contribution,
        class: "approve".to_string(),
        position: 1,
        time: 1,
        party: Id([instance; 16]),
        instance: Id([instance; 16]),
        issuer: Id([instance; 16]),
        binding: ProofBinding {
            intent_digest: Some(d(1)),
            ..ProofBinding::default()
        },
        assurance: BTreeMap::new(),
        consumed: false,
    };
    (term, proof)
}

fn escalations() -> Vec<Scenario> {
    let mut out = Vec::new();
    let mut wider = leaf();
    wider.authority.actions.exact.insert(ActionRef {
        name: "capture".to_string(),
        ..action()
    });
    out.push(delegation(
        "escalate-add-action",
        &["L0-ALG-33", "L0-ALG-50", "L0-ALG-71"],
        wider,
        hop().authority,
    ));
    let mut other = leaf();
    other.authority.resource = ResourceSelector::Structural(Structural {
        namespace: "bank".to_string(),
        prefix: vec![],
        kind: None,
        attrs: BTreeMap::new(),
    });
    out.push(delegation(
        "escalate-other-resource",
        &["L0-ALG-41", "L0-ALG-50", "L0-ALG-71"],
        other,
        hop().authority,
    ));
    let mut longer = leaf();
    longer.constraints.validity.until = 200_000;
    out.push(delegation(
        "escalate-longer-validity",
        &["L0-ALG-11", "L0-ALG-72"],
        longer,
        hop().authority,
    ));
    let mut same = hop().authority;
    same.delegation.depth = 1;
    out.push(delegation(
        "escalate-keep-depth",
        &["L0-ALG-58", "L0-ALG-73"],
        same,
        hop().authority,
    ));
    let mut parent = hop().authority;
    parent.requirements.insert(approval(true));
    out.push(delegation(
        "escalate-drop-requirement",
        &["L0-ALG-61", "L0-ALG-76"],
        leaf(),
        parent,
    ));
    out
}

fn circumventions() -> Vec<Scenario> {
    let mut out = Vec::new();
    let mut w = World::new();
    w.hop(1).authority.authority.actions.exact.clear();
    out.push(evaluate(
        "circumvent-narrow-later-hop",
        CIRCUMVENTION,
        &["L0-ALG-52", "L0-EVAL-12"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    w.hop(0).status = HopStatus::Revoked;
    out.push(evaluate(
        "circumvent-revoked-ancestor",
        CIRCUMVENTION,
        &["L0-EVAL-14"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    w.hop(0).conditions_hold = false;
    out.push(evaluate(
        "circumvent-lapsed-ancestor-condition",
        CIRCUMVENTION,
        &["L0-EVAL-4", "L0-EVAL-14"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    w.hop(0).budgets.push(BudgetState {
        window: BudgetWindow::Total,
        remaining: 0,
        demand: 1,
        resets_at: None,
    });
    out.push(evaluate(
        "circumvent-exhausted-ancestor-budget",
        CIRCUMVENTION,
        &["L0-EVAL-15"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    w.restrictions.push(deny_policy(7, true));
    out.push(evaluate(
        "circumvent-restriction-on-covered-path",
        CIRCUMVENTION,
        &["L0-EVAL-18"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    out
}

fn transfers() -> Vec<Scenario> {
    let mut out = Vec::new();
    let mut w = World::new();
    let mut narrow = authority();
    narrow.actions.exact.clear();
    w.mandate = Some(Mandate {
        authority: narrow,
        requirements: BTreeSet::new(),
    });
    out.push(evaluate(
        "mandate-outside-its-limits",
        TRANSFER,
        &["L0-EVAL-16"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    w.hop(1).authority.requirements.insert(approval(true));
    let mut moved = step_up_proof();
    moved.binding.intent_digest = Some(d(2));
    w.proofs.push(moved);
    out.push(evaluate(
        "approval-for-another-intent",
        TRANSFER,
        &["L0-EVAL-22", "L0-EVAL-23"],
        w,
        Expect::Outcome(Outcome::RequireAction),
    ));
    let mut w = World::new();
    w.hop(1).authority.requirements.insert(approval(true));
    let mut spent = step_up_proof();
    spent.consumed = true;
    w.proofs.push(spent);
    out.push(evaluate(
        "approval-replayed-after-use",
        TRANSFER,
        &["L0-EVAL-22", "L0-EVAL-28"],
        w,
        Expect::Outcome(Outcome::RequireAction),
    ));
    let mut w = World::new();
    w.hop(1).authority.requirements.insert(approval(true));
    w.agent = true;
    out.push(evaluate(
        "agent-stands-in-for-human",
        TRANSFER,
        &["L0-EVAL-30"],
        w,
        Expect::Outcome(Outcome::RequireAction),
    ));
    let mut w = World::new();
    let (term, own) = contribution(1);
    w.hop(1).authority.requirements.insert(term);
    w.proofs.push(own);
    out.push(evaluate(
        "actor-approves-own-request",
        TRANSFER,
        &["L0-EVAL-26"],
        w,
        Expect::Outcome(Outcome::RequireAction),
    ));
    out
}

fn replays() -> Vec<Scenario> {
    let mut out = Vec::new();
    let mut w = World::new();
    w.intent.validity.until = 40_000;
    out.push(evaluate(
        "replay-expired-intent",
        REPLAY,
        &["L0-EVAL-5", "L0-EVAL-60"],
        w,
        Expect::Rejected,
    ));
    out.push(evaluate(
        "replay-old-catalog-pin",
        REPLAY,
        &["L0-ALG-31", "L0-EVAL-12"],
        pinned_catalog(20),
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    w.intent.action.schema = d(10);
    out.push(evaluate(
        "replay-other-schema-version",
        REPLAY,
        &["L0-ALG-30", "L0-EVAL-11"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    w.hop(1).authority.constraints.validity.until = 49_999;
    out.push(evaluate(
        "replay-after-hop-expiry",
        REPLAY,
        &["L0-EVAL-13"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    out
}

fn confusions() -> Vec<Scenario> {
    let mut out = Vec::new();
    let mut w = World::new();
    w.capacity = Capacity::For(party(5));
    out.push(evaluate(
        "act-for-unrelated-party",
        CONFUSION,
        &["L0-EVAL-17"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    for h in w.hops_mut() {
        h.authority.authority.recipient = Some(SubjectSelector::Party(party(5)));
    }
    w.intent.recipient = Some(party(6));
    out.push(evaluate(
        "swap-recipient",
        CONFUSION,
        &["L0-ALG-45", "L0-EVAL-10"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    w.intent.resources[0].namespace = "bank".to_string();
    out.push(evaluate(
        "resource-of-another-namespace",
        CONFUSION,
        &["L0-ALG-41", "L0-EVAL-12"],
        w,
        Expect::Outcome(Outcome::Deny),
    ));
    let mut w = World::new();
    w.mandate = Some(Mandate {
        authority: authority(),
        requirements: BTreeSet::new(),
    });
    out.push(Scenario {
        relaxed: true,
        ..evaluate(
            "mandate-snapshot",
            TRANSFER,
            &["L0-EVAL-16"],
            w,
            Expect::Outcome(Outcome::Allow),
        )
    });
    out
}

/// The corpus.
pub(super) fn scenarios() -> Vec<Scenario> {
    let mut out = escalations();
    out.extend(circumventions());
    out.extend(transfers());
    out.extend(replays());
    out.extend(confusions());
    out
}
