import base64

from .codec import Rejection, decode_evaluation_input, encode, same
from .fuel import Fuel
from .intent import intent_covered
from .requirement import resolve


def hop_position(k):
    return {"hop": k}


def no_covering_authority(k):
    # OP-111 m.8
    return {
        "class": "no-covering-authority",
        "position": hop_position(k),
        "resolver": {"grantor_of_hop": k},
        "remediation": "route-to-coordinator",
    }


def outside_instance_limits():
    # OP-111 m.8
    return {
        "class": "outside-instance-limits",
        "position": "instance",
        "resolver": "actor-party",
        "remediation": "route-to-coordinator",
    }


def restricted(policy):
    # OP-111 m.8, OP-108 m.7
    reference = base64.urlsafe_b64encode(policy).decode("ascii").rstrip("=")
    return {
        "class": "restricted",
        "subcode": f"restricted/policy:{reference}",
        "position": "domain-policy",
        "resolver": "restriction-owner",
        "remediation": "not-satisfiable-by-actor",
    }


def budget_exhausted(k, state):
    # OP-111 m.8
    if state["window"] == "total":
        return {
            "class": "budget-exhausted",
            "position": hop_position(k),
            "resolver": {"grantor_of_hop": k},
            "remediation": "route-to-coordinator",
        }
    if "resets_at" not in state:
        raise Rejection("input", "rolling budget without resets_at")
    return {
        "class": "budget-exhausted",
        "position": hop_position(k),
        "resolver": "time",
        "remediation": {"wait_until": state["resets_at"]},
    }


def ended(k, subcode):
    # OP-111 m.8
    return {
        "class": "ended",
        "subcode": f"ended/{subcode}",
        "position": hop_position(k),
        "resolver": {"grantor_of_hop": k},
        "remediation": "new-request-required",
    }


def not_yet_valid(k, start):
    # OP-111 m.8
    return {
        "class": "ended",
        "subcode": "ended/expired",
        "position": hop_position(k),
        "resolver": "time",
        "remediation": {"wait_until": start},
    }


def capacity_mismatch():
    # OP-111 m.8
    return {
        "class": "capacity-mismatch",
        "position": hop_position(0),
        "resolver": "actor",
        "remediation": "new-request-required",
    }


def hop_blockers(k, hop, evaluation):
    blockers = []
    authority = hop["authority"]
    # OP-111 m.2
    if not intent_covered(authority["authority"], evaluation["intent"], evaluation["catalog"]):
        blockers.append(no_covering_authority(k))
    start, until = authority["constraints"]["validity"]
    now = evaluation["now"]
    if now < start:
        blockers.append(not_yet_valid(k, start))
    if now > until:
        blockers.append(ended(k, "expired"))
    if hop.get("status") == "revoked":
        blockers.append(ended(k, "revoked"))
    if hop.get("status") == "lapsed" or hop.get("conditions_fail") is True:
        blockers.append(ended(k, "lapsed"))
    for state in hop.get("budgets", []):
        # OP-108 m.2
        if state["demand"] > state["remaining"]:
            blockers.append(budget_exhausted(k, state))
    return blockers


def restriction_results(evaluation, fuel):
    blockers = []
    requirements = []
    for result in evaluation.get("restrictions", []):
        # OP-111 m.7
        fuel.spend()
        outcome = result["outcome"]
        if outcome == "no_objection":
            continue
        if "deny" in outcome:
            blockers.append(restricted(outcome["deny"]["policy"]))
        else:
            requirements.extend((term, "domain-policy") for term in outcome["require"])
    return blockers, requirements


def evaluate_candidate(basis, evaluation, global_blockers, global_requirements, fuel):
    blockers = list(global_blockers)
    requirements = list(global_requirements)
    if basis is None:
        blockers.append(no_covering_authority(0))
    else:
        for k, hop in enumerate(basis["hops"]):
            # OP-111 m.7
            fuel.spend()
            blockers.extend(hop_blockers(k, hop, evaluation))
            requirements.extend((term, hop_position(k)) for term in hop["authority"]["requirements"])
        # OP-111 m.8
        if not any(same(capacity, evaluation["capacity"]) for capacity in basis["capacities"]):
            blockers.append(capacity_mismatch())
    # OP-111 m.3, m.4, m.5
    unmet, relied, requirement_blockers = resolve(requirements, evaluation, fuel)
    blockers.extend(requirement_blockers)
    return blockers, unmet, relied


def blocker_order(blocker):
    # OP-108 m.5
    return (blocker["class"].encode("utf-8"), encode(blocker))


def as_set(items, key=encode):
    by_encoding = {}
    for item in items:
        by_encoding[encode(item)] = item
    return sorted(by_encoding.values(), key=key)


def make_decision(blockers, unmet, relied):
    # OP-111 m.8
    decision = {}
    if blockers:
        decision["outcome"] = "deny"
    elif unmet:
        decision["outcome"] = "require_action"
    else:
        decision["outcome"] = "allow"
    if blockers:
        decision["blockers"] = as_set(blockers, key=blocker_order)
    if unmet:
        decision["unmet"] = as_set(unmet)
    if decision["outcome"] == "allow" and relied:
        decision["relied_on"] = as_set(relied)
    return decision


def evaluate(evaluation, fuel_budget):
    fuel = Fuel(fuel_budget)
    mode = evaluation["mode"]
    bases = evaluation["bases"]
    if mode in ("commit", "continue") and len(bases) != 1:
        # OP-111 m.6
        raise Rejection("input", f"{mode} needs exactly one declared basis")
    global_blockers, global_requirements = restriction_results(evaluation, fuel)
    if "mandate" in evaluation:
        mandate = evaluation["mandate"]
        # OP-111 m.2
        if not intent_covered(mandate["authority"], evaluation["intent"], evaluation["catalog"]):
            global_blockers.append(outside_instance_limits())
        global_requirements.extend((term, "instance") for term in mandate.get("requirements", []))
    if mode in ("commit", "continue"):
        # OP-111 m.6
        return make_decision(*evaluate_candidate(bases[0], evaluation, global_blockers, global_requirements, fuel))
    candidates = bases if bases else [None]
    decisions = []
    for basis in candidates:
        blockers, unmet, relied = evaluate_candidate(basis, evaluation, global_blockers, global_requirements, fuel)
        decisions.append((blockers, unmet, relied))
    # OP-111 m.6
    for blockers, unmet, relied in decisions:
        if not blockers and not unmet:
            return make_decision(blockers, unmet, relied)
    for blockers, unmet, relied in decisions:
        if not blockers:
            return make_decision(blockers, unmet, relied)
    all_blockers = [blocker for blockers, _, _ in decisions for blocker in blockers]
    all_unmet = [term for _, unmet, _ in decisions for term in unmet]
    return make_decision(all_blockers, all_unmet, [])


def evaluate_bytes(data, fuel_budget):
    evaluation = decode_evaluation_input(data)
    return encode(evaluate(evaluation, fuel_budget))
