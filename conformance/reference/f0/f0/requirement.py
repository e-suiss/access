from itertools import combinations

from .algebra import party_within
from .codec import encode, same


SOURCE_NOT_ACCEPTED = {
    "class": "source-not-accepted",
    "position": "actor-side",
    "resolver": "issuer",
    "remediation": "refresh-claim",
}


def binding_holds(term, proof, evaluation):
    # OP-111 m.4
    binding = term.get("binding")
    if binding is None:
        return True
    if binding == "actor_instance":
        return "actor_instance" in evaluation and proof.get("bound_instance") == evaluation["actor_instance"]
    if binding == "intent_digest":
        return "bound_intent" in proof and same(proof["bound_intent"], evaluation["intent_digest"])
    if binding == "resource":
        return "bound_resource" in proof and any(
            same(proof["bound_resource"], resource) for resource in evaluation["intent"]["resources"]
        )
    return False


def fresh_enough(term, proof, now):
    # OP-111 m.4
    if proof["time"] > now:
        return False
    if "freshness_ms" in term and now - proof["time"] > term["freshness_ms"]:
        return False
    return True


def assurance_holds(term, proof):
    # OP-111 m.4, OP-107 m.21
    offered = proof.get("assurance", {})
    for dimension, floor in term.get("assurance", {}).items():
        if dimension not in offered:
            return False
        # OP-118 m.3
        if dimension == "synced":
            if offered[dimension] > floor:
                return False
        elif offered[dimension] < floor:
            return False
    return True


def source_holds(term, proof):
    # OP-111 m.4
    return "source" not in term or party_within(proof["issuer"], term["source"])


def matches_without_source(term, proof, evaluation):
    # OP-111 m.4
    if proof["kind"] != term["proof_kind"] or proof["class"] != term["class"]:
        return False
    if not binding_holds(term, proof, evaluation):
        return False
    if not fresh_enough(term, proof, evaluation["now"]):
        return False
    if not assurance_holds(term, proof):
        return False
    if term.get("consumption") == "single_use" and proof.get("consumed") is True:
        return False
    return True


def independence_key(term):
    return term.get("independence", {}).get("distinct")


def independent(term, chosen):
    # OP-111 m.4
    key = independence_key(term)
    if key is None:
        return True
    values = [proof[key] for proof in chosen]
    return len(set(values)) == len(values)


def earliest_key(chosen):
    # OP-108 m.9, OP-111 m.5
    ordered = sorted(chosen, key=lambda proof: (proof["position"], proof["id"]))
    positions = [proof["position"] for proof in ordered]
    return (positions[-1], positions, [proof["id"] for proof in ordered])


def largest_independent_size(term, eligible):
    key = independence_key(term)
    if key is None:
        return len(eligible)
    return len({proof[key] for proof in eligible})


def satisfiable_by_actor(term, evaluation):
    # OP-111 m.4
    needs_human = term.get("assurance", {}).get("human_presence", 0) > 0
    return not (needs_human and evaluation.get("actor_is_agent") is True)


def canonical_order(entries):
    # OP-111 m.5
    return sorted(entries, key=lambda entry: (encode(entry[0]), encode(entry[1])))


def resolve(entries, evaluation, fuel):
    pool = sorted(evaluation.get("proofs", []), key=lambda proof: proof["id"])
    unmet = []
    relied = []
    blockers = []
    for term, position in canonical_order(entries):
        eligible = []
        source_rejected = False
        for proof in pool:
            # OP-111 m.7
            fuel.spend()
            if not matches_without_source(term, proof, evaluation):
                continue
            if source_holds(term, proof):
                eligible.append(proof)
            else:
                source_rejected = True
        need = term.get("count", 1)
        candidates = [
            list(chosen) for chosen in combinations(eligible, need) if independent(term, chosen)
        ]
        if candidates:
            # OP-108 m.9
            chosen = min(candidates, key=earliest_key)
            relied.extend(proof["id"] for proof in chosen)
            # OP-111 m.3, m.5
            if term.get("consumption") == "single_use":
                chosen_ids = {proof["id"] for proof in chosen}
                pool = [proof for proof in pool if proof["id"] not in chosen_ids]
            continue
        missing = need - min(need, largest_independent_size(term, eligible))
        unmet.append({
            "term": term,
            "missing": missing,
            "position": position,
            "satisfiable_by_actor": satisfiable_by_actor(term, evaluation),
        })
        if source_rejected:
            # OP-111 m.8
            blockers.append(SOURCE_NOT_ACCEPTED)
    return unmet, relied, blockers
