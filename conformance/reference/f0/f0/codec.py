import re

import cbor2

from . import dcbor


MAX_SELECTOR_CONDITIONS = 32
MAX_HOPS = 16

UINT_MAX = 2**64 - 1
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
HASH_ALG_SHA256 = -16

IDENT = re.compile(r"[a-z][a-z0-9_]{0,62}")
NAMESPACE = re.compile(r"[a-z][a-z0-9_-]{0,62}(\.[a-z][a-z0-9_-]{0,62}){0,7}")
UNIT = re.compile(r"[a-z][a-z0-9_]{0,15}")


class Rejection(Exception):
    def __init__(self, kind, reason):
        super().__init__(f"{kind}: {reason}")
        self.kind = kind
        self.reason = reason


def fail(reason):
    raise Rejection("input", reason)


def encode(value):
    # OP-106 m.1
    return cbor2.dumps(value, canonical=True)


def same(a, b):
    return encode(a) == encode(b)


def decode_canonical(data, int_keys=False):
    if not isinstance(data, bytes):
        fail("not bytes")
    try:
        dcbor.check(data)
    except dcbor.DecodeError as error:
        fail(f"not deterministic CBOR: {error.name}")
    value = cbor2.loads(data)
    check_data_model(value, int_keys)
    # OP-106 m.1
    if encode(value) != data:
        fail("not deterministic CBOR")
    return value


def check_data_model(value, int_keys=False):
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        # OP-106 m.3
        if value < -(2**64) or value > UINT_MAX:
            fail("integer out of range")
        return
    if isinstance(value, (bytes, str)):
        return
    if isinstance(value, list):
        for item in value:
            check_data_model(item, int_keys)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            # OP-106 m.4
            if not isinstance(key, str) and not (int_keys and type(key) is int):
                fail("map key is not text")
            check_data_model(item, int_keys)
        return
    # OP-106 m.2, m.3, m.4
    fail(f"value type not allowed: {type(value).__name__}")


def check_map(value, required, optional=None):
    optional = optional or {}
    if not isinstance(value, dict):
        fail("expected a map")
    for key in value:
        if key not in required and key not in optional:
            # OP-108 m.4
            fail(f"unknown field {key!r}")
    for key, check in required.items():
        if key not in value:
            fail(f"missing field {key!r}")
        check(value[key])
    for key, check in optional.items():
        if key in value:
            check(value[key])


def check_choice(value, choices, texts=()):
    if isinstance(value, str):
        if value in texts:
            return
        fail(f"unexpected text {value!r}")
    if not isinstance(value, dict) or len(value) != 1:
        fail("expected a single-key map")
    key = next(iter(value))
    if key not in choices:
        # OP-108 m.4
        fail(f"unknown choice {key!r}")
    choices[key](value[key])


def check_text_in(*allowed):
    def check(value):
        if not isinstance(value, str) or value not in allowed:
            fail(f"expected one of {allowed}")
    return check


def check_true(value):
    if value is not True:
        fail("expected true")


def check_bool(value):
    if not isinstance(value, bool):
        fail("expected bool")


def check_uint(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT_MAX:
        fail("expected uint")


def check_uint_at_least(minimum):
    def check(value):
        check_uint(value)
        if value < minimum:
            fail(f"expected uint >= {minimum}")
    return check


def check_amount(value):
    # OP-109 m.8
    if isinstance(value, bool) or not isinstance(value, int) or not INT64_MIN <= value <= INT64_MAX:
        fail("expected int64")


def check_bytes(size=None):
    def check(value):
        if not isinstance(value, bytes):
            fail("expected bytes")
        if size is not None and len(value) != size:
            fail(f"expected {size} bytes")
    return check


def check_text_pattern(pattern):
    def check(value):
        if not isinstance(value, str) or not pattern.fullmatch(value):
            fail(f"text does not match {pattern.pattern}")
    return check


check_ident = check_text_pattern(IDENT)
check_namespace = check_text_pattern(NAMESPACE)
check_unit = check_text_pattern(UNIT)
check_id = check_bytes(16)


def check_tstr(value):
    if not isinstance(value, str):
        fail("expected text")


def check_path_segment(value):
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 128:
        fail("bad path segment")


def check_list(element, nonempty=False, is_set=False):
    def check(value):
        if not isinstance(value, list):
            fail("expected an array")
        if nonempty and not value:
            fail("expected a non-empty array")
        for item in value:
            element(item)
        if is_set:
            # OP-110 m.1
            encodings = [encode(item) for item in value]
            for left, right in zip(encodings, encodings[1:]):
                if not left < right:
                    fail("set is not sorted or has repeats")
    return check


def check_ident_map(element):
    def check(value):
        if not isinstance(value, dict) or not value:
            fail("expected a non-empty map")
        for key, item in value.items():
            check_ident(key)
            element(item)
    return check


def check_digest(value):
    # OP-106 m.20
    if not isinstance(value, list) or len(value) != 2:
        fail("expected a digest")
    if value[0] != HASH_ALG_SHA256 or isinstance(value[0], bool):
        fail("unknown hash algorithm")
    check_bytes(32)(value[1])


def check_time_window(value):
    if not isinstance(value, list) or len(value) != 2:
        fail("expected a time window")
    check_uint(value[0])
    check_uint(value[1])
    # OP-109 m.9 interval
    if value[0] > value[1]:
        fail("time window from > until")


def check_equality_value(value):
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, (str, bytes)):
        return
    fail("bad equality value")


def check_action_ref(value):
    check_map(value, {
        "namespace": check_namespace,
        "name": check_ident,
        "major": check_uint,
        "schema": check_digest,
    })


def check_resource_ref(value):
    check_map(value, {
        "namespace": check_namespace,
        "path": check_list(check_path_segment, nonempty=True),
        "incarnation": check_uint,
    })


def check_purpose_ref(value):
    check_choice(value, {"code": check_ident, "work": check_digest, "aim": check_digest})


def check_where(value):
    check_ident_map(check_equality_value)(value)
    # OP-108 m.3
    if len(value) > MAX_SELECTOR_CONDITIONS:
        fail("selector too complex")


def check_resource_selector(value):
    if isinstance(value, dict) and "exact" in value:
        check_map(value, {"exact": check_resource_ref})
        return
    # OP-109 m.2
    check_map(value, {"namespace": check_namespace}, {
        "prefix": check_list(check_path_segment, nonempty=True),
        "type": check_ident,
        "where": check_where,
    })


def check_conjunct(value):
    # OP-109 m.1
    check_map(value, {"claim_class": check_ident}, {"value": check_equality_value})


def check_pred(value):
    check_list(check_conjunct, nonempty=True, is_set=True)(value)
    # OP-108 m.3
    if len(value) > MAX_SELECTOR_CONDITIONS:
        fail("selector too complex")


def check_foreign(value):
    check_map(value, {"domain": check_digest, "authority_class": check_ident})


def check_subject_selector(value):
    check_choice(value, {
        "party": check_id,
        "pred": check_pred,
        "foreign": check_foreign,
    }, texts=("public",))


def check_range_bound(value):
    check_map(value, {"unit": check_unit}, {"min": check_amount, "max": check_amount})


def check_param_bound(value):
    check_choice(value, {
        "enum": check_list(check_tstr, nonempty=True, is_set=True),
        "eq": check_equality_value,
        "range": check_range_bound,
        "count_max": check_uint,
        "interval": check_time_window,
        "resource": check_resource_selector,
        "subject": check_subject_selector,
        "purpose": check_list(check_purpose_ref, nonempty=True, is_set=True),
        "flag": check_bool,
    })


def check_amount_value(value):
    check_map(value, {"value": check_amount, "unit": check_unit})


def check_param_value(value):
    check_choice(value, {
        "enum": check_tstr,
        "eq": check_equality_value,
        "amount": check_amount_value,
        "count": check_uint,
        "interval": check_time_window,
        "resource": check_resource_ref,
        "subject": check_id,
        "purpose": check_purpose_ref,
        "flag": check_bool,
    })


def check_action_prefix(value):
    check_map(value, {"namespace": check_namespace, "catalog": check_digest})


def check_action_set(value):
    check_map(value, {}, {
        "exact": check_list(check_action_ref, nonempty=True, is_set=True),
        "prefix": check_list(check_action_prefix, nonempty=True, is_set=True),
    })


def check_authority_set(value):
    check_map(value, {
        "actions": check_action_set,
        "resource": check_resource_selector,
    }, {
        "params": check_ident_map(check_param_bound),
        "recipient": check_subject_selector,
        "purpose": check_list(check_purpose_ref, nonempty=True, is_set=True),
    })


def check_claim_held(value):
    check_map(value, {
        "class": check_ident,
        "subject": check_subject_selector,
        "acceptance": check_digest,
    })


def check_while_condition(value):
    # OP-107 m.6
    check_choice(value, {"instance_alive": check_id, "claim_held": check_claim_held})


def check_budget_window(value):
    # OP-107 m.7
    check_choice(value, {"rolling_s": check_uint}, texts=("total",))


def check_budget_dimension(value):
    check_choice(value, {"amount": check_unit}, texts=("count",))


def check_budget_term(value):
    check_map(value, {
        "dimension": check_budget_dimension,
        "capacity": check_uint,
        "window": check_budget_window,
    })


def check_constraint_set(value):
    check_map(value, {"validity": check_time_window}, {
        "while": check_list(check_while_condition, nonempty=True, is_set=True),
        "budget": check_list(check_budget_term, nonempty=True, is_set=True),
    })


def check_delegation_terms(value):
    # OP-109 m.4, OP-107 m.16
    check_map(value, {}, {
        "depth": check_uint_at_least(1),
        "downstream_holder_class": check_subject_selector,
    })


PROOF_KINDS = ("claim", "contribution", "authentication", "foreign_authority")


def check_independence(value):
    check_map(value, {"distinct": check_text_in("party", "instance", "issuer")})


# OP-118 m.3
ASSURANCE_LEVELS = {
    "aal": (1, 3),
    "loa_eidas": (1, 3),
    "phishing_resistant": (0, 1),
    "hardware_bound": (0, 1),
    "non_custodial": (0, 1),
    "uv": (0, 1),
    "human_presence": (0, 1),
    "app_controlled_factor": (0, 1),
    "synced": (0, 1),
}


def check_assurance_level(dimension, level):
    check_uint(level)
    # OP-118 m.3
    if dimension not in ASSURANCE_LEVELS:
        fail(f"unknown assurance dimension {dimension!r}")
    low, high = ASSURANCE_LEVELS[dimension]
    if not low <= level <= high:
        fail(f"assurance {dimension} out of range")


def check_assurance(value):
    check_ident_map(check_uint)(value)
    for dimension, level in value.items():
        check_assurance_level(dimension, level)


def check_requirement_term(value):
    # OP-109 m.3
    check_map(value, {
        "proof_kind": check_text_in(*PROOF_KINDS),
        "class": check_ident,
    }, {
        "count": check_uint_at_least(2),
        "binding": check_text_in("actor_instance", "intent_digest", "resource"),
        "freshness_ms": check_uint,
        "independence": check_independence,
        "consumption": check_text_in("single_use"),
        "source": check_subject_selector,
        "assurance": check_assurance,
    })


check_requirement_set = check_list(check_requirement_term, is_set=True)
check_requirement_list = check_list(check_requirement_term, nonempty=True, is_set=True)


def check_canonical_authority(value):
    check_map(value, {
        "authority": check_authority_set,
        "constraints": check_constraint_set,
        "delegation": check_delegation_terms,
        "requirements": check_requirement_set,
    })


def check_intent_context(value):
    check_map(value, {}, {
        "work": check_digest,
        "commitment": check_digest,
        "step": check_digest,
        "upstream_exercise": check_digest,
    })


def check_intent_envelope(value):
    check_map(value, {
        "action": check_action_ref,
        "resources": check_list(check_resource_ref, nonempty=True, is_set=True),
        "validity": check_time_window,
    }, {
        "params": check_ident_map(check_param_value),
        "opaque": check_ident_map(check_digest),
        "recipient": check_id,
        "purpose": check_purpose_ref,
        "context": check_intent_context,
    })


def check_restriction_deny(value):
    check_map(value, {"policy": check_id, "policy_version": check_digest}, {"undisclosed": check_true})


def check_restriction_outcome(value):
    check_choice(value, {
        "deny": check_restriction_deny,
        "require": check_requirement_list,
    }, texts=("no_objection",))


def check_policy_result(value):
    check_map(value, {
        "policy": check_id,
        "version": check_digest,
        "outcome": check_restriction_outcome,
    })
    deny = value["outcome"].get("deny") if isinstance(value["outcome"], dict) else None
    if deny is not None:
        if deny["policy"] != value["policy"] or not same(deny["policy_version"], value["version"]):
            fail("restriction deny names another policy")


def check_capacity(value):
    check_choice(value, {"for": check_id}, texts=("own",))


def check_budget_state(value):
    check_map(value, {
        "window": check_budget_window,
        "remaining": check_uint,
        "demand": check_uint,
    }, {"resets_at": check_uint})


def check_hop(value):
    # OP-118 m.2
    if isinstance(value, dict) and "not_understood" in value:
        check_map(value, {"not_understood": check_true})
        return
    check_map(value, {"authority": check_canonical_authority}, {
        "status": check_text_in("revoked", "lapsed"),
        "conditions_fail": check_true,
        "budgets": check_list(check_budget_state, nonempty=True, is_set=True),
    })


def check_basis(value):
    check_map(value, {
        "hops": check_list(check_hop, nonempty=True),
        "capacities": check_list(check_capacity, nonempty=True, is_set=True),
    })
    # OP-108 m.10
    if len(value["hops"]) > MAX_HOPS:
        fail("lineage too deep")


def check_mandate(value):
    check_map(value, {"authority": check_authority_set}, {"requirements": check_requirement_list})


def check_proof(value):
    check_map(value, {
        "id": check_id,
        "kind": check_text_in(*PROOF_KINDS),
        "class": check_ident,
        "position": check_uint,
        "time": check_uint,
        "party": check_id,
        "instance": check_id,
        "issuer": check_id,
    }, {
        "bound_instance": check_id,
        "bound_intent": check_digest,
        "bound_resource": check_resource_ref,
        "assurance": check_assurance,
        "consumed": check_true,
    })


def check_catalog_entry(value):
    check_map(value, {
        "catalog": check_digest,
        "actions": check_list(check_action_ref, nonempty=True, is_set=True),
    })


def check_purpose_entry(value):
    check_map(value, {
        "purpose": check_purpose_ref,
        "below": check_list(check_purpose_ref, nonempty=True, is_set=True),
    })


def check_catalog(value):
    check_map(value, {}, {
        "catalogs": check_list(check_catalog_entry, nonempty=True, is_set=True),
        "reserved": check_list(check_action_ref, nonempty=True, is_set=True),
        "purposes": check_list(check_purpose_entry, nonempty=True, is_set=True),
    })
    catalog_ids = [encode(entry["catalog"]) for entry in value.get("catalogs", [])]
    if len(set(catalog_ids)) != len(catalog_ids):
        fail("catalog listed twice")
    purpose_ids = [encode(entry["purpose"]) for entry in value.get("purposes", [])]
    if len(set(purpose_ids)) != len(purpose_ids):
        fail("purpose listed twice")
    check_purpose_order_acyclic(value.get("purposes", []))


def check_purpose_order_acyclic(entries):
    below = {encode(entry["purpose"]): [encode(item) for item in entry["below"]] for entry in entries}
    state = {}

    def visit(node):
        if state.get(node) == "done":
            return
        if state.get(node) == "active":
            # OP-107 m.15
            fail("purpose order has a cycle")
        state[node] = "active"
        for child in below.get(node, []):
            visit(child)
        state[node] = "done"

    for node in below:
        visit(node)


def check_evaluation_input(value):
    check_map(value, {
        "mode": check_text_in("commit", "continue", "check"),
        "intent": check_intent_envelope,
        "intent_digest": check_digest,
        "now": check_uint,
        "capacity": check_capacity,
        "bases": check_list(check_basis),
        "catalog": check_catalog,
    }, {
        "actor_instance": check_id,
        "actor_is_agent": check_true,
        "mandate": check_mandate,
        "restrictions": check_list(check_policy_result, nonempty=True, is_set=True),
        "proofs": check_list(check_proof, nonempty=True, is_set=True),
    })
    proof_ids = [proof["id"] for proof in value.get("proofs", [])]
    if len(set(proof_ids)) != len(proof_ids):
        fail("proof id listed twice")


def decode_evaluation_input(data):
    value = decode_canonical(data)
    check_evaluation_input(value)
    return value


def decode_canonical_authority(data):
    value = decode_canonical(data)
    check_canonical_authority(value)
    return value


def decode_subject_selector(data):
    value = decode_canonical(data)
    check_subject_selector(value)
    return value
