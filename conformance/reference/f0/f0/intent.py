from .algebra import (
    action_covered,
    kind_of,
    party_within,
    purpose_below,
    resource_ref_within,
)
from .codec import same


def value_within(value, bound, catalog):
    # OP-109 m.7
    value_kind = kind_of(value)
    bound_kind = kind_of(bound)
    v = value[value_kind]
    b = bound[bound_kind]
    if bound_kind == "enum" and value_kind == "enum":
        return v in b
    if bound_kind == "eq" and value_kind == "eq":
        return same(v, b)
    if bound_kind == "flag" and value_kind == "flag":
        return v == b
    if bound_kind == "range" and value_kind == "amount":
        if v["unit"] != b["unit"]:
            return False
        if "min" in b and v["value"] < b["min"]:
            return False
        if "max" in b and v["value"] > b["max"]:
            return False
        return True
    if bound_kind == "count_max" and value_kind == "count":
        return v <= b
    if bound_kind == "interval" and value_kind == "interval":
        return b[0] <= v[0] and v[1] <= b[1]
    if bound_kind == "resource" and value_kind == "resource":
        return resource_ref_within(v, b)
    if bound_kind == "subject" and value_kind == "subject":
        return party_within(v, b)
    if bound_kind == "purpose" and value_kind == "purpose":
        return any(purpose_below(v, p, catalog) for p in b)
    return False


def intent_covered(authority, intent, catalog):
    # OP-111 m.2
    if not action_covered(intent["action"], authority["actions"], catalog):
        return False
    for resource in intent["resources"]:
        if not resource_ref_within(resource, authority["resource"]):
            return False
    # OP-107 m.10
    intent_params = intent.get("params", {})
    for name, bound in authority.get("params", {}).items():
        if name not in intent_params or not value_within(intent_params[name], bound, catalog):
            return False
    if "recipient" in authority:
        if "recipient" not in intent or not party_within(intent["recipient"], authority["recipient"]):
            return False
    if "purpose" in authority:
        if "purpose" not in intent:
            return False
        if not any(purpose_below(intent["purpose"], p, catalog) for p in authority["purpose"]):
            return False
    return True
