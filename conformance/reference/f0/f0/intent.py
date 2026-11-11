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
        # L0-EVAL-10: a `subject: public` bound is no restriction
        if kind_of(bound) == "subject" and bound["subject"] == "public":
            continue
        if name not in intent_params or not value_within(intent_params[name], bound, catalog):
            return False
    # L0-EVAL-10: a `public` recipient is no restriction
    if "recipient" in authority and authority["recipient"] != "public":
        if "recipient" not in intent or not party_within(intent["recipient"], authority["recipient"]):
            return False
    if "purpose" in authority:
        if "purpose" not in intent:
            return False
        if not any(purpose_below(intent["purpose"], p, catalog) for p in authority["purpose"]):
            return False
    return True


I64_MIN, I64_MAX = -(2 ** 63), 2 ** 63 - 1
U64_MAX = 2 ** 64 - 1


def apply_mapping(mapping, intent):
    # OP-157 m.3 (b), §9.13.4: a pinned, non-broadening mapping turns the new version's intent
    # into the old version's; any operation that does not apply leaves it unmapped
    if not same(mapping["to"], intent["action"]):
        return None
    if mapping["relation"] not in ("representation-equivalent", "narrowing"):
        return None
    params = dict(intent.get("params", {}))
    provenance = dict(intent.get("provenance", {}))
    opaque = dict(intent.get("opaque", {}))
    for op in mapping["ops"]:
        kind = kind_of(op)
        body = op[kind]
        if kind == "rename":
            if body["from"] in params:
                value = params.pop(body["from"])
                if body["to"] in params:
                    return None
                params[body["to"]] = value
                if body["from"] in provenance:
                    provenance[body["to"]] = provenance.pop(body["from"])
        elif kind == "enum":
            if body["field"] in params:
                value = params[body["field"]]
                if kind_of(value) != "enum" or value["enum"] not in body["values"]:
                    return None
                params[body["field"]] = {"enum": body["values"][value["enum"]]}
        elif kind == "constant":
            params[body["field"]] = {"eq": body["value"]}
            provenance.pop(body["field"], None)
        elif kind == "scale":
            if body["field"] in params:
                value = params[body["field"]]
                if kind_of(value) == "amount":
                    scaled = value["amount"]["value"] * body["factor"]
                    if not I64_MIN <= scaled <= I64_MAX:
                        return None
                    params[body["field"]] = {"amount": {"value": scaled, "unit": value["amount"]["unit"]}}
                elif kind_of(value) == "count":
                    scaled = value["count"] * body["factor"]
                    if scaled > U64_MAX:
                        return None
                    params[body["field"]] = {"count": scaled}
                else:
                    return None
        elif kind == "drop":
            if body["field"] in params:
                return None
            opaque.pop(body["field"], None)
    mapped = dict(intent)
    mapped["action"] = mapping["from"]
    mapped["params"] = params
    mapped["provenance"] = provenance
    mapped["opaque"] = opaque
    return mapped


def intent_covered_mapped(authority, intent, catalog, mappings):
    # OP-157 m.3 (b): coverage directly or through a pinned, non-broadening mapping
    if intent_covered(authority, intent, catalog):
        return True
    for mapping in mappings:
        mapped = apply_mapping(mapping, intent)
        if mapped is not None and intent_covered(authority, mapped, catalog):
            return True
    return False
