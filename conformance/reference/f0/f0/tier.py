"""Consequence tiers (§13.7.1, L0-EVAL-70, L0-EVAL-71, OP-141 m.34, OP-159 m.3 (l), (m))."""

import hashlib

from .codec import check_intent_envelope, decode_canonical, encode
from .meta import decode_payload

THRESHOLD_UNIT = "eur"
CT1_MAX = 100_000
CT2_MAX = 10_000_000
NAMESPACE = "access"
READS = ("read", "audit_export")
PAYEE_CONTEXT = "access/payee/v1"

EXPANSION_CT3 = {
    "anchor_create", "anchor_transfer", "anchor_amend", "anchor_retire", "party_depart",
    "instance_recover", "grant_amend", "acceptance_establish", "acceptance_amend", "policy_set",
    "policy_retire", "domain_handover", "domain_recover", "version_activate",
}


def meta_tier(name, expansion):
    if name in ("contribute", "projection_issue") or not expansion:
        return 1
    return 3 if name in EXPANSION_CT3 else 2


def amount_tier(value, unit):
    if unit != THRESHOLD_UNIT:
        return 2
    if value > CT2_MAX:
        return 3
    return 2 if value > CT1_MAX else 1


def amounts(intent):
    return [p["amount"] for p in intent.get("params", {}).values() if "amount" in p]


def tier_of(intent, payload_name, expansion, schema):
    if payload_name is not None:
        return meta_tier(payload_name, expansion)
    action = intent["action"]
    # L0-EVAL-70
    if action["namespace"] == NAMESPACE and action["name"] in READS:
        return 0 if action["name"] == "read" else 1
    tiers = [amount_tier(a["value"], a["unit"]) for a in amounts(intent)]
    top = max(tiers) if tiers else None
    if schema is not None and schema.get("reserved") is True:
        return 3
    if schema is not None and schema["effect_class"] == "irreversible":
        return max(top if top is not None else 2, 2)
    if schema is not None and schema["effect_class"] == "none":
        return top if top is not None else 0
    return top if top is not None else 1


def payee(intent, payload_name):
    # L0-EVAL-71
    if payload_name is not None or not amounts(intent) or "recipient" not in intent:
        return None
    return hashlib.sha256(PAYEE_CONTEXT.encode() + b"\x00" + encode(intent["recipient"])).digest()


def tier(intent_bytes, payload_bytes, expansion, schema_bytes, payee_seen):
    intent = decode_canonical(intent_bytes)
    check_intent_envelope(intent)
    name = decode_payload(payload_bytes)[0] if payload_bytes is not None else None
    schema = decode_canonical(schema_bytes) if schema_bytes is not None else None
    level = tier_of(intent, name, expansion, schema)
    who = payee(intent, name)
    if who is not None and not payee_seen:
        level = max(level, 2)
    return level, who
