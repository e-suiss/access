"""Portable Authority Proofs (L2-PAP-1, L2-PAP-3), written from the protocol text."""

import hashlib

import cbor2

from .ais import SKEW_MS
from .codec import (
    UINT_MAX,
    Rejection,
    check_authority_set,
    check_capacity,
    check_digest,
    check_id,
    check_intent_envelope,
    check_map,
    check_requirement_list,
    check_uint,
    decode_canonical,
    encode,
    fail,
    same,
)
from .cose import CoseError, verify_sign1
from .digest import intent_digest, tagged_digest
from .intent import intent_covered
from .keyscope import KeyScopeError, check_public_key, operational_key, thumbprint
from .validity import ValidityError, check_validity, check_validity_contract

CONTENT_TYPE = "application/access-pap+cbor"
PRESENTATION_CONTENT_TYPE = "application/access-pap-presentation+cbor"
PAP_CONTEXT = "access/pap/v1"
HOLDER_CONTEXT = "access/holder/v1"


class PapError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


def check_holder(value):
    check_map(value, {"instance": check_id, "key": check_public_key})


def check_pap(value):
    # L2-PAP-1
    check_map(value, {
        "domain": check_digest,
        "projection_exercise": check_digest,
        "holder": check_holder,
        "capacity": check_capacity,
        "bounds": check_authority_set,
        "validity": check_validity_contract,
        "lineage_commitment": check_digest,
        "iat": check_uint,
    }, {"local_requirements": check_requirement_list})


def check_audience(value):
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= 255:
        fail("audience is not 1 to 255 bytes of text")


def check_nonce(value):
    if not isinstance(value, bytes) or not 16 <= len(value) <= 64:
        fail("nonce is not 16 to 64 bytes")


def check_presentation(value):
    check_map(value, {
        "pap": check_digest,
        "intent": check_digest,
        "audience": check_audience,
        "nonce": check_nonce,
        "iat": check_uint,
    })


def pap_digest(sign1):
    # L2-PAP-2: over the signed COSE_Sign1 bytes, not over a re-encoding
    return [-16, hashlib.sha256(PAP_CONTEXT.encode() + b"\x00" + sign1).digest()]


def holder_digest(holder):
    # L2-PAP-1
    return tagged_digest(HOLDER_CONTEXT, holder)


def decode_pap(payload):
    try:
        value = decode_canonical(payload)
        check_pap(value)
    except Rejection:
        raise PapError("pap-malformed")
    return value


def unverified_payload(data):
    try:
        payload = cbor2.loads(data).value[2]
    except Exception:
        raise PapError("pap-malformed")
    if not isinstance(payload, bytes):
        raise PapError("pap-malformed")
    return payload


def presentation_holds(pap, pap_sign1, presentation_sign1, metadata, intent_bytes, audience, nonce, now):
    # L2-PAP-3 step 3: proof of possession by the holder key for this use
    holder_key = pap["holder"]["key"]
    try:
        _, payload = verify_sign1(
            presentation_sign1, PRESENTATION_CONTENT_TYPE, metadata["algorithms"], {thumbprint(holder_key): holder_key}
        )
        presentation = decode_canonical(payload)
        check_presentation(presentation)
    except (CoseError, Rejection):
        return False
    if now + SKEW_MS > UINT_MAX:
        return False
    return (
        same(presentation["pap"], pap_digest(pap_sign1))
        and same(presentation["intent"], intent_digest(intent_bytes))
        and presentation["audience"] == audience
        and presentation["nonce"] == nonce
        and now - SKEW_MS <= presentation["iat"] <= now + SKEW_MS
    )


def demand(unit, intent):
    # L2-PAP-3 step 5: a count term is drawn by one; an amount term by the intent's amounts in its unit
    if unit == "count":
        return 1
    total = 0
    for value in intent.get("params", {}).values():
        if isinstance(value, dict) and "amount" in value and value["amount"]["unit"] == unit:
            if value["amount"]["value"] < 0:
                return None
            total += value["amount"]["value"]
    return total if total <= UINT_MAX else None


def contains(terms, term):
    return any(same(term, t) for t in terms)


def verify(metadata_bytes, pap_sign1, excerpt, presentation_sign1, domain, intent_bytes, audience, nonce, now,
           catalog, satisfied, remaining, fresh, understood, last_refresh, online, skew_ms, horizon_cap_ms):
    # L2-PAP-3 step 1
    claimed = decode_pap(unverified_payload(pap_sign1))
    try:
        key = operational_key(metadata_bytes, encode(claimed["domain"]), excerpt, "pap", claimed["iat"])
    except KeyScopeError:
        raise PapError("pap-key")
    try:
        _, payload = verify_sign1(pap_sign1, CONTENT_TYPE, [key["alg"]], {key["kid"]: key["key"]})
    except CoseError:
        raise PapError("pap-signature")
    pap = decode_pap(payload)
    metadata = decode_canonical(metadata_bytes)
    if not same(pap["domain"], domain) or not same(metadata["domain"], domain):
        raise PapError("pap-domain")
    # L2-PAP-3 step 2, must-understand included
    contract = pap["validity"]
    try:
        check_validity(contract, now, audience, understood, last_refresh, online, skew_ms, pap["iat"], horizon_cap_ms)
    except ValidityError:
        raise PapError("pap-validity")
    if not same(contract["holder"], holder_digest(pap["holder"])):
        raise PapError("pap-holder")
    # L2-PAP-3 step 3
    if not presentation_holds(pap, pap_sign1, presentation_sign1, metadata, intent_bytes, audience, nonce, now):
        raise PapError("pap-presentation")
    # L2-PAP-3 step 4: the PAP's bounds, which the contract also carries
    intent = decode_canonical(intent_bytes)
    check_intent_envelope(intent)
    if not intent_covered(pap["bounds"], intent, catalog) or not intent_covered(contract["bounds"], intent, catalog):
        raise PapError("pap-bounds")
    required = pap.get("local_requirements", []) + contract.get("local_requirements", [])
    if not all(contains(satisfied, term) for term in required):
        raise PapError("pap-requirements")
    # L2-PAP-3 step 5: the verifier's remaining slice, never more than the contract granted
    for entry in contract.get("offline_slice", []):
        kept = next((amount for term, amount in remaining if same(term, entry["budget_term"])), None)
        need = demand(entry["unit"], intent)
        if kept is None or need is None or need > min(kept, entry["amount"]):
            raise PapError("pap-slice")
    # L2-PAP-3 step 6
    if not fresh:
        raise PapError("pap-stale")
    return payload
