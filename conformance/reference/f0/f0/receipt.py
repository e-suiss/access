"""Decision receipts (L2-RCP-1, L2-RCP-3), written from the protocol text."""

import hashlib

import cbor2

from .ais import SKEW_MS
from .codec import (
    Rejection,
    check_bool,
    encode,
    check_capacity,
    check_choice,
    check_digest,
    check_id,
    check_list,
    check_map,
    check_uint,
    decode_canonical,
    same,
)
from .cose import CoseError, verify_sign1
from .inclusion import superseded_inclusion
from .keyscope import KeyScopeError, operational_key

CONTENT_TYPE = "application/access-receipt+cbor"
DIGEST_CONTEXT = "access/receipt/v1"


class ReceiptError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


def check_audience(value):
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= 255:
        raise Rejection("shape", "receipt")


def check_holding(value):
    if not isinstance(value, list) or len(value) != 3:
        raise Rejection("shape", "receipt")
    check_id(value[0])
    check_id(value[1])
    check_uint(value[2])


def check_basis(value):
    check_choice(value, {"anchor": check_id, "holding": check_holding, "public": check_id})


def check_agency_link(value):
    # OP-149 m.11
    check_map(value, {"mandate": check_id, "principal": check_id, "agent": check_id})


def check_receipt(value):
    # L2-RCP-1
    check_map(value, {
        "domain": check_digest,
        "exercise": check_digest,
        "record": check_uint,
        "intent": check_digest,
        "capacity": check_capacity,
        "basis": check_basis,
        "audience": check_audience,
        "iat": check_uint,
        "drawn": check_bool,
    }, {"instance": check_id, "ais": check_digest, "agency": check_list(check_agency_link, nonempty=True)})


def decode(payload):
    try:
        value = decode_canonical(payload)
        check_receipt(value)
    except Rejection:
        raise ReceiptError("receipt-malformed")
    return value


def unverified_payload(data):
    try:
        message = cbor2.loads(data)
        payload = message.value[2]
    except Exception:
        raise ReceiptError("receipt-malformed")
    if not isinstance(payload, bytes):
        raise ReceiptError("receipt-malformed")
    return payload


def verify(metadata_bytes, sign1, excerpt, domain, audience, intent, now, evidence=None):
    # L2-RCP-3
    unverified = unverified_payload(sign1)
    claimed = decode(unverified)
    check = None
    if evidence is not None:
        # OP-159 m.17 (a)
        own = hashlib.sha256(DIGEST_CONTEXT.encode("utf-8") + b"\x00" + encode(claimed)).digest()
        if own != evidence["artefact"]:
            raise ReceiptError("receipt-key")
        check = lambda binding: superseded_inclusion(binding, evidence)
    try:
        key = operational_key(metadata_bytes, encode(claimed["domain"]), excerpt, "receipt", claimed["iat"], evidence=check)
    except KeyScopeError:
        raise ReceiptError("receipt-key")
    try:
        _, payload = verify_sign1(sign1, CONTENT_TYPE, [key["alg"]], {key["kid"]: key["key"]})
    except CoseError:
        raise ReceiptError("receipt-signature")
    receipt = decode(payload)
    metadata = decode_canonical(metadata_bytes)
    if not same(receipt["domain"], domain) or not same(metadata["domain"], domain):
        raise ReceiptError("receipt-domain")
    if receipt["audience"] != audience:
        raise ReceiptError("receipt-audience")
    if not same(receipt["intent"], intent):
        raise ReceiptError("receipt-intent")
    if receipt["iat"] > now + SKEW_MS:
        raise ReceiptError("receipt-future")
    return payload
