"""Claims, written from L2-CLM-1 to L2-CLM-3."""

import hashlib

from .codec import Rejection, decode_canonical, encode
from .cose import CoseError, verify_sign1
from .keyscope import thumbprint

CONTENT_TYPE = "application/access-claim+cbor"
SKEW_MS = 60_000
FIELDS = {
    "domain", "issuer", "subject", "class", "value", "issued_at", "validity", "assurance",
    "bound_intent", "bound_instance", "bound_resource", "supersedes",
}
REQUIRED = {"domain", "issuer", "subject", "class", "issued_at", "validity"}


class ClaimError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def claim_id(sign1):
    # L2-CLM-1: the first 16 bytes of the digest under access/claim/v1
    return hashlib.sha256(b"access/claim/v1\x00" + sign1).digest()[:16]


def _uint(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _window(v):
    return isinstance(v, list) and len(v) == 2 and all(_uint(x) for x in v)


def check_statement(value, domain, issuer):
    if not isinstance(value, dict) or not REQUIRED <= set(value) or not set(value) <= FIELDS:
        raise ClaimError("claim-payload")
    if value["domain"] != domain or value["issuer"] != issuer:
        raise ClaimError("claim-payload")
    for name in ("issuer", "subject"):
        if not isinstance(value[name], bytes) or len(value[name]) != 16:
            raise ClaimError("claim-payload")
    if not isinstance(value["class"], str) or not _uint(value["issued_at"]) or not _window(value["validity"]):
        raise ClaimError("claim-payload")
    return value


def verify(sign1, key, issuer, domain):
    kid = thumbprint(key)
    try:
        _, payload = verify_sign1(sign1, CONTENT_TYPE, [-19, -9, -7], {kid: key})
    except CoseError as error:
        raise ClaimError("claim-signature") from error
    try:
        value = decode_canonical(payload)
    except Rejection as error:
        raise ClaimError("claim-payload") from error
    return check_statement(value, domain, issuer)


def _meets(dim, floor, level):
    # OP-118 m.3: for synced the lower level is the stronger one
    return level <= floor if dim == "synced" else level >= floor


def _admits(acceptance, statement, now):
    subject = acceptance["subject"]
    covers_subject = subject == "public" or subject == {"party": statement["subject"]}
    issuer = acceptance["issuer"]
    floor = acceptance.get("assurance_floor", {})
    levels = statement.get("assurance", {})
    lo, hi = acceptance["validity"]
    until = acceptance.get("ingest_until")
    return (
        acceptance["use"] == "predicate-input"
        and isinstance(issuer, bytes)
        and issuer == statement["issuer"]
        and statement["class"] in acceptance["classes"]
        and covers_subject
        and lo <= now <= hi
        and (until is None or now <= until)
        and all(dim in levels and _meets(dim, f, levels[dim]) for dim, f in floor.items())
    )


def disposition(statement, acceptances, now):
    if statement["issued_at"] > now + SKEW_MS:
        return "quarantine:future"
    if any(_admits(a, statement, now) for a in acceptances):
        return "admit"
    return "quarantine:source-not-accepted"
