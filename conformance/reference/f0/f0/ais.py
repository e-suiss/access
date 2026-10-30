"""The Actor Intent Statement, written from L2-AIS-1 to L2-AIS-4."""

from .codec import Rejection, decode_canonical
from .cose import CoseError, verify_sign1
from .keyscope import thumbprint

CONTENT_TYPE = "application/access-ais+cbor"
SKEW_MS = 60_000
FIELDS = {"domain", "nonce", "intent", "mode", "pep", "capacity", "basis", "iat", "exercise"}
REQUIRED = FIELDS - {"exercise"}
ORDER = ("domain", "nonce", "intent", "mode", "pep", "capacity", "basis", "exercise")


class AisError(Exception):
    def __init__(self, code, field=None):
        super().__init__(code)
        self.code = code
        self.field = field


def is_digest(value):
    return isinstance(value, list) and len(value) == 2 and value[0] == -16 and isinstance(value[1], bytes) and len(value[1]) == 32


def check_statement(value):
    if not isinstance(value, dict) or not REQUIRED <= set(value) or not set(value) <= FIELDS:
        raise AisError("ais-payload")
    nonce, pep = value["nonce"], value["pep"]
    if not isinstance(nonce, bytes) or not 16 <= len(nonce) <= 64:
        raise AisError("ais-payload")
    if not isinstance(pep, str) or not 1 <= len(pep.encode()) <= 255:
        raise AisError("ais-payload")
    if not is_digest(value["domain"]) or not is_digest(value["intent"]):
        raise AisError("ais-payload")
    if value["mode"] not in ("commit", "continue", "check"):
        raise AisError("ais-payload")
    if not isinstance(value["iat"], int) or isinstance(value["iat"], bool) or value["iat"] < 0:
        raise AisError("ais-payload")
    return value


def verify(sign1, key, request, now):
    kid = thumbprint(key)
    try:
        _, payload = verify_sign1(sign1, CONTENT_TYPE, [-19, -9, -7], {kid: key})
    except CoseError as error:
        raise AisError("ais-signature") from error
    try:
        statement = check_statement(decode_canonical(payload))
    except Rejection as error:
        raise AisError("ais-payload") from error
    for name in ORDER:
        if statement.get(name) != request.get(name):
            raise AisError("ais-mismatch", name)
    if statement["iat"] > now + SKEW_MS:
        raise AisError("ais-future")
    return statement
