"""Claim bodies and unsigned Claims, written from L2-CLB-1 to L2-CLB-3 and L2-CLM-5."""

import hashlib

from .claim import FIELDS, REQUIRED
from .codec import (
    IDENT,
    Rejection,
    check_amount,
    check_bytes,
    check_digest,
    check_id,
    check_ident,
    check_ident_map,
    check_list,
    check_map,
    check_text_in,
    check_time_window,
    check_true,
    check_tstr,
    check_uint,
    check_unit,
    decode_canonical,
    encode,
    fail,
)
from .keyscope import check_horizon_caps, check_spec_versions
from .report import check_report

BODY_CONTEXT = b"access/claim-body/v1"
ACCOUNT_STATUSES = ("active", "locked", "suspended", "deactivated", "tombstone")
BINDING_KINDS = ("person", "organization", "workload", "agent", "legal_representative")
VARIANTS = (
    "online-strict", "bounded-staleness", "revalidate-on-reconnect",
    "checkpointed-offline", "checkpoint-continuation",
)
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1


class BodyError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def check_sized_text(maximum):
    def check(value):
        if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum:
            fail("text size")
    return check


def check_int64(value):
    if isinstance(value, bool) or not isinstance(value, int) or not INT64_MIN <= value <= INT64_MAX:
        fail("expected int")


def check_nonempty_list_of_text(value):
    if not isinstance(value, list) or not value:
        fail("expected a non-empty array")
    for item in value:
        check_tstr(item)


def check_webauthn(value):
    check_map(value, {"aaguid": check_bytes(16), "sign_count": check_uint},
              {"up": check_true, "uv": check_true, "be": check_true, "bs": check_true})


def check_upstream(value):
    check_map(value, {"iss": check_sized_text(2048)}, {"acr": check_tstr, "amr": check_nonempty_list_of_text})


def check_authentication(value):
    # §10.1.2, §10.1.5
    check_map(value, {
        "method": check_text_in("webauthn", "password", "totp", "device-key", "oidc", "saml",
                                "ldap-bind", "kerberos", "x509"),
        "auth_time": check_uint,
    }, {
        "statement": check_digest,
        "evidence": check_digest,
        "webauthn": check_webauthn,
        "upstream": check_upstream,
    })


def check_attestation(value):
    check_map(value, {
        "format": check_sized_text(64),
        "result": check_text_in("verified", "self", "none", "failed"),
    })


def check_authenticator_binding(value):
    # §10.1.3, IDP-2
    check_map(value, {
        "kind": check_text_in("passkey", "device-key", "password", "totp", "x509"),
        "material": check_digest,
    }, {
        "alg": check_int64,
        "attestation": check_attestation,
        "aaguid": check_bytes(16),
        "be": check_true,
        "transports": check_list(check_sized_text(32), nonempty=True, is_set=True),
    })


def check_device_posture(value):
    # §5.9
    check_map(value, {
        "verdict": check_text_in("compliant", "noncompliant", "unknown"),
        "source": check_sized_text(255),
        "observed_at": check_uint,
    }, {"nonce": check_digest, "evidence": check_digest})


def check_verifier_id(value):
    if not isinstance(value, dict) or len(value) != 1:
        fail("verifier")
    check_map(value, {}, {"instance": check_id, "workload": check_sized_text(255)})


def check_variant_map(element):
    def check(value):
        if not isinstance(value, dict) or not value:
            fail("expected a non-empty map")
        for key, item in value.items():
            if key not in VARIANTS:
                fail("unknown variant")
            element(item)
    return check


def check_profile_entry(value):
    check_map(value, {}, {"params": check_ident_map(check_uint)})


def check_slice_max(value):
    check_ident_map(check_amount)(value)
    for unit in value:
        check_unit(unit)


def check_verifier_profile(value):
    # §9.12.1
    check_map(value, {
        "verifier": check_verifier_id,
        "profiles": check_variant_map(check_profile_entry),
        "versions": check_spec_versions,
        "clock": lambda c: check_map(c, {"source_class": check_ident, "skew_ms": check_uint}),
    }, {
        "tamper_evident_counter": check_true,
        "offline_report": check_true,
        "content_position_check": check_true,
        "status_access": check_list(check_tstr, nonempty=True, is_set=True),
        "refresh_interval_ms": check_uint,
        "attestation": check_digest,
        "cap_horizon": check_variant_map(check_horizon_caps),
        "slice_max": check_slice_max,
        "conformance": check_list(check_sized_text(255), nonempty=True, is_set=True),
    })


def check_ack_event(value):
    if not isinstance(value, dict) or len(value) != 1:
        fail("event")
    check_map(value, {}, {"exercise": check_digest, "event": check_sized_text(255)})


def check_authority_state_ack(value):
    # §9.12.3
    check_map(value, {
        "pep": check_sized_text(255),
        "event": check_ack_event,
        "applied_at": check_uint,
        "basis": check_uint,
        "scope": check_list(check_text_in("cache", "decision", "session", "token"), nonempty=True, is_set=True),
    }, {"clock_evidence": check_digest})


def check_party_key_state(value):
    # §10.1.5, §9.13.1
    check_map(value, {
        "sequence": check_uint,
        "keys": check_list(check_digest, nonempty=True, is_set=True),
    }, {"designated": check_ident_map(check_list(check_id, nonempty=True, is_set=True))})


def check_party_recovered(value):
    check_map(value, {"previous": check_digest, "next": check_digest})


def check_identity_binding(value):
    check_map(value, {"evidence": check_digest})


BODIES = {
    "authentication": check_authentication,
    "authenticator_binding": check_authenticator_binding,
    "posture_device": check_device_posture,
    "verifier_profile": check_verifier_profile,
    "offline_exercise_report": check_report,
    "authority_state_ack": check_authority_state_ack,
    "party_key_state": check_party_key_state,
    "party_recovered": check_party_recovered,
}


def _nonneg_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


SCALARS = {
    "account_status": lambda v: isinstance(v, str) and v in ACCOUNT_STATUSES,
    "party_compromise": lambda v: v is None or _nonneg_int(v),
    "party_terminated": _nonneg_int,
    "party_identity_break": lambda v: isinstance(v, str) and IDENT.fullmatch(v) is not None,
    "agent_kind": lambda v: isinstance(v, str) and IDENT.fullmatch(v) is not None,
    "controller_of": lambda v: isinstance(v, bytes) and len(v) == 16,
    "operated_by": lambda v: isinstance(v, bytes) and len(v) == 16,
    "sponsored_by": lambda v: isinstance(v, bytes) and len(v) == 16,
    "org_member": lambda v: isinstance(v, bytes) and len(v) == 16,
}


def body_check_of(name):
    if name.startswith("identity_binding_"):
        if name[len("identity_binding_"):] in BINDING_KINDS:
            return check_identity_binding
        return None
    return BODIES.get(name)


def body_digest(name, body):
    # L2-CLB-1
    return hashlib.sha256(BODY_CONTEXT + b"\x00" + encode([name, body])).digest()


def check(name, value, body_bytes):
    """Returns the body digest when a body was checked, None otherwise (L2-CLB-2, L2-CLB-3)."""
    if name in SCALARS:
        if body_bytes is not None or not SCALARS[name](value):
            raise BodyError("claim-value")
        return None
    shape = body_check_of(name)
    if shape is None:
        return None
    if not isinstance(value, bytes) or len(value) != 32:
        raise BodyError("claim-value")
    if body_bytes is None:
        return None
    try:
        body = decode_canonical(body_bytes)
        shape(body)
    except Rejection:
        raise BodyError("claim-body")
    if body_digest(name, body) != value:
        raise BodyError("claim-body-digest")
    return value


def check_statement_shape(value):
    if not isinstance(value, dict) or not REQUIRED <= set(value) or not set(value) <= FIELDS:
        fail("statement")
    check_digest(value["domain"])
    check_id(value["issuer"])
    check_id(value["subject"])
    check_ident(value["class"])
    check_uint(value["issued_at"])
    check_time_window(value["validity"])


def check_channel(value):
    if not isinstance(value, dict) or len(value) != 1:
        fail("channel")
    check_map(value, {}, {"pep": check_bytes(32), "scim": check_bytes(32)})


def unsigned(data, domain, channel):
    # L2-CLM-5
    try:
        value = decode_canonical(data)
        check_map(value, {"statement": check_statement_shape, "channel": check_channel})
    except Rejection:
        raise BodyError("claim-payload")
    if encode(value["statement"]["domain"]) != encode(domain) or value["channel"] != channel:
        raise BodyError("claim-payload")
    return hashlib.sha256(b"access/claim/v1\x00" + data).digest()[:16]
