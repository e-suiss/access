"""Approval Act Statements, written from L2-AAS-1 to L2-AAS-4."""

import hashlib

from .ais import SKEW_MS
from .codec import (
    Rejection,
    check_capacity,
    check_digest,
    check_id,
    check_ident,
    check_list,
    check_map,
    check_tstr,
    check_uint,
    decode_canonical,
    encode,
    fail,
)
from .cose import CoseError, verify_sign1
from .keyscope import thumbprint

CONTENT_TYPE = "application/access-aas+cbor"
CONTEXT = b"access/aas/v1"


class AasError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def check_exercise_ref(value):
    if not isinstance(value, list) or len(value) != 2:
        fail("exercise_ref")
    check_digest(value[0])
    if not isinstance(value[1], bytes) or not 16 <= len(value[1]) <= 64:
        fail("nonce")


def check_surface(value):
    def profile(v):
        check_tstr(v)
        if not 1 <= len(v.encode("utf-8")) <= 255:
            fail("profile")
    check_map(value, {"profile": profile, "version": check_uint})


def check_statement(value):
    # L2-AAS-1, E32
    check_map(value, {
        "act": check_tstr,
        "approver": lambda v: check_map(v, {"instance": check_id, "party": check_id}),
        "capacity": check_capacity,
        "target": check_digest,
        "exercise_ref": check_exercise_ref,
        "surface": check_surface,
        "render_digest": check_digest,
        "material_fields": check_list(check_ident, is_set=True),
        "issued_at": check_uint,
        "expires_at": check_uint,
    }, {
        "contribution_class": check_ident,
        "work_gate": lambda v: check_map(v, {"gate": check_digest, "declaration": check_digest}),
    })
    if value["act"] == "contribution":
        if "contribution_class" not in value:
            fail("a contribution names its class")
    elif value["act"] == "authority-act":
        if "contribution_class" in value:
            fail("an authority act has no class")
    else:
        fail("unknown act")


def verify(sign1, key, domain, target, instance, render_digest, now):
    # L2-AAS-2
    try:
        _, payload = verify_sign1(sign1, CONTENT_TYPE, [-19, -9, -7], {thumbprint(key): key})
    except CoseError:
        raise AasError("aas-signature")
    try:
        statement = decode_canonical(payload)
        check_statement(statement)
    except Rejection:
        raise AasError("aas-malformed")
    # L2-AAS-3
    if encode(statement["exercise_ref"][0]) != encode(domain):
        raise AasError("aas-domain")
    if encode(statement["target"]) != encode(target):
        raise AasError("aas-target")
    if statement["approver"]["instance"] != instance:
        raise AasError("aas-approver")
    if encode(statement["render_digest"]) != encode(render_digest):
        raise AasError("aas-render")
    # L2-AAS-4
    if statement["issued_at"] > now + SKEW_MS:
        raise AasError("aas-future")
    if statement["expires_at"] < statement["issued_at"] or now > statement["expires_at"]:
        raise AasError("aas-expired")
    # L2-AAS-1
    return hashlib.sha256(CONTEXT + b"\x00" + payload).digest()
