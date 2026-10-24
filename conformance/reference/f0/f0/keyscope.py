import base64
import hashlib
import json

from .codec import (
    Rejection,
    check_digest,
    check_ident_map,
    check_list,
    check_map,
    check_text_in,
    check_uint,
    check_amount,
    check_bytes,
    check_choice,
    check_unit,
    decode_canonical,
    fail,
    same,
)
from .cose import CoseError, verify_sign1


EXCERPT_CONTENT_TYPE = "application/access-key-excerpt+cbor"
OPERATIONAL_WINDOW_CEILING_MS = 86400000
COSE_ALGS = (-19, -9, -7, -48, -49, -50)
KEY_USAGES = ("receipt", "pap", "token", "checkpoint", "set", "status-list")
ML_DSA_NAMES = {-48: "ML-DSA-44", -49: "ML-DSA-65", -50: "ML-DSA-87"}


class KeyScopeError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


def check_cose_alg(value):
    if type(value) is not int or value not in COSE_ALGS:
        fail("unknown COSE algorithm")


def check_ml_dsa_key(value):
    if not isinstance(value, list) or len(value) != 2:
        fail("bad ML-DSA key")
    check_cose_alg(value[0])
    check_bytes()(value[1])


def check_public_key(value):
    check_choice(value, {
        "ed25519": check_bytes(32),
        "p256": check_bytes(65),
        "ml_dsa": check_ml_dsa_key,
    })


def check_operational_key(value):
    check_map(value, {
        "kid": check_bytes(32),
        "alg": check_cose_alg,
        "key": check_public_key,
        "valid_from": check_uint,
        "valid_until": check_uint,
        "usage": check_list(check_text_in(*KEY_USAGES), nonempty=True, is_set=True),
    })


def check_key_excerpt(value):
    check_map(value, {"domain": check_digest, "key": check_operational_key})


def check_binding_scope(value):
    # CR-58 m.4
    check_choice(value, {"provider": check_list(check_digest, nonempty=True, is_set=True)}, texts=("domain",))


def check_superseded(value):
    check_map(value, {"at": check_digest, "cited": check_digest})


def check_binding_key(value):
    check_map(value, {
        "kid": check_bytes(32),
        "alg": check_cose_alg,
        "key": check_public_key,
        "scope": check_binding_scope,
    }, {"superseded": check_superseded})


def check_spec_versions(value):
    check_map(value, {"core": check_uint, "meta_schema": check_uint}, {
        "profiles": check_ident_map(check_uint),
        "schemas": check_list(check_digest, nonempty=True, is_set=True),
    })


def check_window_max(value):
    check_uint(value)
    # CR-58 m.3
    if value > OPERATIONAL_WINDOW_CEILING_MS:
        fail("operational window above 24 h")


def check_caps(value):
    check_map(value, {}, {
        "horizon_max_ms": check_uint,
        "slice_max": check_ident_map(check_amount),
    })
    for unit in value.get("slice_max", {}):
        check_unit(unit)


def check_domain_metadata(value):
    # CR-58 m.3
    check_map(value, {
        "domain": check_digest,
        "genesis": check_digest,
        "issued_at": check_uint,
        "binding": check_list(check_binding_key, nonempty=True, is_set=True),
        "algorithms": check_list(check_cose_alg, nonempty=True, is_set=True),
        "operational_window_max_ms": check_window_max,
        "operational_keys": check_list(check_operational_key, is_set=True),
        "min_versions": check_spec_versions,
    }, {
        "caps": check_caps,
        "hybrid": check_text_in("classic", "both", "pq"),
        "discovery": check_bytes(),
    })
    kids = [binding["kid"] for binding in value["binding"]]
    if len(set(kids)) != len(kids):
        fail("binding kid listed twice")


def decode_payload(data, check):
    try:
        value = decode_canonical(data)
    except Rejection:
        raise KeyScopeError("payload:cbor")
    try:
        check(value)
    except Rejection:
        raise KeyScopeError("payload:shape")
    return value


def base64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def jwk_members(public_key):
    # RFC 7638 §3.2
    if "ed25519" in public_key:
        return {"crv": "Ed25519", "kty": "OKP", "x": base64url(public_key["ed25519"])}
    if "p256" in public_key:
        point = public_key["p256"]
        if point[0] != 0x04:
            return None
        return {"crv": "P-256", "kty": "EC", "x": base64url(point[1:33]), "y": base64url(point[33:])}
    alg, raw = public_key["ml_dsa"]
    if alg not in ML_DSA_NAMES:
        return None
    return {"alg": ML_DSA_NAMES[alg], "kty": "AKP", "pub": base64url(raw)}


def thumbprint(public_key):
    # CR-55 m.4, CR-58 m.1
    members = jwk_members(public_key)
    if members is None:
        return None
    text = json.dumps(members, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).digest()


def alg_matches_key(alg, public_key):
    # CR-56 row 4, CR-58 m.5
    if alg == -19:
        return "ed25519" in public_key
    if alg in (-9, -7):
        return "p256" in public_key
    if alg in ML_DSA_NAMES:
        return "ml_dsa" in public_key and public_key["ml_dsa"][0] == alg
    return False


def binding_scope_domains(binding, metadata):
    # CR-58 m.4
    if binding["scope"] == "domain":
        return [metadata["domain"]]
    return binding["scope"]["provider"]


COSE_ERROR_NAMES = {
    "unknown-kid": "unknown-binding",
    "content-type": "content-type",
    "signature": "signature",
}


def operational_key(metadata_bytes, domain_bytes, excerpt_bytes, usage, iat):
    metadata = decode_payload(metadata_bytes, check_domain_metadata)
    domain = decode_payload(domain_bytes, check_digest)
    bindings = {binding["kid"]: binding for binding in metadata["binding"]}
    # CR-58 m.5, CR-55 m.6
    try:
        kid, payload = verify_sign1(
            excerpt_bytes,
            EXCERPT_CONTENT_TYPE,
            metadata["algorithms"],
            {kid: binding["key"] for kid, binding in bindings.items()},
        )
    except CoseError as error:
        raise KeyScopeError(COSE_ERROR_NAMES.get(error.name, f"cose:{error.name}"))
    excerpt = decode_payload(payload, check_key_excerpt)
    binding = bindings[kid]
    # CR-58 m.6
    if "superseded" in binding:
        raise KeyScopeError("superseded")
    # CR-58 m.5, HL-8
    if not any(same(domain, scoped) for scoped in binding_scope_domains(binding, metadata)):
        raise KeyScopeError("outside-binding-scope")
    # TI-RT6, G35
    if not same(excerpt["domain"], domain):
        raise KeyScopeError("domain-mismatch")
    key = excerpt["key"]
    # CR-58 m.1
    if thumbprint(key["key"]) != key["kid"]:
        raise KeyScopeError("thumbprint")
    # SAI-40, CR-58 m.5
    if key["alg"] not in metadata["algorithms"] or not alg_matches_key(key["alg"], key["key"]):
        raise KeyScopeError("algorithm")
    # CR-58 m.2
    if usage not in key["usage"]:
        raise KeyScopeError("usage")
    # CR-58 m.5, T20, CR-K1
    if key["valid_from"] > key["valid_until"]:
        raise KeyScopeError("window")
    if key["valid_until"] - key["valid_from"] > metadata["operational_window_max_ms"]:
        raise KeyScopeError("window")
    if not key["valid_from"] <= iat <= key["valid_until"]:
        raise KeyScopeError("window")
    return key
