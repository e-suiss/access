import base64
import hashlib
import json

import cbor2

from .codec import (
    Rejection,
    check_bool,
    check_tstr,
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
KEY_USAGES = ("receipt", "pap", "token", "checkpoint", "set", "status-list", "key-lookup")
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
    # OP-159 m.3 (i)
    check_map(value, {"at": check_digest, "cited": check_digest}, {"cause": check_text_in("re-anchor", "handover", "recovery")})


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


CT_KEYS = ("ct0", "ct1", "ct2", "ct3")


def check_horizon_caps(value):
    # OP-118 m.4
    if not isinstance(value, dict) or not value:
        fail("expected a non-empty map")
    for ct, ceiling in value.items():
        # L0-VAL-10a
        if ct not in CT_KEYS:
            fail("horizon key is not a CT")
        check_uint(ceiling)


def check_caps(value):
    check_map(value, {}, {
        "horizon": check_horizon_caps,
        "slice_max": check_ident_map(check_amount),
    })
    for unit in value.get("slice_max", {}):
        check_unit(unit)


def check_name(value):
    check_tstr(value)
    if not 1 <= len(value.encode("utf-8")) <= 255:
        fail("name length")


def check_witness(value):
    check_map(value, {"name": check_name, "key": check_public_key, "alg": check_cose_alg, "operator": check_name, "independent": check_bool})


def check_replica(value):
    check_map(value, {"name": check_name, "key": check_public_key, "operator": check_name, "independent": check_bool})


def check_residency(value):
    check_map(value, {"region": check_name, "class": check_text_in("regional", "multi-region-sync")})


def check_mmd(value):
    check_map(value, {"authority_ms": check_uint, "identity_ms": check_uint})


def check_pq_reanchor(value):
    check_map(value, {"size": check_uint, "time": check_uint, "witnesses": check_list(check_name, nonempty=True, is_set=True)})


def check_hosting(value):
    sharing = check_text_in("shared", "dedicated")
    check_map(value, {"hsm_partition": sharing, "compute": sharing})


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
        # OP-120 m.7
        "adopted": check_spec_versions,
    }, {
        "caps": check_caps,
        "hybrid": check_text_in("classic", "both", "pq"),
        "discovery": check_bytes(),
        # OP-158 m.3 (b), OP-159 m.3 (b)
        "witnesses": check_list(check_witness, nonempty=True, is_set=True),
        "replicas": check_list(check_replica, nonempty=True, is_set=True),
        "durability": check_text_in("replicated", "single-node"),
        "residency": check_residency,
        "mmd": check_mmd,
        "recovery": check_text_in("available", "not-available"),
        "ceremony_transcript": check_digest,
        "pq_reanchor": check_pq_reanchor,
        "hosting": check_hosting,
        "crypto_profile": check_text_in("standard", "fips"),
        "fips_module": check_bool,
    })
    kids = [binding["kid"] for binding in value["binding"]]
    if len(set(kids)) != len(kids):
        fail("binding kid listed twice")
    for binding in value["binding"]:
        # CR-58 m.9
        if thumbprint(binding["key"]) != binding["kid"]:
            fail("binding kid is not the key thumbprint")


def decode_payload(data, check):
    # L0-SIG-62a: a payload that does not decode as its type fails with `payload`
    try:
        value = decode_canonical(data)
        check(value)
    except Rejection:
        raise KeyScopeError("payload")
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


def horizon_cap(metadata, ct):
    # OP-118 m.4, L0-VAL-10a
    return metadata.get("caps", {}).get("horizon", {}).get(f"ct{ct}")


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
    "key-alg": "algorithm",
}


def hybrid_admits(policy, alg):
    # L0-SIG-75a, OP-159 m.3 (e)
    if policy == "both":
        return False
    return (alg in ML_DSA_NAMES) == (policy == "pq")


def classical_retired(metadata, alg):
    # CR-45 RA-7, OP-159 m.3 (h)
    return (
        alg not in ML_DSA_NAMES
        and alg not in metadata["algorithms"]
        and any(a in ML_DSA_NAMES for a in metadata["algorithms"])
        and "pq_reanchor" in metadata
    )


def cose_alg(data):
    try:
        message = cbor2.loads(data)
        return cbor2.loads(message.value[0]).get(1)
    except Exception:
        return None


def operational_key(metadata_bytes, domain_bytes, excerpt_bytes, usage, iat, ml_dsa=False, admits=None, evidence=None):
    metadata = decode_payload(metadata_bytes, check_domain_metadata)
    domain = decode_payload(domain_bytes, check_digest)
    bindings = {binding["kid"]: binding for binding in metadata["binding"]}
    # L0-SIG-82, CR-44
    if metadata.get("crypto_profile") == "fips" and any(a in ML_DSA_NAMES for a in metadata["algorithms"]):
        raise KeyScopeError("algorithm")
    # CR-45 RA-7, OP-159 m.3 (h)
    if classical_retired(metadata, cose_alg(excerpt_bytes)):
        raise KeyScopeError("pq-anchor-missing")
    # CR-58 m.5, CR-55 m.6
    try:
        kid, payload = verify_sign1(
            excerpt_bytes,
            EXCERPT_CONTENT_TYPE,
            metadata["algorithms"],
            {kid: binding["key"] for kid, binding in bindings.items()},
            key_algs={kid: binding["alg"] for kid, binding in bindings.items()},
            ml_dsa=ml_dsa,
        )
    except CoseError as error:
        raise KeyScopeError(COSE_ERROR_NAMES.get(error.name, f"cose:{error.name}"))
    excerpt = decode_payload(payload, check_key_excerpt)
    binding = bindings[kid]
    # CR-58 m.6, L0-SIG-80, OP-159 m.3 (i)
    if "superseded" in binding:
        superseded = binding["superseded"]
        if evidence is not None:
            accepted = evidence(binding)
        else:
            accepted = superseded.get("cause") == "re-anchor" and iat <= metadata["issued_at"]
        if not accepted:
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
    policy = metadata.get("hybrid", "classic")
    admitted = hybrid_admits(policy, key["alg"]) if admits is None else admits(key["alg"])
    # CR-45 RA-7, OP-159 m.3 (h)
    if classical_retired(metadata, key["alg"]):
        raise KeyScopeError("pq-anchor-missing")
    # SAI-40, CR-58 m.5, L0-SIG-8, L0-SIG-75a
    if (
        key["alg"] not in metadata["algorithms"]
        or (key["alg"] in ML_DSA_NAMES and not ml_dsa)
        or not alg_matches_key(key["alg"], key["key"])
        or not admitted
    ):
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


def hybrid(metadata_bytes, domain_bytes, classic, pq, usage, iat, content_type, ml_dsa):
    # CR-42, L0-SIG-18, L0-SIG-75a, SAI-44, OP-159 m.3 (e)
    metadata = decode_payload(metadata_bytes, check_domain_metadata)
    policy = metadata.get("hybrid", "classic")

    def component(part, post_quantum):
        key = operational_key(
            metadata_bytes, domain_bytes, part["excerpt"], usage, iat, ml_dsa,
            admits=lambda alg: (alg in ML_DSA_NAMES) == post_quantum,
        )
        try:
            _, payload = verify_sign1(part["sign1"], content_type, [key["alg"]], {key["kid"]: key["key"]}, ml_dsa=ml_dsa)
        except CoseError as error:
            raise KeyScopeError("high-s" if error.name == "high-s" else "signature" if error.name == "signature" else error.name)
        return payload

    if policy == "classic":
        if classic is None:
            raise KeyScopeError("hybrid-missing")
        return component(classic, False)
    if policy == "pq":
        if pq is None:
            raise KeyScopeError("hybrid-missing")
        return component(pq, True)
    if classic is None or pq is None:
        raise KeyScopeError("hybrid-missing")
    first = component(classic, False)
    second = component(pq, True)
    if first != second:
        raise KeyScopeError("hybrid-payload")
    return first


def decode_carrier(data):
    # OP-159 m.15 (b)
    from . import dcbor
    try:
        dcbor.check(data)
        items = cbor2.loads(data)
    except Exception:
        raise KeyScopeError("hybrid-carrier")
    if not isinstance(items, list) or len(items) != 2 or not all(isinstance(i, bytes) for i in items):
        raise KeyScopeError("hybrid-carrier")
    classic, pq = items
    a, b = cose_alg(classic), cose_alg(pq)
    if a is None or b is None or a in ML_DSA_NAMES or b not in ML_DSA_NAMES:
        raise KeyScopeError("hybrid-carrier")
    return classic, pq
