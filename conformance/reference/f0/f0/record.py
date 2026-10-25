import hashlib

import cbor2

from . import dcbor, merkle
from .codec import HASH_ALG_SHA256, IDENT, UINT_MAX, check_data_model, encode


GENESIS_CONTEXT = "access/genesis/v1"
RECORD_KINDS = ("genesis", "opening", "decision", "claim")
HEADER = ("domain", "pos", "kind", "recorded_at", "prev")


class RecordError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


def decode(data):
    # OP-106 m.1
    try:
        dcbor.check(data)
    except dcbor.DecodeError:
        raise RecordError("cbor")
    value = cbor2.loads(data)
    try:
        check_data_model(value)
    except Exception:
        raise RecordError("cbor")
    if encode(value) != data:
        raise RecordError("cbor")
    return value


def tagged_digest(context, value):
    # OP-117 m.1, L0-ENC-22
    return [HASH_ALG_SHA256, hashlib.sha256(context.encode("utf-8") + b"\x00" + encode(value)).digest()]


def check_digest(value):
    if not isinstance(value, list) or len(value) != 2 or type(value[0]) is not int:
        raise RecordError("shape")
    if value[0] != HASH_ALG_SHA256 or not isinstance(value[1], bytes):
        raise RecordError("shape")
    if len(value[1]) != 32:
        raise RecordError("range")


def check_uint(value):
    if type(value) is not int:
        raise RecordError("shape")
    if not 0 <= value <= UINT_MAX:
        raise RecordError("range")


def check_header(value):
    # L0-ENC-26, L0-ENC-27, L0-ENC-29b
    for name in ("pos", "kind", "recorded_at"):
        if name not in value:
            raise RecordError("missing")
    check_uint(value["pos"])
    check_uint(value["recorded_at"])
    if not isinstance(value["kind"], str):
        raise RecordError("shape")
    if value["kind"] not in RECORD_KINDS:
        raise RecordError("unknown")
    for name in ("domain", "prev"):
        if name in value:
            check_digest(value[name])
    genesis = value["kind"] == "genesis"
    if genesis != (value["pos"] == 0):
        raise RecordError("range")
    for name in ("domain", "prev"):
        if (name in value) == genesis:
            raise RecordError("range")


def check_named_map(value, element):
    if not isinstance(value, dict):
        raise RecordError("shape")
    if not value:
        raise RecordError("range")
    for name, item in value.items():
        if not isinstance(name, str):
            raise RecordError("shape")
        if not IDENT.fullmatch(name):
            raise RecordError("range")
        element(item)


def check_salt(value):
    if not isinstance(value, bytes):
        raise RecordError("shape")
    if len(value) != 32:
        raise RecordError("range")


def check_any(value):
    return


def decode_disclosure(data, envelope):
    # L0-ENC-29b, L0-ENC-29c
    value = decode(data)
    if not isinstance(value, dict):
        raise RecordError("shape")
    allowed = HEADER + ("fields", "field_salt") + (() if envelope else ("withheld",))
    for name in value:
        if name not in allowed:
            raise RecordError("unknown")
    check_header(value)
    if envelope:
        for name in ("fields", "field_salt"):
            if name not in value:
                raise RecordError("missing")
    elif not any(name in value for name in ("fields", "field_salt", "withheld")):
        raise RecordError("missing")
    if ("fields" in value) != ("field_salt" in value):
        raise RecordError("missing")
    if "fields" in value:
        check_named_map(value["fields"], check_any)
        check_named_map(value["field_salt"], check_salt)
        if set(value["fields"]) != set(value["field_salt"]):
            raise RecordError("range")
    if "withheld" in value:
        check_named_map(value["withheld"], check_digest)
        if set(value["withheld"]) & set(value.get("fields", {})):
            raise RecordError("range")
    return value


def field_commitment(name, salt, item):
    # L0-ENC-28, OP-120 m.5
    return hashlib.sha256(b"\x02" + salt + encode([name, item])).digest()


def commitments(record):
    # L0-ENC-29c: opened fields are always recomputed
    out = {name: field_commitment(name, record["field_salt"][name], item) for name, item in record.get("fields", {}).items()}
    for name, digest in record.get("withheld", {}).items():
        out[name] = digest[1]
    return out


def field_root(record):
    # L0-ENC-29, OP-106 m.13
    committed = commitments(record)
    ordered = sorted(committed, key=lambda name: name.encode("utf-8"))
    return merkle.tree_hash([committed[name] for name in ordered])


def leaf_core(record):
    core = {name: record[name] for name in HEADER if name in record}
    core["field_root"] = field_root(record)
    return core


def leaf_hash(record):
    # L0-ENC-29
    return merkle.leaf_hash(encode(leaf_core(record)))


def domain_id(record):
    # L0-ENC-25
    if record["kind"] == "genesis":
        return tagged_digest(GENESIS_CONTEXT, record)
    return record["domain"]
