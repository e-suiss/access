import hashlib

from .codec import HASH_ALG_SHA256, check_intent_envelope, decode_canonical, encode


INTENT_CONTEXT = "access/intent/v1"


def tagged_digest(context, value):
    # L0-ENC-22
    return [HASH_ALG_SHA256, hashlib.sha256(context.encode("utf-8") + b"\x00" + encode(value)).digest()]


def intent_digest(data):
    # L0-ENC-23
    intent = decode_canonical(data)
    check_intent_envelope(intent)
    return tagged_digest(INTENT_CONTEXT, intent)


def body_commit(salt, body):
    # L0-ENC-29a, OP-106 m.14
    decode_canonical(body)
    return hashlib.sha256(b"\x03" + salt + body).digest()
