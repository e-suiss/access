import cbor2

from . import ed25519, p256
from .codec import Rejection, check_data_model, decode_canonical, encode


COSE_SIGN1_TAG = 18
LABEL_ALG = 1
LABEL_CRIT = 2
LABEL_CONTENT_TYPE = 3
LABEL_KID = 4
UNDERSTOOD_LABELS = (LABEL_ALG, LABEL_CRIT, LABEL_CONTENT_TYPE, LABEL_KID)

ALGORITHM_KEY_TYPE = {
    -19: "ed25519",
    -8: "ed25519",
    -9: "p256",
    -7: "p256",
}
ML_DSA_ALGORITHMS = (-48, -49, -50)


class CoseError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


def decode_tagged(data):
    # CR-55 m.6, OP-106 m.3
    try:
        value = cbor2.loads(data)
    except Exception:
        raise CoseError("cbor")
    if not isinstance(value, cbor2.CBORTag) or value.tag != COSE_SIGN1_TAG:
        raise CoseError("cbor")
    try:
        check_data_model(value.value, 2, int_keys=True)
    except Rejection:
        raise CoseError("cbor")
    # OP-106 m.1
    if encode(value) != data:
        raise CoseError("cbor")
    return value.value


def check_shape(message):
    # RFC 9052 §4.2, CR-55 m.6
    if not isinstance(message, list) or len(message) != 4:
        raise CoseError("shape")
    protected, unprotected, payload, signature = message
    if not isinstance(protected, bytes) or not isinstance(unprotected, dict):
        raise CoseError("shape")
    if not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise CoseError("shape")
    return protected, unprotected, payload, signature


def decode_protected(protected):
    # CR-55 m.6
    try:
        header = decode_canonical(protected, int_keys=True)
    except Rejection:
        raise CoseError("header")
    if not isinstance(header, dict):
        raise CoseError("header")
    for label in header:
        if type(label) is not int or label not in UNDERSTOOD_LABELS:
            raise CoseError("header")
    for label in (LABEL_ALG, LABEL_CONTENT_TYPE, LABEL_KID):
        if label not in header:
            raise CoseError("header")
    if type(header[LABEL_ALG]) is not int:
        raise CoseError("header")
    if not isinstance(header[LABEL_CONTENT_TYPE], str):
        raise CoseError("header")
    # CR-55 m.4
    if not isinstance(header[LABEL_KID], bytes) or len(header[LABEL_KID]) != 32:
        raise CoseError("header")
    return header


def check_crit(header):
    # CR-55 m.6
    if LABEL_CRIT not in header:
        return
    crit = header[LABEL_CRIT]
    if not isinstance(crit, list) or not crit:
        raise CoseError("crit")
    for label in crit:
        if type(label) is not int or label not in (LABEL_ALG, LABEL_CONTENT_TYPE, LABEL_KID):
            raise CoseError("crit")


def signature_input(protected, payload):
    # RFC 9052 §4.4, CR-55 m.6
    return encode(["Signature1", protected, b"", payload])


def verify_sign1(data, content_type, allowed, keys, access_native=True):
    message = decode_tagged(data)
    protected, unprotected, payload, signature = check_shape(message)
    header = decode_protected(protected)
    check_crit(header)
    # CR-55 m.6
    if unprotected:
        raise CoseError("unprotected")
    alg = header[LABEL_ALG]
    # CR-7, CR-55 m.1
    if alg not in allowed or alg in ML_DSA_ALGORITHMS or alg not in ALGORITHM_KEY_TYPE:
        raise CoseError("algorithm")
    kid = header[LABEL_KID]
    # CR-55 m.4
    if kid not in keys:
        raise CoseError("unknown-kid")
    key = keys[kid]
    key_type = ALGORITHM_KEY_TYPE[alg]
    # CR-56 row 4, CR-55 m.3
    if not isinstance(key, dict) or key_type not in key:
        raise CoseError("key-type")
    if header[LABEL_CONTENT_TYPE] != content_type:
        raise CoseError("content-type")
    to_be_signed = signature_input(protected, payload)
    if key_type == "ed25519":
        # CR-53
        result, _ = ed25519.verify(key["ed25519"], to_be_signed, signature)
        if result != "accept":
            raise CoseError("signature")
    else:
        # CR-9 m.3
        if access_native and p256.is_high_s(signature):
            raise CoseError("high-s")
        if not p256.verify(key["p256"], to_be_signed, signature):
            raise CoseError("signature")
    return kid, payload
