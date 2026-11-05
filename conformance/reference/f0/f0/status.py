"""Token Status List references and lookups, written from L2-STL-1 to L2-STL-3."""

from .codec import Rejection, check_bytes, check_map, check_tstr, check_uint, decode_canonical, fail

MAX_URI = 2048


class StatusError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def check_uri(value):
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= MAX_URI:
        fail("uri")


def check_status_ref(value):
    # L2-STL-1
    check_map(value, {"status_list": lambda v: check_map(v, {"idx": check_uint, "uri": check_uri})})


def check_bits(value):
    # OP-150 m.3 (s): one bit per entry
    if value != 1 or isinstance(value, bool):
        fail("bits")


def check_status_list(value):
    check_map(value, {"bits": check_bits, "lst": check_bytes()}, {"aggregation_uri": check_tstr})


def check_token(value):
    # L2-STL-2: CWT claims 2 (sub), 6 (iat), 4 (exp), 65534 (ttl), 65533 (the list) and as_of
    if not isinstance(value, dict):
        fail("token")
    required = {2: check_uri, 6: check_uint, 65533: check_status_list, "as_of": check_uint}
    optional = {4: check_uint, 65534: check_uint}
    for key in value:
        if key not in required and key not in optional:
            fail("unknown claim")
    for key, check in required.items():
        if key not in value:
            fail("missing claim")
        check(value[key])
    for key, check in optional.items():
        if key in value:
            check(value[key])


def lookup(token_bytes, decompressed, reference_bytes):
    # L2-STL-3
    try:
        token = decode_canonical(token_bytes, int_keys=True)
        check_token(token)
    except Rejection:
        raise StatusError("status-malformed")
    reference = decode_canonical(reference_bytes)
    check_status_ref(reference)
    entry = reference["status_list"]
    if token[2] != entry["uri"]:
        raise StatusError("status-uri")
    index = entry["idx"]
    if index // 8 >= len(decompressed):
        raise StatusError("status-index")
    return (decompressed[index // 8] >> (index % 8)) & 1 == 1
