import json

from . import ed25519, p256


MAX_HEADER = 2048
MAX_PAYLOAD = 65536
MAX_TOKEN = 98304
MAX_JSON_DEPTH = 32
UINT_MAX = 2**64 - 1

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
HEADER_MEMBERS = ("alg", "kid", "typ")
ALGORITHM_KEY_TYPE = {"Ed25519": "ed25519", "ES256": "p256"}
ALGORITHM_IDS = {"Ed25519": -19, "ES256": -7}


class JoseError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


class Base64Error(Exception):
    pass


class JsonError(Exception):
    # L0-SIG-41b JSON reasons
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason
        self.duplicate = reason == "duplicate member"


def b64url_decode(text):
    # OP-106 m.15, RFC 4648 §5
    if not isinstance(text, str) or len(text) % 4 == 1:
        raise Base64Error()
    bits = 0
    count = 0
    out = bytearray()
    for char in text:
        index = ALPHABET.find(char)
        if index < 0:
            raise Base64Error()
        bits = (bits << 6) | index
        count += 6
        if count >= 8:
            count -= 8
            out.append((bits >> count) & 0xFF)
            bits &= (1 << count) - 1
    if bits != 0:
        raise Base64Error()
    return bytes(out)


def b64url_encode(data):
    out = []
    for start in range(0, len(data), 3):
        chunk = data[start:start + 3]
        value = int.from_bytes(chunk + bytes(3 - len(chunk)), "big")
        for index in range(len(chunk) + 1):
            out.append(ALPHABET[(value >> (18 - 6 * index)) & 0x3F])
    return "".join(out)


def reject_float(text):
    raise JsonError("number not allowed")


def reject_constant(text):
    raise JsonError("syntax error")


def collect_members(pairs):
    # OP-117 m.14
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise JsonError("duplicate member")
    return dict(pairs)


def check_ijson(value, depth):
    # RFC 7493 §2.1, OP-106 m.5
    if isinstance(value, str):
        for char in value:
            code = ord(char)
            if 0xD800 <= code <= 0xDFFF or 0xFDD0 <= code <= 0xFDEF or code & 0xFFFE == 0xFFFE:
                raise JsonError("syntax error")
        return
    if isinstance(value, (list, dict)):
        if depth + 1 > MAX_JSON_DEPTH:
            raise JsonError("nesting too deep")
        items = value.items() if isinstance(value, dict) else enumerate(value)
        for key, item in items:
            if isinstance(key, str):
                check_ijson(key, depth + 1)
            check_ijson(item, depth + 1)


def parse_json(data, limit=None):
    # OP-106 m.15, L0-ENC-15a
    if limit is not None and len(data) > limit:
        raise JsonError("input too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise JsonError("invalid UTF-8")
    try:
        value = json.loads(
            text,
            object_pairs_hook=collect_members,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except JsonError:
        raise
    except RecursionError:
        raise JsonError("nesting too deep")
    except ValueError:
        raise JsonError("syntax error")
    check_ijson(value, 0)
    return value


def decode_key_set(table):
    keys = {}
    for kid, public in table.items():
        raw = b64url_decode(public)
        keys[b64url_decode(kid)] = {"ed25519": raw} if len(raw) == 32 else {"p256": raw}
    return keys


def verify_signature(key_type, public_key, signing_input, signature):
    # OP-117 m.14a step 12, CR-9 m.3
    if key_type == "ed25519":
        result, reason = ed25519.verify(public_key, signing_input, signature)
        if result == "accept":
            return
        raise JoseError("signature: wrong length" if reason == "length" else "signature: invalid signature")
    parts = p256.split_signature(signature)
    if parts is None:
        raise JoseError("signature: wrong length")
    r, s = parts
    # CR-56 row 12
    if not (0 < r < p256.N and 0 < s < p256.N):
        raise JoseError("signature: ECDSA scalar out of range")
    if s > p256.N // 2:
        raise JoseError("signature: high S")
    if not p256.verify(public_key, signing_input, signature):
        raise JoseError("signature: invalid signature")


def verify_jws(token, keys, allowed, typ, require_kid=True):
    # OP-117 m.14a step 1
    if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN:
        raise JoseError("not a compact JWS")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("not a compact JWS")
    header_text, payload_text, signature_text = parts
    # step 2
    try:
        header_bytes = b64url_decode(header_text)
    except Base64Error:
        raise JoseError("bad base64url")
    # step 3, OP-117 m.16
    try:
        header = parse_json(header_bytes, MAX_HEADER)
    except JsonError as error:
        raise JoseError(f"header: {error.reason}")
    if not isinstance(header, dict):
        raise JoseError("header not in profile")
    for name, value in header.items():
        if name not in HEADER_MEMBERS or not isinstance(value, str):
            raise JoseError("header not in profile")
    # step 4, CR-56 rows 1-3
    if "alg" not in header:
        raise JoseError("header not in profile")
    alg = header["alg"]
    if alg not in ALGORITHM_KEY_TYPE:
        raise JoseError("algorithm not allowed")
    # step 5
    kid = None
    if "kid" in header:
        try:
            kid = b64url_decode(header["kid"])
        except Base64Error:
            raise JoseError("header not in profile")
        if len(kid) != 32:
            raise JoseError("header not in profile")
    if "typ" not in header:
        raise JoseError("header not in profile")
    # step 6
    try:
        payload = b64url_decode(payload_text)
        signature = b64url_decode(signature_text)
    except Base64Error:
        raise JoseError("bad base64url")
    # step 7
    if require_kid and kid is None:
        raise JoseError("header not in profile")
    # step 8
    if ALGORITHM_IDS[alg] not in allowed:
        raise JoseError("algorithm not allowed")
    # step 9
    if header["typ"] != typ:
        raise JoseError("unexpected typ")
    # step 10
    if require_kid:
        if kid not in keys:
            raise JoseError("unknown kid")
        key = keys[kid]
    else:
        key = keys
    # step 11
    key_type = ALGORITHM_KEY_TYPE[alg]
    if key_type not in key:
        raise JoseError("key type does not match algorithm")
    # step 12
    verify_signature(key_type, key[key_type], (header_text + "." + payload_text).encode("ascii"), signature)
    return header, payload


def numeric_date_ms(claims, name):
    # L0-SIG-41a, L0-SIG-41b
    value = claims[name]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise JoseError("bad time claim")
    milliseconds = value * 1000
    if milliseconds > UINT_MAX:
        raise JoseError("bad time claim")
    return milliseconds


def checked_add(a, b):
    # L0-VAL-20
    if a + b > UINT_MAX:
        raise JoseError("bad time claim")
    return a + b


def check_times(claims, now, skew_ms):
    # L0-SIG-41, L0-SIG-41a, L0-SIG-41b: exp (also when absent), then nbf, then iat
    if "exp" not in claims:
        raise JoseError("expired")
    if now > checked_add(numeric_date_ms(claims, "exp"), skew_ms):
        raise JoseError("expired")
    for name in ("nbf", "iat"):
        if name in claims and numeric_date_ms(claims, name) > checked_add(now, skew_ms):
            raise JoseError("not yet valid")


def audience_holds(aud, audience):
    # L0-SIG-41
    if isinstance(aud, str):
        return aud == audience
    return isinstance(aud, list) and aud != [] and audience in aud


def parse_claims(payload):
    try:
        claims = parse_json(payload, MAX_PAYLOAD)
    except JsonError as error:
        raise JoseError(f"payload: {error.reason}")
    return claims if isinstance(claims, dict) else {}


def check_jwt_claims(claims, issuer, audience, now, skew_ms):
    # L0-SIG-41b order: iss, aud, exp, nbf, iat
    if claims.get("iss") != issuer or not isinstance(claims.get("iss"), str):
        raise JoseError("issuer")
    if "aud" not in claims or not audience_holds(claims["aud"], audience):
        raise JoseError("audience")
    check_times(claims, now, skew_ms)


def verify_jwt(token, keys, allowed, typ, issuer, audience, now, skew_ms):
    _, payload = verify_jws(token, keys, allowed, typ)
    claims = parse_claims(payload)
    check_jwt_claims(claims, issuer, audience, now, skew_ms)
    return claims
