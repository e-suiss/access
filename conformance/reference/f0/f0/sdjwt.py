import hashlib
import json

from . import p256
from .jose import (
    MAX_PAYLOAD,
    UINT_MAX,
    Base64Error,
    JoseError,
    JsonError,
    b64url_decode,
    b64url_encode,
    check_times,
    numeric_date_ms,
    parse_json,
    verify_jws,
)


MAX_PRESENTATION = 262144
MAX_DISCLOSURES = 256
KB_TYP = "kb+jwt"
KB_MAX_AGE_MS = 300000
RESERVED_NAMES = ("_sd", "...")


class SdJwtError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


def digest_of(disclosure):
    # RFC 9901 §4.2.3
    return b64url_encode(hashlib.sha256(disclosure.encode("ascii")).digest())


def parse(data):
    # L0-SIG-53 `json: <JSON reason>`
    try:
        return parse_json(data, MAX_PAYLOAD)
    except JsonError as error:
        raise SdJwtError(f"json: {error.reason}")


def decode_disclosure(text):
    # RFC 9901 §4.2.1, §4.2.2, L0-SIG-50
    try:
        raw = b64url_decode(text)
    except Base64Error:
        raise SdJwtError("malformed disclosure")
    value = parse(raw)
    if not isinstance(value, list) or len(value) not in (2, 3) or not isinstance(value[0], str):
        raise SdJwtError("malformed disclosure")
    if len(value) == 3:
        if not isinstance(value[1], str) or value[1] in RESERVED_NAMES:
            raise SdJwtError("malformed disclosure")
        return value[1], value[2]
    return None, value[1]


class Disclosures:
    def __init__(self, texts):
        self.by_digest = {}
        for text in texts:
            decoded = decode_disclosure(text)
            digest = digest_of(text)
            # RFC 9901 §7.1 step 3
            if digest in self.by_digest:
                raise SdJwtError("duplicate disclosure")
            self.by_digest[digest] = decoded
        self.used = set()

    def take(self, digest):
        if not isinstance(digest, str):
            raise SdJwtError("malformed disclosure")
        # RFC 9901 §7.1 step 3.3.1
        if digest in self.used:
            raise SdJwtError("duplicate disclosure")
        self.used.add(digest)
        return self.by_digest.get(digest)


def process(value, disclosures):
    # RFC 9901 §7.1 step 3
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict) and "..." in item:
                if len(item) != 1:
                    raise SdJwtError("malformed disclosure")
                found = disclosures.take(item["..."])
                if found is None:
                    continue
                name, element = found
                if name is not None:
                    raise SdJwtError("malformed disclosure")
                out.append(process(element, disclosures))
            else:
                out.append(process(item, disclosures))
        return out
    if not isinstance(value, dict):
        return value
    out = {}
    for name, item in value.items():
        if name == "_sd":
            continue
        if name == "...":
            raise SdJwtError("malformed disclosure")
        out[name] = process(item, disclosures)
    digests = value.get("_sd", [])
    if not isinstance(digests, list):
        raise SdJwtError("malformed disclosure")
    for digest in digests:
        found = disclosures.take(digest)
        if found is None:
            continue
        name, element = found
        if name is None:
            raise SdJwtError("malformed disclosure")
        if name in out:
            raise SdJwtError("claim name collision")
        out[name] = process(element, disclosures)
    return out


def key_from_jwk(jwk):
    # RFC 7800 §3.2, RFC 8037, RFC 7518 §6.2
    if isinstance(jwk, dict):
        try:
            if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
                x = b64url_decode(jwk["x"])
                if len(x) == 32:
                    return {"ed25519": x}
            if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
                x = b64url_decode(jwk["x"])
                y = b64url_decode(jwk["y"])
                point = b"\x04" + x + y
                if len(x) == 32 and len(y) == 32 and p256.decode_public_key(point) is not None:
                    return {"p256": point}
        except (KeyError, Base64Error, TypeError):
            pass
    raise SdJwtError("bad confirmation key")


def check_issuer_claims(claims, now, skew_ms):
    # L0-SIG-51
    try:
        if not isinstance(claims.get("iss"), str):
            raise JoseError("issuer")
        check_times(claims, now, skew_ms)
    except JoseError as error:
        raise SdJwtError(f"issuer claims: {error.name}")


def verify_key_binding(kb_jwt, holder_key, allowed, audience, nonce, sd_hash, now, skew_ms):
    # L0-SIG-52, RFC 9901 §7.3
    try:
        header, payload = verify_jws(kb_jwt, holder_key, allowed, KB_TYP, require_kid=False)
    except JoseError as error:
        raise SdJwtError(f"jws: {error.name}")
    if "kid" in header:
        raise SdJwtError("jws: header not in profile")
    claims = parse(payload)
    if not isinstance(claims, dict):
        raise SdJwtError("json: syntax error")
    if claims.get("aud") != audience:
        raise SdJwtError("key binding claims: audience")
    if claims.get("nonce") != nonce or claims.get("sd_hash") != sd_hash:
        raise SdJwtError("key binding mismatch")
    try:
        if "iat" not in claims:
            raise JoseError("bad time claim")
        iat = numeric_date_ms(claims, "iat")
    except JoseError as error:
        raise SdJwtError(f"key binding claims: {error.name}")
    if now >= KB_MAX_AGE_MS and iat < now - KB_MAX_AGE_MS:
        raise SdJwtError("key binding claims: expired")
    if now + skew_ms > UINT_MAX or iat > now + skew_ms:
        raise SdJwtError("key binding claims: not yet valid")


def verify_sd_jwt(presentation, keys, allowed, typ, audience, nonce, now, skew_ms):
    # OP-117 m.6
    if not isinstance(presentation, str) or len(presentation.encode("utf-8")) > MAX_PRESENTATION:
        raise SdJwtError("not an SD-JWT presentation")
    parts = presentation.split("~")
    if len(parts) < 2:
        raise SdJwtError("not an SD-JWT presentation")
    issuer_jwt, disclosure_texts, kb_jwt = parts[0], parts[1:-1], parts[-1]
    if len(disclosure_texts) > MAX_DISCLOSURES or any(text == "" for text in disclosure_texts):
        raise SdJwtError("not an SD-JWT presentation")
    # L0-SIG-50: the issuer-signed JWT follows §3
    try:
        _, payload = verify_jws(issuer_jwt, keys, allowed, typ)
    except JoseError as error:
        raise SdJwtError(f"jws: {error.name}")
    claims = parse(payload)
    if not isinstance(claims, dict):
        raise SdJwtError("json: syntax error")
    # L0-SIG-51: before any disclosure is applied
    check_issuer_claims(claims, now, skew_ms)
    # OP-117 m.18
    if "_sd_alg" in claims and claims["_sd_alg"] != "sha-256":
        raise SdJwtError("hash algorithm not allowed")
    disclosures = Disclosures(disclosure_texts)
    disclosed = process(claims, disclosures)
    # RFC 9901 §7.1 step 4
    if set(disclosures.by_digest) - disclosures.used:
        raise SdJwtError("unreferenced disclosure")
    disclosed.pop("_sd_alg", None)
    if "cnf" in claims:
        # L0-SIG-50: holder-bound artifacts carry a Key Binding JWT
        if not kb_jwt:
            raise SdJwtError("key binding mismatch")
        cnf = claims["cnf"]
        holder_key = key_from_jwk(cnf.get("jwk") if isinstance(cnf, dict) else None)
        sd_hash = digest_of(presentation[: len(presentation) - len(kb_jwt)])
        verify_key_binding(kb_jwt, holder_key, allowed, audience, nonce, sd_hash, now, skew_ms)
    elif kb_jwt:
        raise SdJwtError("key binding mismatch")
    return disclosed


def disclosed_json(disclosed):
    return json.dumps(disclosed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
