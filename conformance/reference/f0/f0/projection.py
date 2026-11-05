from .jose import (
    MAX_PAYLOAD,
    Base64Error,
    JoseError,
    JsonError,
    b64url_decode,
    check_jwt_claims,
    parse_json,
    verify_jws,
)
from .sdjwt import SdJwtError, verify_sd_jwt


ACCESS_TOKEN_TYP = "at+jwt"
PAP_TYP = "access-pap+sd-jwt"
KINDS = ("intent", "bounds")


class ProjectionError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def text(claims, name):
    value = claims.get(name)
    if not isinstance(value, str) or value == "":
        raise ProjectionError("projection-member")
    return value


def confirmation(claims, member, thumbprint):
    # L2-JOS-3
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict):
        raise ProjectionError("projection-member")
    if len(cnf) != 1:
        raise ProjectionError("projection-confirmation")
    (name, value), = cnf.items()
    if not isinstance(value, str):
        raise ProjectionError("projection-confirmation")
    try:
        raw = b64url_decode(value)
    except Base64Error:
        raise ProjectionError("projection-confirmation")
    if name != member or raw != thumbprint:
        raise ProjectionError("projection-confirmation")


def authority(claims, domain):
    # L2-JOS-4
    details = claims.get("authorization_details")
    if not isinstance(details, list):
        raise ProjectionError("projection-member")
    kind = None
    for detail in details:
        if not isinstance(detail, dict):
            raise ProjectionError("projection-authority")
        text(detail, "type")
        this = text(detail, "kind")
        if this not in KINDS:
            raise ProjectionError("projection-authority")
        if kind is not None and kind != this:
            raise ProjectionError("projection-authority")
        kind = this
        if text(detail, "domain") != domain:
            raise ProjectionError("projection-domain")
        if not isinstance(detail.get("validity"), dict):
            raise ProjectionError("projection-member")
    if kind is None or (kind == "intent" and len(details) != 1):
        raise ProjectionError("projection-authority")
    return kind


def verify_access_token(token, keys, allowed, issuer, audience, domain, member, thumbprint, now, skew_ms):
    # L2-JOS-1, L2-JOS-2
    try:
        _, payload = verify_jws(token, keys, allowed, ACCESS_TOKEN_TYP)
    except JoseError:
        raise ProjectionError("projection-jws")
    try:
        claims = parse_json(payload, MAX_PAYLOAD)
    except JsonError:
        raise ProjectionError("projection-json")
    if not isinstance(claims, dict):
        raise ProjectionError("projection-member")
    if not isinstance(claims.get("aud"), str):
        raise ProjectionError("projection-claims")
    try:
        check_jwt_claims(claims, issuer, audience, now, skew_ms)
    except JoseError:
        raise ProjectionError("projection-claims")
    if not is_int(claims.get("iat")):
        raise ProjectionError("projection-member")
    for name in ("sub", "jti", "client_id"):
        text(claims, name)
    confirmation(claims, member, thumbprint)
    return authority(claims, domain)


def verify_pap_sd_jwt(presentation, keys, allowed, audience, nonce, domain, now, skew_ms):
    # L2-JOS-5, L2-JOS-6
    try:
        claims = verify_sd_jwt(presentation, keys, allowed, PAP_TYP, audience, nonce, now, skew_ms)
    except SdJwtError:
        raise ProjectionError("projection-sd-jwt")
    if "cnf" not in claims:
        raise ProjectionError("projection-holder")
    if text(claims, "iss") != domain:
        raise ProjectionError("projection-domain")
    if not is_int(claims.get("iat")):
        raise ProjectionError("projection-member")
    for name in ("projection_exercise", "lineage_commitment"):
        text(claims, name)
    for name in ("holder", "bounds", "validity"):
        if not isinstance(claims.get(name), dict):
            raise ProjectionError("projection-member")
    if "capacity" not in claims:
        raise ProjectionError("projection-member")
