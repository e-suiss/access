import hashlib


P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
INFINITY = None


def on_curve(point):
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    if p1 is INFINITY:
        return p2
    if p2 is INFINITY:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return INFINITY
    if p1 == p2:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(scalar, point):
    result = INFINITY
    while scalar > 0:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def decode_public_key(data):
    # SEC 1 §2.3.4, CR-56 row 11
    if len(data) != 65 or data[0] != 0x04:
        return None
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:], "big")
    if x >= P or y >= P or not on_curve((x, y)):
        return None
    return (x, y)


def split_signature(signature):
    # RFC 9053 §2.1
    if len(signature) != 64:
        return None
    return int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")


def is_high_s(signature):
    # CR-9 m.3
    parts = split_signature(signature)
    return parts is not None and parts[1] > N // 2


def verify(public_key, message, signature):
    # FIPS 186-5 §6.4.2
    point = decode_public_key(public_key)
    parts = split_signature(signature)
    if point is None or parts is None:
        return False
    r, s = parts
    # CR-56 row 12
    if not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, N)
    u1 = e * w % N
    u2 = r * w % N
    result = point_add(point_mul(u1, G), point_mul(u2, point))
    if result is INFINITY:
        return False
    return result[0] % N == r
