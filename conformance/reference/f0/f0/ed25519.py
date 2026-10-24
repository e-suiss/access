import hashlib


P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)


def point_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e1 = (y1 - x1) * (y2 - x2) % P
    e2 = (y1 + x1) * (y2 + x2) % P
    e3 = t1 * 2 * D * t2 % P
    e4 = z1 * 2 * z2 % P
    e, f, g, h = e2 - e1, e4 - e3, e4 + e3, e2 + e1
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(scalar, point):
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def point_equal(a, b):
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def point_decode(data):
    # RFC 8032 §5.1.3, CR-53
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x2, (P + 3) // 8, P)
        if (x * x - x2) % P != 0:
            x = x * SQRT_M1 % P
        if (x * x - x2) % P != 0:
            return None
        if (x & 1) != sign:
            x = P - x
    return (x, y, 1, x * y % P)


BASE = point_decode((4 * pow(5, P - 2, P) % P).to_bytes(32, "little"))


def small_order(point):
    return point_equal(point_mul(8, point), IDENTITY)


def verify(public_key, message, signature):
    # CR-53, CR-9 m.1
    if len(signature) != 64:
        return "reject", "length"
    a = point_decode(public_key)
    r = point_decode(signature[:32])
    if a is None:
        return "reject", "non_canonical_a"
    if r is None:
        return "reject", "non_canonical_r"
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return "reject", "s_not_reduced"
    if small_order(a):
        return "reject", "small_order_a"
    if small_order(r):
        return "reject", "small_order_r"
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    if point_equal(point_mul(s, BASE), point_add(r, point_mul(k, a))):
        return "accept", "ok"
    return "reject", "equation"
