"""Independent CR-53 reference (RFC 8032 arithmetic) that labels the speccheck cases.

Rule: cofactorless [S]B = R + [k]A; reject non-canonical A, R, S; S >= L; small-order A or R.
Usage: python -I ed25519_strict.py <speccheck cases.json>  > core/1/ed25519-strict.json
"""

import hashlib
import json
import sys

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    C = t1 * 2 * D * t2 % P
    Dd = z1 * 2 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = add(q, p)
        p = add(p, p)
        s >>= 1
    return q


def eq(a, b):
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def decode(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
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


IDENTITY = (0, 1, 1, 0)
gy = 4 * pow(5, P - 2, P) % P
B = decode(gy.to_bytes(32, "little"))


def small_order(p):
    return eq(mul(8, p), IDENTITY)


def verify(pk, msg, sig):
    if len(sig) != 64:
        return "reject", "length"
    a = decode(pk)
    r = decode(sig[:32])
    if a is None:
        return "reject", "non_canonical_a"
    if r is None:
        return "reject", "non_canonical_r"
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return "reject", "s_not_reduced"
    if small_order(a):
        return "reject", "small_order_a"
    if small_order(r):
        return "reject", "small_order_r"
    k = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % L
    if eq(mul(s, B), add(r, mul(k, a))):
        return "accept", "ok"
    return "reject", "equation"


def main():
    cases = json.load(open(sys.argv[1]))
    out = []
    for i, c in enumerate(cases):
        result, reason = verify(bytes.fromhex(c["pub_key"]), bytes.fromhex(c["message"]), bytes.fromhex(c["signature"]))
        out.append({"id": f"speccheck-{i}", "public_key": c["pub_key"], "message": c["message"],
                    "signature": c["signature"], "result": result, "reason": reason})
    json.dump({"rule": "CR-53", "track": "core", "version": 1, "operation": "verify.ed25519",
               "source": "novifinancial/ed25519-speccheck cases.json; labels from this reference", "cases": out},
              sys.stdout, indent=1)
    sys.stdout.write("\n")


main()
