"""ML-DSA verification written from FIPS 204 (CR-41, CR-51 V9, OP-159 m.3 (n)).

Plain Python integers, no dependency beyond hashlib's SHAKE. Verification only: the F0 reference
never signs. `verify` is ML-DSA.Verify (Algorithm 3) with a context string; `verify_internal` is
Algorithm 8 on a prepared M' or a given mu.
"""

import hashlib

Q = 8380417
N = 256
D = 13
ZETA = 1753
N_INV = 8347681

PARAMS = {
    "ML-DSA-44": dict(k=4, l=4, eta=2, tau=39, beta=78, gamma1=1 << 17, gamma2=(Q - 1) // 88, omega=80, ctilde=32),
    "ML-DSA-65": dict(k=6, l=5, eta=4, tau=49, beta=196, gamma1=1 << 19, gamma2=(Q - 1) // 32, omega=55, ctilde=48),
    "ML-DSA-87": dict(k=8, l=7, eta=2, tau=60, beta=120, gamma1=1 << 19, gamma2=(Q - 1) // 32, omega=75, ctilde=64),
}

COSE_ALGORITHMS = {-48: "ML-DSA-44", -49: "ML-DSA-65", -50: "ML-DSA-87"}


def _brv8(x):
    return int(f"{x:08b}"[::-1], 2)


ZETAS = [pow(ZETA, _brv8(i), Q) for i in range(N)]


def shake128(data, length):
    return hashlib.shake_128(data).digest(length)


def shake256(data, length):
    return hashlib.shake_256(data).digest(length)


def public_key_length(p):
    return 32 + 320 * p["k"]


def z_bits(p):
    return (2 * p["gamma1"] - 1).bit_length()


def signature_length(p):
    return p["ctilde"] + 32 * z_bits(p) * p["l"] + p["omega"] + p["k"]


def ntt(f):
    w = list(f)
    m = 0
    length = 128
    while length >= 1:
        start = 0
        while start < N:
            m += 1
            z = ZETAS[m]
            for j in range(start, start + length):
                t = z * w[j + length] % Q
                w[j + length] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
            start += 2 * length
        length //= 2
    return w


def ntt_inverse(w):
    f = list(w)
    m = N
    length = 1
    while length < N:
        start = 0
        while start < N:
            m -= 1
            z = -ZETAS[m]
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = z * (t - f[j + length]) % Q
            start += 2 * length
        length *= 2
    return [N_INV * x % Q for x in f]


def pointwise(a, b):
    return [x * y % Q for x, y in zip(a, b)]


def add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def unpack(data, width, count=N):
    value = int.from_bytes(data, "little")
    mask = (1 << width) - 1
    return [(value >> (width * i)) & mask for i in range(count)]


def pack(values, width):
    value = 0
    for i, v in enumerate(values):
        value |= (v & ((1 << width) - 1)) << (width * i)
    return value.to_bytes(width * len(values) // 8, "little")


def rej_ntt_poly(seed):
    # Algorithm 30
    out = []
    length = 840
    while True:
        stream = shake128(seed, length)
        out = []
        pos = 0
        while len(out) < N and pos + 3 <= len(stream):
            z = stream[pos] | (stream[pos + 1] << 8) | ((stream[pos + 2] & 0x7F) << 16)
            pos += 3
            if z < Q:
                out.append(z)
        if len(out) == N:
            return out
        length *= 2


def expand_a(rho, p):
    # Algorithm 32
    return [[rej_ntt_poly(rho + bytes([s, r])) for s in range(p["l"])] for r in range(p["k"])]


def sample_in_ball(ctilde, p):
    # Algorithm 29
    tau = p["tau"]
    length = 272
    while True:
        stream = shake256(ctilde, length)
        signs = int.from_bytes(stream[:8], "little")
        c = [0] * N
        pos = 8
        complete = True
        for i in range(N - tau, N):
            while True:
                if pos >= len(stream):
                    complete = False
                    break
                j = stream[pos]
                pos += 1
                if j <= i:
                    break
            if not complete:
                break
            c[i] = c[j]
            c[j] = -1 if (signs >> (i + tau - N)) & 1 else 1
        if complete:
            return [x % Q for x in c]
        length *= 2


def mod_pm(r, alpha):
    r0 = r % alpha
    if r0 > alpha // 2:
        r0 -= alpha
    return r0


def decompose(r, gamma2):
    # Algorithm 36
    r_plus = r % Q
    r0 = mod_pm(r_plus, 2 * gamma2)
    if r_plus - r0 == Q - 1:
        return 0, r0 - 1
    return (r_plus - r0) // (2 * gamma2), r0


def high_bits(r, gamma2):
    return decompose(r, gamma2)[0]


def low_bits(r, gamma2):
    return decompose(r, gamma2)[1]


def use_hint(h, r, gamma2):
    # Algorithm 40
    m = (Q - 1) // (2 * gamma2)
    r1, r0 = decompose(r, gamma2)
    if h == 1:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1


def centered(x):
    return mod_pm(x, Q)


def infinity_norm(polys):
    return max(abs(centered(x)) for poly in polys for x in poly)


def pk_decode(pk, p):
    rho = pk[:32]
    t1 = [unpack(pk[32 + 320 * i: 32 + 320 * (i + 1)], 10) for i in range(p["k"])]
    return rho, t1


def hint_unpack(y, p):
    # Algorithm 21: strictly increasing indices, counts bounded by omega, zero padding
    k, omega = p["k"], p["omega"]
    h = [[0] * N for _ in range(k)]
    index = 0
    for i in range(k):
        count = y[omega + i]
        if count < index or count > omega:
            return None
        first = index
        while index < count:
            if index > first and y[index - 1] >= y[index]:
                return None
            h[i][y[index]] = 1
            index += 1
    if any(y[i] != 0 for i in range(index, omega)):
        return None
    return h


def sig_decode(sig, p):
    width = z_bits(p)
    size = 32 * width
    ctilde = sig[: p["ctilde"]]
    at = p["ctilde"]
    z = []
    for _ in range(p["l"]):
        z.append([(p["gamma1"] - v) % Q for v in unpack(sig[at: at + size], width)])
        at += size
    return ctilde, z, hint_unpack(sig[at:], p)


def w1_encode(w1, p):
    width = ((Q - 1) // (2 * p["gamma2"]) - 1).bit_length()
    return b"".join(pack(poly, width) for poly in w1)


def verify_internal(name, pk, message, sig, mu=None):
    # Algorithm 8
    p = PARAMS[name]
    if len(pk) != public_key_length(p) or len(sig) != signature_length(p):
        return False
    rho, t1 = pk_decode(pk, p)
    ctilde, z, h = sig_decode(sig, p)
    if h is None:
        return False
    if infinity_norm(z) >= p["gamma1"] - p["beta"]:
        return False
    a_hat = expand_a(rho, p)
    if mu is None:
        tr = shake256(pk, 64)
        mu = shake256(tr + message, 64)
    c_hat = ntt(sample_in_ball(ctilde, p))
    z_hat = [ntt(poly) for poly in z]
    w1 = []
    for r in range(p["k"]):
        acc = [0] * N
        for s in range(p["l"]):
            acc = add(acc, pointwise(a_hat[r][s], z_hat[s]))
        t1_hat = ntt([x * (1 << D) % Q for x in t1[r]])
        approx = ntt_inverse(sub(acc, pointwise(c_hat, t1_hat)))
        w1.append([use_hint(h[r][j], approx[j], p["gamma2"]) for j in range(N)])
    return shake256(mu + w1_encode(w1, p), p["ctilde"]) == ctilde


def verify(name, pk, message, sig, context=b""):
    # Algorithm 3: pure ML-DSA with a context string
    if name not in PARAMS or len(context) > 255:
        return False
    return verify_internal(name, pk, bytes([0, len(context)]) + context + message, sig)
