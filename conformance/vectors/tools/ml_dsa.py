"""ML-DSA vector tool (CR-51 V9, OP-159 m.3 (n)).

  python -I ml_dsa.py extract <wycheproof testvectors_v1 dir> <ACVP ML-DSA-sigVer-FIPS204 internalProjection.json> <external dir>
      Writes the trimmed third-party sets: Wycheproof mldsa_{44,65,87}_verify_test.json without
      publicKeyDer, and the ACVP pure and internal sigVer groups without private keys (HashML-DSA
      groups are dropped: the Access profile has no pre-hash variant).

  python -I ml_dsa.py edges > ../core/1/ml-dsa.json
      Writes the norm and hint edge vectors. Keys come from os.urandom at generation time and are
      never written; only public keys, messages and signatures are. The signer here exists only to
      produce these cases: it can skip the z-norm rejection so a signature that satisfies the
      verification equation still carries ||z|| >= gamma1 - beta, and it re-encodes hints in ways
      a lax decoder would read as the same hint set.
"""

import hashlib
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "reference" / "f0"))

from f0 import mldsa  # noqa: E402
from f0.mldsa import N, Q, D, PARAMS  # noqa: E402


def extract(wycheproof, acvp, out):
    out = pathlib.Path(out)
    for size in ("44", "65", "87"):
        name = f"mldsa_{size}_verify_test.json"
        doc = json.loads((pathlib.Path(wycheproof) / name).read_text())
        for group in doc["testGroups"]:
            group.pop("publicKeyDer", None)
        (out / ("wycheproof-" + name)).write_text(json.dumps(doc, indent=1) + "\n")
    data = json.loads(pathlib.Path(acvp).read_text())
    kept = [g for g in data["testGroups"] if g.get("preHash") != "preHash"]
    fields = ("tcId", "testPassed", "reason", "pk", "message", "mu", "context", "signature")
    doc = {
        "source": "usnistgov/ACVP-Server gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json",
        "algorithm": data["algorithm"],
        "mode": data.get("mode"),
        "revision": data["revision"],
        "groups": [
            {
                **{k: v for k, v in g.items() if k != "tests"},
                "tests": [{k: t[k] for k in fields if k in t} for t in g["tests"]],
            }
            for g in kept
        ],
    }
    (out / "acvp-ml-dsa-sigver-fips204.json").write_text(json.dumps(doc, indent=1) + "\n")


def power2round(r):
    r_plus = r % Q
    r0 = mldsa.mod_pm(r_plus, 1 << D)
    return (r_plus - r0) >> D, r0


def coeff_from_half_byte(b, eta):
    if eta == 2 and b < 15:
        return 2 - (b % 5)
    if eta == 4 and b < 9:
        return 4 - b
    return None


def rej_bounded_poly(seed, eta):
    stream = mldsa.shake256(seed, 4096)
    out = []
    for byte in stream:
        for half in (byte & 15, byte >> 4):
            c = coeff_from_half_byte(half, eta)
            if c is not None and len(out) < N:
                out.append(c % Q)
        if len(out) == N:
            return out
    raise ValueError("stream too short")


def keygen(name, xi):
    p = PARAMS[name]
    seed = mldsa.shake256(xi + bytes([p["k"], p["l"]]), 128)
    rho, rho_prime, key = seed[:32], seed[32:96], seed[96:]
    a_hat = mldsa.expand_a(rho, p)
    s1 = [rej_bounded_poly(rho_prime + r.to_bytes(2, "little"), p["eta"]) for r in range(p["l"])]
    s2 = [rej_bounded_poly(rho_prime + (r + p["l"]).to_bytes(2, "little"), p["eta"]) for r in range(p["k"])]
    s1_hat = [mldsa.ntt(x) for x in s1]
    t = []
    for r in range(p["k"]):
        acc = [0] * N
        for s in range(p["l"]):
            acc = mldsa.add(acc, mldsa.pointwise(a_hat[r][s], s1_hat[s]))
        t.append(mldsa.add(mldsa.ntt_inverse(acc), s2[r]))
    t1 = [[power2round(x)[0] for x in poly] for poly in t]
    t0 = [[power2round(x)[1] % Q for x in poly] for poly in t]
    pk = rho + b"".join(mldsa.pack(poly, 10) for poly in t1)
    return dict(name=name, p=p, pk=pk, a_hat=a_hat, s1=s1, s2=s2, t0=t0, key=key, tr=mldsa.shake256(pk, 64))


def expand_mask(rho2, kappa, p):
    width = mldsa.z_bits(p)
    return [
        [(p["gamma1"] - v) % Q for v in mldsa.unpack(mldsa.shake256(rho2 + (kappa + r).to_bytes(2, "little"), 32 * width), width)]
        for r in range(p["l"])
    ]


def mul_ntt(c_hat, polys):
    return [mldsa.ntt_inverse(mldsa.pointwise(c_hat, mldsa.ntt(x))) for x in polys]


def hint_pack(h, p):
    y = [0] * (p["omega"] + p["k"])
    index = 0
    for i, poly in enumerate(h):
        for j, bit in enumerate(poly):
            if bit:
                y[index] = j
                index += 1
        y[p["omega"] + i] = index
    return y


def sig_encode(ctilde, z, y, p):
    width = mldsa.z_bits(p)
    body = b"".join(mldsa.pack([(p["gamma1"] - mldsa.centered(x)) for x in poly], width) for poly in z)
    return ctilde + body + bytes(y)


def sign(sk, m_prime, accept):
    """Algorithm 7 with randomised rnd. `accept(z_norm)` replaces the z-norm rejection."""
    p = sk["p"]
    mu = mldsa.shake256(sk["tr"] + m_prime, 64)
    rho2 = mldsa.shake256(sk["key"] + os.urandom(32) + mu, 64)
    kappa = 0
    while True:
        y = expand_mask(rho2, kappa, p)
        kappa += p["l"]
        w = []
        for r in range(p["k"]):
            acc = [0] * N
            for s in range(p["l"]):
                acc = mldsa.add(acc, mldsa.pointwise(sk["a_hat"][r][s], mldsa.ntt(y[s])))
            w.append(mldsa.ntt_inverse(acc))
        w1 = [[mldsa.high_bits(x, p["gamma2"]) for x in poly] for poly in w]
        ctilde = mldsa.shake256(mu + mldsa.w1_encode(w1, p), p["ctilde"])
        c_hat = mldsa.ntt(mldsa.sample_in_ball(ctilde, p))
        cs1 = mul_ntt(c_hat, sk["s1"])
        cs2 = mul_ntt(c_hat, sk["s2"])
        z = [mldsa.add(a, b) for a, b in zip(y, cs1)]
        if any(not (-p["gamma1"] < mldsa.centered(x) <= p["gamma1"]) for poly in z for x in poly):
            continue
        if not accept(mldsa.infinity_norm(z)):
            continue
        w_cs2 = [mldsa.sub(a, b) for a, b in zip(w, cs2)]
        if mldsa.infinity_norm([[mldsa.low_bits(x, p["gamma2"]) for x in poly] for poly in w_cs2]) >= p["gamma2"] - p["beta"]:
            continue
        ct0 = mul_ntt(c_hat, sk["t0"])
        if mldsa.infinity_norm(ct0) >= p["gamma2"]:
            continue
        h = [
            [
                int(mldsa.high_bits((a + b) % Q, p["gamma2"]) != mldsa.high_bits(a, p["gamma2"]))
                for a, b in zip(w_cs2[i], ct0[i])
            ]
            for i in range(p["k"])
        ]
        if sum(map(sum, h)) > p["omega"]:
            continue
        return sig_encode(ctilde, z, hint_pack(h, p), p), h


def pure(message, context=b""):
    return bytes([0, len(context)]) + context + message


def case(cid, name, pk, message, sig, result, reason):
    return {
        "id": cid,
        "algorithm": name,
        "public_key": pk.hex(),
        "message": message.hex(),
        "signature": sig.hex(),
        "result": result,
        "reason": reason,
    }


def hint_offset(p):
    return p["ctilde"] + 32 * mldsa.z_bits(p) * p["l"]


def edges():
    cases = []
    for name in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        tag = name.lower().replace("ml-dsa-", "")
        sk = keygen(name, os.urandom(32))
        p, pk = sk["p"], sk["pk"]
        bound = p["gamma1"] - p["beta"]
        message = os.urandom(32)
        while True:
            sig, h = sign(sk, pure(message), lambda norm: norm < bound)
            if any(sum(poly) >= 2 for poly in h) and sum(map(sum, h)) < p["omega"]:
                break
        assert mldsa.verify(name, pk, message, sig)
        cases.append(case(f"{tag}-valid", name, pk, message, sig, "accept", "ok"))
        cases.append(case(f"{tag}-empty-message", name, pk, b"", sign(sk, pure(b""), lambda n: n < bound)[0], "accept", "ok"))

        over, _ = sign(sk, pure(message), lambda norm: norm >= bound)
        assert not mldsa.verify(name, pk, message, over)
        cases.append(case(f"{tag}-z-norm-above-bound", name, pk, message, over, "reject", "z_norm"))
        if name != "ML-DSA-87":
            exact, _ = sign(sk, pure(message), lambda norm: norm == bound)
            cases.append(case(f"{tag}-z-norm-at-bound", name, pk, message, exact, "reject", "z_norm"))

        at = hint_offset(p)
        y = list(sig[at:])
        omega, k = p["omega"], p["k"]
        poly = next(i for i in range(k) if (y[omega + i] - (y[omega + i - 1] if i else 0)) >= 2)
        first = y[omega + poly - 1] if poly else 0

        swapped = list(y)
        swapped[first], swapped[first + 1] = swapped[first + 1], swapped[first]
        cases.append(case(f"{tag}-hint-unsorted", name, pk, message, sig[:at] + bytes(swapped), "reject", "hint_order"))

        duplicate = list(y)
        total = y[omega + k - 1]
        duplicate[first + 1: total + 1] = [y[first]] + y[first + 1: total]
        for i in range(poly, k):
            duplicate[omega + i] += 1
        cases.append(case(f"{tag}-hint-duplicate", name, pk, message, sig[:at] + bytes(duplicate), "reject", "hint_order"))

        trailing = list(y)
        trailing[omega - 1] = 1
        cases.append(case(f"{tag}-hint-trailing-nonzero", name, pk, message, sig[:at] + bytes(trailing), "reject", "hint_padding"))

        over_omega = list(y)
        over_omega[omega + k - 1] = omega + 1
        cases.append(case(f"{tag}-hint-count-above-omega", name, pk, message, sig[:at] + bytes(over_omega), "reject", "hint_count"))

        decreasing = list(y)
        if k >= 2 and y[omega] > 0:
            decreasing[omega + 1] = y[omega] - 1
            cases.append(case(f"{tag}-hint-count-decreasing", name, pk, message, sig[:at] + bytes(decreasing), "reject", "hint_count"))

        cases.append(case(f"{tag}-ctilde-short", name, pk, message, sig[1:], "reject", "length"))
        cases.append(case(f"{tag}-ctilde-long", name, pk, message, sig[:1] + sig, "reject", "length"))
        cases.append(case(f"{tag}-truncated", name, pk, message, sig[:-1], "reject", "length"))
        cases.append(case(f"{tag}-trailing-byte", name, pk, message, sig + b"\x00", "reject", "length"))
        cases.append(case(f"{tag}-key-truncated", name, pk[:-1], message, sig, "reject", "length"))
        flipped = bytearray(sig)
        flipped[0] ^= 1
        cases.append(case(f"{tag}-ctilde-bit-flip", name, pk, message, bytes(flipped), "reject", "equation"))
        cases.append(case(f"{tag}-other-message", name, pk, os.urandom(32), sig, "reject", "equation"))

        ctx_sig, _ = sign(sk, pure(message, b"access"), lambda n: n < bound)
        assert mldsa.verify(name, pk, message, ctx_sig, b"access")
        cases.append(case(f"{tag}-nonempty-context", name, pk, message, ctx_sig, "reject", "context"))
        internal, _ = sign(sk, message, lambda n: n < bound)
        assert mldsa.verify_internal(name, pk, message, internal)
        cases.append(case(f"{tag}-internal-interface", name, pk, message, internal, "reject", "context"))
        sha256_oid = bytes.fromhex("0609608648016503040201")
        prehash, _ = sign(sk, bytes([1, 0]) + sha256_oid + hashlib.sha256(message).digest(), lambda n: n < bound)
        cases.append(case(f"{tag}-hash-ml-dsa", name, pk, message, prehash, "reject", "context"))
    for c in cases:
        got = mldsa.verify(c["algorithm"], bytes.fromhex(c["public_key"]), bytes.fromhex(c["message"]), bytes.fromhex(c["signature"]))
        assert got == (c["result"] == "accept"), c["id"]
    doc = {
        "rule": "CR-51",
        "track": "core",
        "version": 1,
        "operation": "verify.ml_dsa",
        "rules": ["CR-41", "CR-51", "SAI-44"],
        "source": "conformance/vectors/tools/ml_dsa.py edges: norm and hint edge vectors under the Access profile (pure ML-DSA, empty context); Crucible is a test harness without a published vector set, so these replace it (OP-159 m.3 (n))",
        "cases": cases,
    }
    json.dump(doc, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["extract"] and len(sys.argv) == 5:
        extract(*sys.argv[2:])
    elif sys.argv[1:] == ["edges"]:
        edges()
    else:
        sys.exit(__doc__)
