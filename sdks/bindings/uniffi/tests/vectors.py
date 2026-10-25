# OP-116 m.6
"""Core conformance vectors through the uniffi Python binding.

Usage: python3 -I vectors.py <directory with the generated module and library>
"""

import base64
import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, sys.argv.pop(1))

import access_kernel_uniffi as k

VECTORS = pathlib.Path(__file__).resolve().parents[4] / "conformance" / "vectors" / "core" / "1"
COUNTS = {}


def load(name):
    return json.loads((VECTORS / name).read_text())


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    raise ValueError("length out of range for this test encoder")


def bstr(b):
    return head(2, len(b)) + b


def tstr(s):
    b = s.encode()
    return head(3, len(b)) + b


def cbor_map(entries):
    entries = sorted(entries, key=lambda e: e[0])
    return head(5, len(entries)) + b"".join(k + v for k, v in entries)


def key_set(keys, allowed):
    algs = sorted(head(1, -1 - a) for a in allowed)
    return cbor_map([
        (tstr("keys"), cbor_map([(bstr(kid), key) for kid, key in keys])),
        (tstr("allowed"), head(4, len(algs)) + b"".join(algs)),
    ])


def b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jose_keys(v):
    keys = []
    for kid, key in v["keys"].items():
        raw = b64url(key)
        keys.append((b64url(kid), cbor_map([(tstr("ed25519" if len(raw) == 32 else "p256"), bstr(raw))])))
    return keys


def outcome(f):
    try:
        return ("ok", f())
    except k.KernelError as e:
        return ("error", str(e))


class Vectors(unittest.TestCase):
    def count(self, name, n):
        COUNTS[name] = COUNTS.get(name, 0) + n

    def test_decision(self):
        v = load("decision.json")
        for c in v["cases"]:
            got = outcome(lambda: k.evaluate(bytes.fromhex(c["input"]), c.get("fuel", v["fuel"])).hex())
            want = ("ok", c["decision"]) if "decision" in c else ("error", c["rejection"])
            self.assertEqual(got, want, c["id"])
        self.count("decision.json", len(v["cases"]))

    def test_cve_regressions(self):
        v = load("cve-regressions.json")
        for c in v["cases"]:
            if c["operation"] == "combinator.evaluate":
                got = k.evaluate(bytes.fromhex(c["input"]), v["fuel"]).hex()
                self.assertEqual(got, c["decision"], c["id"])
            else:
                got = k.child_within_parent(
                    bytes.fromhex(c["child"]),
                    bytes.fromhex(c["parent"]),
                    bytes.fromhex(c["holder"]),
                    b"\xa0",
                )
                self.assertEqual(got, c["within"], c["id"])
        self.count("cve-regressions.json", len(v["cases"]))

    def test_cose(self):
        v = load("cose.json")
        keys = key_set([(bytes.fromhex(kid), bytes.fromhex(key)) for kid, key in v["keys"].items()], v["allowed"])
        for c in v["cases"]:
            got = outcome(lambda: k.verify_cose_sign1(bytes.fromhex(c["sign1"]), keys, v["content_type"]))
            if "error" in c:
                want = ("error", c["error"])
            else:
                want = ("ok", cbor_map([
                    (tstr("kid"), bstr(bytes.fromhex(c["kid"]))),
                    (tstr("payload"), bstr(bytes.fromhex(c["payload"]))),
                ]))
            self.assertEqual(got, want, c["id"])
        self.count("cose.json", len(v["cases"]))

    def test_key_scope(self):
        v = load("key-scope.json")
        for c in v["cases"]:
            got = outcome(lambda: k.operational_key(
                bytes.fromhex(c["metadata"]),
                bytes.fromhex(c["domain"]),
                bytes.fromhex(c["excerpt"]),
                c["usage"],
                c["iat"],
            ).hex())
            want = ("error", c["error"]) if "error" in c else ("ok", c["key"])
            self.assertEqual(got, want, c["id"])
        self.count("key-scope.json", len(v["cases"]))

    def test_jose_attack_classes(self):
        v = load("jose-attack-classes.json")
        keys = []
        for kid, key in v["keys"].items():
            raw = b64url(key)
            keys.append((b64url(kid), cbor_map([(tstr("ed25519" if len(raw) == 32 else "p256"), bstr(raw))])))
        for c in v["cases"]:
            ks = key_set(keys, c.get("allowed", v["allowed"]))
            got = outcome(lambda: k.verify_jws_compact(
                c["token"], ks, v["typ"], "https://access.example", "pep:shop", 1_500_000, 60_000
            ))
            self.assertEqual("accept" if got[0] == "ok" else "reject: " + got[1], c["expect"], c["id"])
        self.count("jose-attack-classes.json", len(v["cases"]))

    # OP-122 m.7
    def test_jwt_claims(self):
        v = load("jwt-claims.json")
        ks = key_set(jose_keys(v), v["allowed"])
        for c in v["cases"]:
            ctx = c.get("claims", v["claims"])
            got = outcome(lambda: k.verify_jws_compact(
                c["token"], ks, v["typ"], ctx["issuer"], ctx["audience"], ctx["now"], ctx["skew_ms"]
            ))
            self.assertEqual("accept" if got[0] == "ok" else "reject: " + got[1], c["expect"], c["id"])
        self.count("jwt-claims.json", len(v["cases"]))

    # OP-122 m.7
    def test_sd_jwt(self):
        v = load("sd-jwt.json")
        ks = key_set(jose_keys(v), v["allowed"])
        ctx = v["context"]
        for c in v["cases"]:
            got = outcome(lambda: json.loads(k.verify_sd_jwt(
                c["presentation"], ks, ctx["typ"], ctx["audience"], ctx["nonce"], ctx["now"], ctx["skew_ms"]
            )))
            want = ("ok", c["claims"]) if "claims" in c else ("error", c["error"])
            self.assertEqual(got, want, c["id"])
        self.count("sd-jwt.json", len(v["cases"]))

    # OP-118 m.4, OP-122 m.6
    def test_validity(self):
        v = load("validity.json")
        for c in v["cases"]:
            got = outcome(lambda: k.check_validity(
                bytes.fromhex(c.get("contract", v["contract"])), c["now"], v["audience"], [],
                c.get("last_refresh"), c.get("online", v["online"]), v["skew_ms"], c["iat"], c["horizon_cap_ms"],
            ))
            want = ("error", c["error"]) if "error" in c else ("ok", None)
            self.assertEqual(got, want, c["id"])
        self.count("validity.json", len(v["cases"]))

    def test_merkle(self):
        v = load("merkle.json")
        roots = {r["size"]: bytes.fromhex(r["root"]) for r in v["roots"]}

        def path(c):
            return b"".join(bytes.fromhex(p) for p in c["path"])

        for c in v["inclusion"]:
            leaf = hashlib.sha256(b"\x00" + bytes.fromhex(v["leaves"][c["index"]])).digest()
            ok = k.verify_inclusion(c["index"], c["size"], leaf, path(c), roots[c["size"]])
            self.assertTrue(ok, (c["index"], c["size"]))
        for c in v["consistency"]:
            ok = k.verify_consistency(c["first"], c["second"], roots[c["first"]], roots[c["second"]], path(c))
            self.assertTrue(ok, (c["first"], c["second"]))
        self.assertEqual(outcome(lambda: k.verify_inclusion(0, 1, bytes(31), b"", roots[1])), ("error", "input"))
        self.count("merkle.json", len(v["inclusion"]) + len(v["consistency"]))

    def test_errors_cross_as_stable_names(self):
        first = bytes.fromhex(load("decision.json")["cases"][0]["input"])
        self.assertEqual(outcome(lambda: k.evaluate(first, 1_000_001)), ("error", "input"))
        self.assertEqual(outcome(lambda: k.evaluate(first, 0)), ("error", "fuel"))
        with self.assertRaises(k.KernelError.Fuel):
            k.evaluate(first, 0)
        empty = b"\xa0"
        self.assertEqual(outcome(lambda: k.intent_digest(empty)), ("error", "input"))
        self.assertEqual(outcome(lambda: k.verify_metadata(empty, empty)), ("error", "input"))
        self.assertEqual(
            outcome(lambda: k.check_validity(empty, 0, "pep:shop", [], None, True, 60_000, 0, 0)), ("error", "input")
        )
        ed = cbor_map([(tstr("ed25519"), bstr(b64url("6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw")))])
        keys = key_set([(bytes([1]) * 32, ed)], [-19])
        self.assertEqual(
            outcome(lambda: k.verify_sd_jwt("x", keys, "t", "a", "n", 0, 0)),
            ("error", "not an SD-JWT presentation"),
        )
        self.assertEqual(k.api_version(), "0.0")


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=1).result
    print("vector cases:", COUNTS, "total", sum(COUNTS.values()))
    sys.exit(0 if result.wasSuccessful() else 1)
