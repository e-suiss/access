"""Independent RFC 9162 reference used to generate conformance/vectors/core/1/merkle.json (OP-106 m.23, m.24)."""

import hashlib
import json
import sys

LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]


def h(b):
    return hashlib.sha256(b).digest()


def mth(d):
    if not d:
        return h(b"")
    if len(d) == 1:
        return h(b"\x00" + d[0])
    k = 1
    while k * 2 < len(d):
        k *= 2
    return h(b"\x01" + mth(d[:k]) + mth(d[k:]))


def path(m, d):
    if len(d) <= 1:
        return []
    k = 1
    while k * 2 < len(d):
        k *= 2
    if m < k:
        return path(m, d[:k]) + [mth(d[k:])]
    return path(m - k, d[k:]) + [mth(d[:k])]


def subproof(m, d, b):
    n = len(d)
    if m == n:
        return [] if b else [mth(d)]
    k = 1
    while k * 2 < n:
        k *= 2
    if m <= k:
        return subproof(m, d[:k], b) + [mth(d[k:])]
    return subproof(m - k, d[k:], False) + [mth(d[:k])]


def main():
    data = [bytes.fromhex(x) for x in LEAVES]
    out = {
        "rule": "OP-106 m.12, m.18",
        "track": "core",
        "version": 1,
        "operation": "digest.merkle",
        "leaves": LEAVES,
        "roots": [{"size": n, "root": mth(data[:n]).hex()} for n in range(0, len(data) + 1)],
        "inclusion": [
            {"index": i, "size": n, "path": [p.hex() for p in path(i, data[:n])]}
            for n in range(1, len(data) + 1)
            for i in range(n)
        ],
        "consistency": [
            {"first": m, "second": n, "path": [p.hex() for p in subproof(m, data[:n], True)]}
            for n in range(1, len(data) + 1)
            for m in range(1, n + 1)
        ],
    }
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


main()
