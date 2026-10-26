"""Independent reference for conformance/vectors/core/1/record-fold.json (L2-REC-2, L2-REC-3).

Usage: python -I fold.py > core/1/record-fold.json
       python -I fold.py --check core/1/record-fold.json
"""

import json
import sys

import cbor2


def enc(v):
    return cbor2.dumps(v, canonical=True)


DOMAIN = [-16, bytes([7]) * 32]
PREV = [-16, bytes([8]) * 32]


def record(pos, kind, fields):
    out = {"domain": DOMAIN, "pos": pos, "kind": kind, "recorded_at": 1000 + pos, "prev": PREV}
    out["fields"] = dict(fields)
    out["field_salt"] = {n: bytes([pos]) * 32 for n in fields}
    return enc(out)


def decision(pos, outcome, effects=None):
    fields = {"outcome": {"outcome": outcome}}
    if effects is not None:
        fields["effects"] = effects
    return record(pos, "decision", fields)


class Reject(Exception):
    pass


def fold(records):
    state = {}
    for i, raw in enumerate(records):
        rec = cbor2.loads(raw)
        if rec["pos"] != i + 1:
            raise Reject("order")
        fields = rec["fields"]
        effects = fields.get("effects")
        if rec["kind"] != "decision":
            if effects is not None:
                raise Reject("effects-outside-decision")
            continue
        outcome = fields.get("outcome")
        if not isinstance(outcome, dict) or outcome.get("outcome") not in ("allow", "deny", "require_action"):
            raise Reject("outcome")
        if effects is None:
            continue
        if outcome["outcome"] != "allow":
            raise Reject("effects-without-allow")
        if not isinstance(effects, list) or not effects:
            raise Reject("effect")
        seen = set()
        for e in effects:
            if not isinstance(e, list) or len(e) not in (1, 2) or not isinstance(e[0], bytes) or not 1 <= len(e[0]) <= 512:
                raise Reject("effect")
            if e[0] in seen:
                raise Reject("duplicate-effect")
            seen.add(e[0])
            state[e[0]] = (enc(e[1]) if len(e) == 2 else None, rec["pos"])
    return [[k.hex(), None if v is None else v.hex(), p] for k, (v, p) in sorted(state.items())]


CASES = [
    ("empty", []),
    ("set-overwrite-remove", [
        decision(1, "allow", [[b"k1", 1], [b"k2", "a"]]),
        decision(2, "deny"),
        decision(3, "allow", [[b"k1", 2]]),
        decision(4, "allow", [[b"k2"]]),
        record(5, "claim", {"class": "email"}),
        record(6, "opening", {"nonce": b"n"}),
    ]),
    ("keys-sorted-by-bytes", [decision(1, "allow", [[b"a", 1], [b"\x00\x02", 2], [b"\x01", {"x": [1, 2]}]])]),
    ("allow-without-effects", [decision(1, "allow")]),
    ("effects-on-deny", [decision(1, "deny", [[b"k", 1]])]),
    ("effects-on-require-action", [decision(1, "require_action", [[b"k", 1]])]),
    ("effects-on-claim", [record(1, "claim", {"effects": [[b"k", 1]]})]),
    ("duplicate-key", [decision(1, "allow", [[b"k", 1], [b"k", 2]])]),
    ("key-empty", [decision(1, "allow", [[b"", 1]])]),
    ("key-too-long", [decision(1, "allow", [[b"k" * 513, 1]])]),
    ("key-longest", [decision(1, "allow", [[b"k" * 512, 1]])]),
    ("key-not-bytes", [decision(1, "allow", [["k", 1]])]),
    ("effect-three-items", [decision(1, "allow", [[b"k", 1, 2]])]),
    ("effect-empty", [decision(1, "allow", [[]])]),
    ("remove-absent-key", [decision(1, "allow", [[b"k"]])]),
    ("outcome-unknown", [record(1, "decision", {"outcome": {"outcome": "maybe"}})]),
    ("effects-empty", [decision(1, "allow", [])]),
    ("decision-without-outcome", [record(1, "decision", {"effects": [[b"k", 1]]})]),
    ("positions-not-consecutive", [decision(1, "allow", [[b"k", 1]]), decision(3, "allow", [[b"k", 2]])]),
    ("first-position-not-1", [decision(2, "allow", [[b"k", 1]])]),
]


def build():
    cases = []
    for case_id, records in CASES:
        case = {"id": case_id, "rules": ["L2-REC-2", "L2-REC-3"], "records": [r.hex() for r in records]}
        try:
            case["state"] = fold(records)
        except Reject as e:
            case["rejection"] = str(e)
        cases.append(case)
    return {"track": "core", "version": 1, "operation": "record.fold", "rule": "L2-REC-2, L2-REC-3", "cases": cases}


if __name__ == "__main__":
    doc = build()
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        with open(sys.argv[2]) as f:
            if json.load(f) != doc:
                sys.exit(f"{sys.argv[2]} differs from the reference")
    else:
        json.dump(doc, sys.stdout, indent=1)
        sys.stdout.write("\n")
