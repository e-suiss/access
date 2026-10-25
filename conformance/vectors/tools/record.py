"""Independent reference for conformance/vectors/core/1/record.json (§17.6.1, OP-106 m.10-m.15, m.23, m.24).

Usage: python -I record.py > core/1/record.json
       python -I record.py --check core/1/record.json
"""

import hashlib
import json
import sys

import cbor2


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


def enc(v):
    return cbor2.dumps(v, canonical=True)


def tagged(raw):
    return [-16, raw]


def salt(n):
    return bytes([n]) * 32


def commitment(name, value, s):
    return h(b"\x02" + s + enc([name, value]))


def field_root(commitments):
    names = sorted(commitments, key=lambda n: n.encode())
    return mth([commitments[n] for n in names])


def header(rec):
    return {k: rec[k] for k in ("domain", "pos", "kind", "recorded_at", "prev") if k in rec}


def leaf_core(rec, commitments):
    core = header(rec)
    core["field_root"] = field_root(commitments)
    return core


def envelope(rec, fields):
    out = header(rec)
    out["fields"] = {n: v for n, (v, _) in fields.items()}
    out["field_salt"] = {n: s for n, (_, s) in fields.items()}
    return out


def record_case(case_id, rec, fields):
    env = envelope(rec, fields)
    commitments = {n: commitment(n, v, s) for n, (v, s) in fields.items()}
    core = leaf_core(rec, commitments)
    core_bytes = enc(core)
    domain = rec.get("domain") or tagged(h(b"access/genesis/v1\x00" + enc(env)))
    case = {
        "id": case_id,
        "cbor": enc(env).hex(),
        "commitments": {n: c.hex() for n, c in sorted(commitments.items())},
        "field_root": core["field_root"].hex(),
        "leaf_core": core_bytes.hex(),
        "leaf_hash": h(b"\x00" + core_bytes).hex(),
        "domain": enc(domain).hex(),
    }
    return case, core_bytes, domain, commitments


def disclosure(rec, fields, commitments, opened):
    out = header(rec)
    shown = {n: f for n, f in fields.items() if n in opened}
    if shown:
        out["fields"] = {n: v for n, (v, _) in shown.items()}
        out["field_salt"] = {n: s for n, (_, s) in shown.items()}
    hidden = {n: tagged(c) for n, c in commitments.items() if n not in opened}
    if hidden:
        out["withheld"] = hidden
    return out


# TI-RT12
RULES = {
    "genesis": ["L0-ENC-22", "L0-ENC-25", "L0-ENC-26", "L0-ENC-27", "L0-ENC-28", "L0-ENC-29", "L2-DIG-1"],
    "opening-name-order": ["L0-ENC-21", "L0-ENC-26", "L0-ENC-27", "L0-ENC-28", "L0-ENC-29"],
    "decision": ["L0-ENC-26", "L0-ENC-28", "L0-ENC-29", "L0-ENC-29d"],
    "claim": ["L0-ENC-26", "L0-ENC-29", "L0-ENC-29d"],
    "decision-artifacts-only": ["L0-ENC-29c", "L0-ENC-29d", "L0-ENC-31"],
    "decision-all-withheld": ["L0-ENC-29c", "L0-ENC-29d", "L0-ENC-31"],
    "decision-all-opened": ["L0-ENC-29c", "L0-ENC-29d", "L0-ENC-31"],
    "salt-missing": ["L0-ENC-28", "L0-ENC-29b"],
    "salt-extra": ["L0-ENC-28", "L0-ENC-29b"],
    "salt-short": ["L0-ENC-28", "L0-ENC-29b"],
    "genesis-with-domain": ["L0-ENC-27", "L0-ENC-29b"],
    "genesis-with-prev": ["L0-ENC-27", "L0-ENC-29b"],
    "genesis-not-first": ["L0-ENC-29b"],
    "record-without-domain": ["L0-ENC-27", "L0-ENC-29b"],
    "record-without-prev": ["L0-ENC-27", "L0-ENC-29b"],
    "position-0-not-genesis": ["L0-ENC-29b"],
    "kind-unknown": ["L0-ENC-9", "L0-ENC-26"],
    "field-unknown": ["L0-ENC-9"],
    "withheld-in-envelope": ["L0-ENC-9", "L0-ENC-29c"],
    "field-name-not-ident": ["L0-ENC-29b"],
    "fields-empty": ["L0-ENC-29b"],
    "fields-missing": ["L0-ENC-29b"],
    "prev-not-sha256": ["L0-ENC-20"],
    "not-canonical": ["L0-ENC-1"],
    "disclosure-opened-and-withheld": ["L0-ENC-29c"],
    "disclosure-empty": ["L0-ENC-29c"],
    "disclosure-withheld-untagged": ["L0-ENC-21", "L0-ENC-29c"],
}

SCHEMA = tagged(bytes([9]) * 32)
VERSIONS = {"core": 1, "meta_schema": 1}


def main():
    genesis = {"pos": 0, "kind": "genesis", "recorded_at": 1_767_225_600_000}
    genesis_fields = {
        "root_terms": ({"anchor": bytes([1]) * 16, "quorum": 1}, salt(0x11)),
        "versions": (VERSIONS, salt(0x12)),
    }
    g_case, g_core, domain, _ = record_case("genesis", genesis, genesis_fields)

    opening = {
        "domain": domain,
        "pos": 1,
        "kind": "opening",
        "recorded_at": 1_767_225_600_000,
        "prev": tagged(h(b"\x00" + g_core)),
    }
    opening_fields = {
        "z": ("last by name, first on the wire", salt(0x21)),
        "ab": (-1, salt(0x22)),
    }
    o_case, o_core, _, _ = record_case("opening-name-order", opening, opening_fields)

    decision = {
        "domain": domain,
        "pos": 2,
        "kind": "decision",
        "recorded_at": 1_767_225_601_500,
        "prev": tagged(h(b"\x00" + o_core)),
    }
    decision_fields = {
        "artifacts": ([tagged(bytes([4]) * 32)], salt(0x31)),
        "basis": ({"hops": [bytes([5]) * 16, bytes([6]) * 16]}, salt(0x32)),
        "consumption": ([], salt(0x33)),
        "outcome": ("allow", salt(0x34)),
        "versions": ({**VERSIONS, "schemas": [SCHEMA]}, salt(0x35)),
    }
    d_case, d_core, _, d_commitments = record_case("decision", decision, decision_fields)

    claim = {
        "domain": domain,
        "pos": 3,
        "kind": "claim",
        "recorded_at": 1_767_225_601_500,
        "prev": tagged(h(b"\x00" + d_core)),
    }
    claim_fields = {
        "disposition": ("accepted", salt(0x41)),
        "ingest": ({"class": "party_email", "time": 1_767_225_601_500}, salt(0x42)),
    }
    c_case, c_core, _, _ = record_case("claim", claim, claim_fields)

    log = [g_core, o_core, d_core, c_core]
    log_root = mth(log)

    disclosures = []
    for case_id, opened in (
        ("decision-artifacts-only", {"artifacts"}),
        ("decision-all-withheld", set()),
        ("decision-all-opened", set(decision_fields)),
    ):
        disclosures.append(
            {
                "id": case_id,
                "record_disclosure": enc(disclosure(decision, decision_fields, d_commitments, opened)).hex(),
                "leaf_hash": d_case["leaf_hash"],
                "size": len(log),
                "root": log_root.hex(),
                "path": [p.hex() for p in path(2, log)],
            }
        )

    bad_salt = envelope(opening, opening_fields)
    del bad_salt["field_salt"]["ab"]
    extra_salt = envelope(opening, opening_fields)
    extra_salt["field_salt"]["zz"] = salt(0x23)
    short_salt = envelope(opening, opening_fields)
    short_salt["field_salt"]["ab"] = bytes(31)
    genesis_with_domain = envelope({**genesis, "domain": domain}, genesis_fields)
    genesis_with_prev = envelope({**genesis, "prev": opening["prev"]}, genesis_fields)
    genesis_not_first = envelope({**genesis, "pos": 1, "prev": opening["prev"]}, genesis_fields)
    no_domain = envelope({k: v for k, v in opening.items() if k != "domain"}, opening_fields)
    no_prev = envelope({k: v for k, v in opening.items() if k != "prev"}, opening_fields)
    first_not_genesis = envelope({"domain": domain, "pos": 0, "kind": "opening", "recorded_at": 0}, opening_fields)
    unknown_kind = envelope({**opening, "kind": "checkpoint"}, opening_fields)
    unknown_field = {**envelope(opening, opening_fields), "witness": True}
    bad_name = envelope(opening, {"Ab": opening_fields["ab"]})
    empty_fields = {**header(opening), "fields": {}, "field_salt": {}}
    no_fields = header(opening)
    bad_prev = envelope({**opening, "prev": [-44, opening["prev"][1]]}, opening_fields)
    withheld_in_envelope = {**envelope(opening, opening_fields), "withheld": {"q": tagged(bytes(32))}}
    errors = [
        ("salt-missing", enc(bad_salt), "range"),
        ("salt-extra", enc(extra_salt), "range"),
        ("salt-short", enc(short_salt), "range"),
        ("genesis-with-domain", enc(genesis_with_domain), "range"),
        ("genesis-with-prev", enc(genesis_with_prev), "range"),
        ("genesis-not-first", enc(genesis_not_first), "range"),
        ("record-without-domain", enc(no_domain), "range"),
        ("record-without-prev", enc(no_prev), "range"),
        ("position-0-not-genesis", enc(first_not_genesis), "range"),
        ("kind-unknown", enc(unknown_kind), "unknown"),
        ("field-unknown", enc(unknown_field), "unknown"),
        ("withheld-in-envelope", enc(withheld_in_envelope), "unknown"),
        ("field-name-not-ident", enc(bad_name), "range"),
        ("fields-empty", enc(empty_fields), "range"),
        ("fields-missing", enc(no_fields), "missing"),
        ("prev-not-sha256", enc(bad_prev), "shape"),
    ]

    full = disclosure(decision, decision_fields, d_commitments, {"artifacts"})
    overlap = {**full, "withheld": {**full["withheld"], "artifacts": tagged(d_commitments["artifacts"])}}
    empty = header(decision)
    withheld_raw = {**full, "withheld": {**full["withheld"], "basis": d_commitments["basis"]}}
    disclosure_errors = [
        ("disclosure-opened-and-withheld", enc(overlap), "range"),
        ("disclosure-empty", enc(empty), "missing"),
        ("disclosure-withheld-untagged", enc(withheld_raw), "shape"),
    ]

    cases = [g_case, o_case, d_case, c_case]
    cases += disclosures
    cases += [{"id": i, "cbor": b.hex(), "error": e} for i, b, e in errors]
    cases.append({"id": "not-canonical", "data": "a263706f73006161f5", "error": "cbor"})
    cases += [{"id": i, "record_disclosure": b.hex(), "error": e} for i, b, e in disclosure_errors]
    cases = [{"id": c["id"], "rules": RULES[c["id"]], **c} for c in cases]
    return {
        "rule": "OP-106 m.10-m.15, §17.6.1",
        "track": "core",
        "version": 1,
        "operation": "record.envelope",
        "log": {"size": len(log), "root": log_root.hex()},
        "cases": cases,
    }


def render(doc):
    return json.dumps(doc, indent=1) + "\n"


if len(sys.argv) == 3 and sys.argv[1] == "--check":
    with open(sys.argv[2]) as f:
        if f.read() != render(main()):
            print(f"FAIL {sys.argv[2]}: differs from the independent reference")
            sys.exit(1)
    print(f"{sys.argv[2]}: matches the independent reference")
else:
    sys.stdout.write(render(main()))
