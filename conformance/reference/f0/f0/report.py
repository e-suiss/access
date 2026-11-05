"""Offline Exercise Reports, written from L2-RPT-1 to L2-RPT-3."""

import hashlib

from .codec import (
    HASH_ALG_SHA256,
    UINT_MAX,
    Rejection,
    check_digest,
    check_id,
    check_list,
    check_map,
    check_text_in,
    check_time_window,
    check_uint,
    decode_canonical,
    encode,
    fail,
)

CHAIN_CONTEXT = b"access/report-chain/v1"


class ReportError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def check_slice_amount(value):
    check_map(value, {"budget_term": check_digest, "amount": check_uint})


def check_draw(value):
    check_slice_amount(value)
    if value["amount"] < 1:
        fail("a draw is at least 1")


def check_entry(value):
    check_map(value, {
        "intent": check_digest,
        "time": check_uint,
        "outcome": check_text_in("allow", "deny"),
    }, {
        "params": check_digest,
        "clock_evidence": check_digest,
        "drawn": check_list(check_draw, nonempty=True, is_set=True),
        "holder_proof": check_digest,
    })


def check_entries(value):
    if not isinstance(value, list):
        fail("expected an array")
    for item in value:
        check_entry(item)


def check_report(value):
    # L2-RPT-1, §9.12.2
    check_map(value, {
        "verifier": lambda v: check_map(v, {"profile": check_digest}, {"instance": check_id}),
        "projection": lambda v: check_map(v, {"exercise": check_digest, "contract": check_digest}),
        "period": check_time_window,
        "first_seq": check_uint,
        "entries": check_entries,
        "head": check_digest,
        "profile_version": check_uint,
    }, {
        "previous": check_digest,
        "slice_unused": check_list(check_slice_amount, nonempty=True, is_set=True),
    })


def chain_digest(value):
    return [HASH_ALG_SHA256, hashlib.sha256(CHAIN_CONTEXT + b"\x00" + encode(value)).digest()]


def verify(data):
    # L2-RPT-3
    try:
        report = decode_canonical(data)
        check_report(report)
    except Rejection:
        raise ReportError("report-malformed")
    if ("previous" in report) != (report["first_seq"] != 0):
        raise ReportError("report-start")
    if "previous" in report:
        head = report["previous"]
    else:
        # L2-RPT-2
        head = chain_digest([report["projection"]["exercise"], report["projection"]["contract"]])
    seq = report["first_seq"]
    drawn = {}
    period_from, period_until = report["period"]
    for entry in report["entries"]:
        if not period_from <= entry["time"] <= period_until:
            raise ReportError("report-period")
        if entry["outcome"] == "deny" and entry.get("drawn"):
            raise ReportError("report-entry")
        for draw in entry.get("drawn", []):
            key = draw["budget_term"][1]
            drawn[key] = drawn.get(key, 0) + draw["amount"]
            if drawn[key] > UINT_MAX:
                raise ReportError("report-entry")
        head = chain_digest([head, seq, entry])
        seq += 1
        if seq > UINT_MAX:
            raise ReportError("report-chain")
    if encode(head) != encode(report["head"]):
        raise ReportError("report-chain")
    return head[1], seq, sorted(drawn.items(), key=lambda item: encode([HASH_ALG_SHA256, item[0]]))
