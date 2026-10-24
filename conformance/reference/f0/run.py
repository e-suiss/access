import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from f0.algebra import child_within_parent
from f0.codec import Rejection, decode_canonical_authority, decode_subject_selector
from f0.combinator import evaluate_bytes


def run_evaluate(case, fuel):
    try:
        got = evaluate_bytes(bytes.fromhex(case["input"]), fuel)
    except Rejection as rejection:
        return {"rejection": rejection.kind}, rejection.reason
    return {"decision": got.hex()}, None


def run_child_within_parent(case, fuel):
    try:
        child = decode_canonical_authority(bytes.fromhex(case["child"]))
        parent = decode_canonical_authority(bytes.fromhex(case["parent"]))
        holder = decode_subject_selector(bytes.fromhex(case["holder"]))
    except Rejection as rejection:
        return {"rejection": rejection.kind}, rejection.reason
    return {"within": child_within_parent(child, parent, holder, {})}, None


OPERATIONS = {
    "combinator.evaluate": (run_evaluate, ("decision", "rejection")),
    "algebra.child_within_parent": (run_child_within_parent, ("within", "rejection")),
}


def load_cases(path):
    try:
        document = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, []
    if not isinstance(document, dict) or not isinstance(document.get("cases"), list):
        return None, []
    return document, [case for case in document["cases"] if isinstance(case, dict)]


def main():
    if len(sys.argv) != 2:
        print("usage: run.py <vectors dir>", file=sys.stderr)
        return 2
    passed = 0
    failures = []
    for path in sorted(pathlib.Path(sys.argv[1]).rglob("*.json")):
        document, cases = load_cases(path)
        for case in cases:
            operation = case.get("operation", document.get("operation"))
            if operation not in OPERATIONS:
                continue
            runner, fields = OPERATIONS[operation]
            fuel = case.get("fuel", document.get("fuel", 10000))
            expected = {field: case[field] for field in fields if field in case}
            got, reason = runner(case, fuel)
            if got == expected:
                passed += 1
            else:
                failures.append((path, case.get("id"), expected, got, reason))
    for path, case_id, expected, got, reason in failures:
        print(f"FAIL {path} {case_id}")
        print(f"  expected: {expected}")
        print(f"  got:      {got}" + (f" ({reason})" if reason else ""))
    print(f"{passed} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
