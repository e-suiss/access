import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from f0 import ed25519
from f0.algebra import child_within_parent
from f0.codec import Rejection, decode_canonical, decode_canonical_authority, decode_subject_selector, encode
from f0.combinator import evaluate_bytes
from f0.cose import CoseError, verify_sign1
from f0.keyscope import KeyScopeError, check_public_key, operational_key


def run_evaluate(case, document):
    fuel = case.get("fuel", document.get("fuel", 10000))
    try:
        got = evaluate_bytes(bytes.fromhex(case["input"]), fuel)
    except Rejection as rejection:
        return {"rejection": rejection.kind}, rejection.reason
    return {"decision": got.hex()}, None


def run_child_within_parent(case, document):
    try:
        child = decode_canonical_authority(bytes.fromhex(case["child"]))
        parent = decode_canonical_authority(bytes.fromhex(case["parent"]))
        holder = decode_subject_selector(bytes.fromhex(case["holder"]))
    except Rejection as rejection:
        return {"rejection": rejection.kind}, rejection.reason
    return {"within": child_within_parent(child, parent, holder, {})}, None


def load_keys(table):
    keys = {}
    for kid, encoded in table.items():
        key = decode_canonical(bytes.fromhex(encoded))
        check_public_key(key)
        keys[bytes.fromhex(kid)] = key
    return keys


def run_cose_sign1(case, document):
    keys = load_keys(document["keys"])
    try:
        kid, payload = verify_sign1(
            bytes.fromhex(case["sign1"]), document["content_type"], document["allowed"], keys
        )
    except CoseError as error:
        return {"error": error.name}, None
    return {"kid": kid.hex(), "payload": payload.hex()}, None


def run_operational_key(case, document):
    try:
        key = operational_key(
            bytes.fromhex(case["metadata"]),
            bytes.fromhex(case["domain"]),
            bytes.fromhex(case["excerpt"]),
            case["usage"],
            case["iat"],
        )
    except KeyScopeError as error:
        return {"error": error.name}, None
    return {"key": encode(key).hex()}, None


def run_ed25519(case, document):
    result, reason = ed25519.verify(
        bytes.fromhex(case["public_key"]), bytes.fromhex(case["message"]), bytes.fromhex(case["signature"])
    )
    return {"result": result}, reason


OPERATIONS = {
    "combinator.evaluate": (run_evaluate, ("decision", "rejection")),
    "algebra.child_within_parent": (run_child_within_parent, ("within", "rejection")),
    "verify.cose_sign1": (run_cose_sign1, ("kid", "payload", "error")),
    "key_scope.operational_key": (run_operational_key, ("key", "error")),
    "verify.ed25519": (run_ed25519, ("result",)),
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
    passed = {}
    failures = []
    for path in sorted(pathlib.Path(sys.argv[1]).rglob("*.json")):
        document, cases = load_cases(path)
        for case in cases:
            operation = case.get("operation", document.get("operation"))
            if operation not in OPERATIONS:
                continue
            runner, fields = OPERATIONS[operation]
            expected = {field: case[field] for field in fields if field in case}
            got, reason = runner(case, document)
            if got == expected:
                passed[path] = passed.get(path, 0) + 1
            else:
                failures.append((path, case.get("id"), expected, got, reason))
    for path, case_id, expected, got, reason in failures:
        print(f"FAIL {path} {case_id}")
        print(f"  expected: {expected}")
        print(f"  got:      {got}" + (f" ({reason})" if reason else ""))
    for path in sorted(set(passed) | {failure[0] for failure in failures}):
        failed_here = sum(1 for failure in failures if failure[0] == path)
        print(f"  {path}: {passed.get(path, 0)} passed, {failed_here} failed")
    print(f"{sum(passed.values())} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
