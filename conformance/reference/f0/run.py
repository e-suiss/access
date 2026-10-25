import json
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from f0 import codec, dcbor, ed25519, jose, merkle, record, sdjwt, validity
from f0.algebra import child_within_parent
from f0.version import CORE_VERSION, VERSION
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


def run_dcbor_decode(case, document):
    try:
        dcbor.check(bytes.fromhex(case["data"]))
    except dcbor.DecodeError as error:
        return {"error": error.name}, None
    return {"valid": True}, None


JWS_ALLOWED = (-19, -7)


def run_jws_compact(case, document):
    keys = jose.decode_key_set(document["keys"])
    allowed = case.get("allowed", document.get("allowed", JWS_ALLOWED))
    context = case.get("claims", document.get("claims"))
    try:
        if context is None:
            jose.verify_jws(case["token"], keys, allowed, document["typ"])
        else:
            jose.verify_jwt(
                case["token"], keys, allowed, document["typ"],
                context["issuer"], context["audience"], context["now"], context["skew_ms"],
            )
    except jose.JoseError as error:
        return {"expect": f"reject: {error.name}"}, None
    return {"expect": "accept"}, None


def run_sd_jwt(case, document):
    keys = jose.decode_key_set(document["keys"])
    allowed = document.get("allowed", JWS_ALLOWED)
    context = {**document.get("context", {}), **case.get("context", {})}
    try:
        disclosed = sdjwt.verify_sd_jwt(
            case["presentation"], keys, allowed, context["typ"], context["audience"],
            context["nonce"], context["now"], context["skew_ms"],
        )
    except sdjwt.SdJwtError as error:
        return {"error": error.name}, None
    return {"claims": json.loads(sdjwt.disclosed_json(disclosed))}, None


def run_sd_jwt_disclosure(case, document):
    try:
        name, value = sdjwt.decode_disclosure(case["disclosure"])
    except sdjwt.SdJwtError as error:
        return {"error": error.name}, None
    return {
        "digest": sdjwt.digest_of(case["disclosure"]),
        "name": name,
        "value": json.dumps(value, ensure_ascii=False, separators=(",", ":")),
    }, None


def run_validity(case, document):
    given = {**document, **case}
    try:
        validity.check_validity_bytes(
            bytes.fromhex(given["contract"]), given["now"], given["audience"], given.get("understood", []),
            given.get("last_refresh"), given.get("online", False), given["skew_ms"],
            given.get("iat"), given.get("horizon_cap_ms"),
        )
    except Rejection as rejection:
        return {"error": rejection.kind}, rejection.reason
    except validity.ValidityError as error:
        return {"error": error.name}, None
    return {"valid": True}, None


def run_record(case, document):
    try:
        if "record_disclosure" in case:
            disclosure = record.decode_disclosure(bytes.fromhex(case["record_disclosure"]), envelope=False)
            leaf = record.leaf_hash(disclosure)
            # L0-ENC-29d
            included = merkle.verify_inclusion(
                disclosure["pos"], case["size"], leaf, [bytes.fromhex(item) for item in case["path"]],
                bytes.fromhex(case["root"]),
            )
            return {"leaf_hash": leaf.hex(), "included": included}, None
        data = case["cbor"] if "cbor" in case else case["data"]
        envelope = record.decode_disclosure(bytes.fromhex(data), envelope=True)
    except record.RecordError as error:
        return {"error": error.name}, None
    return {
        "commitments": {name: value.hex() for name, value in record.commitments(envelope).items()},
        "field_root": record.field_root(envelope).hex(),
        "leaf_core": encode(record.leaf_core(envelope)).hex(),
        "leaf_hash": record.leaf_hash(envelope).hex(),
        "domain": encode(record.domain_id(envelope)).hex(),
    }, None


def record_expected(case):
    if "record_disclosure" in case and "error" not in case:
        return {"leaf_hash": case["leaf_hash"], "included": True}
    fields = ("commitments", "field_root", "leaf_core", "leaf_hash", "domain", "error")
    return {field: case[field] for field in fields if field in case}


CODEC_SHAPES = {
    "canonical_authority": codec.check_canonical_authority,
    "bound": codec.check_param_bound,
    "subject": codec.check_subject_selector,
    "digest": codec.check_digest,
}


def run_codec_encode(case, document):
    check = CODEC_SHAPES[case["id"].split(".")[0]]
    try:
        value = decode_canonical(bytes.fromhex(case["cbor"]))
        check(value)
    except Rejection as rejection:
        return {"cbor": None}, rejection.reason
    return {"cbor": encode(value).hex()}, None


def merkle_cases(document):
    leaves = [bytes.fromhex(leaf) for leaf in document["leaves"]]
    roots = {entry["size"]: entry["root"] for entry in document["roots"]}
    cases = []
    for entry in document["roots"]:
        got = merkle.tree_hash(leaves[:entry["size"]]).hex()
        cases.append((f"root-{entry['size']}", entry["root"], got))
    for entry in document["inclusion"]:
        index, size = entry["index"], entry["size"]
        ok = merkle.verify_inclusion(
            index, size, merkle.leaf_hash(leaves[index]),
            [bytes.fromhex(item) for item in entry["path"]], bytes.fromhex(roots[size]),
        )
        cases.append((f"inclusion-{index}-{size}", True, ok))
    for entry in document["consistency"]:
        first, second = entry["first"], entry["second"]
        ok = merkle.verify_consistency(
            first, second, bytes.fromhex(roots[first]), bytes.fromhex(roots[second]),
            [bytes.fromhex(item) for item in entry["path"]],
        )
        cases.append((f"consistency-{first}-{second}", True, ok))
    return cases


DOCUMENT_OPERATIONS = {
    "digest.merkle": merkle_cases,
}


OPERATIONS = {
    "dcbor.decode": (run_dcbor_decode, ("valid", "error")),
    "combinator.evaluate": (run_evaluate, ("decision", "rejection")),
    "algebra.child_within_parent": (run_child_within_parent, ("within", "rejection")),
    "verify.cose_sign1": (run_cose_sign1, ("kid", "payload", "error")),
    "key_scope.operational_key": (run_operational_key, ("key", "error")),
    "verify.ed25519": (run_ed25519, ("result",)),
    "verify.jws_compact": (run_jws_compact, ("expect",)),
    "verify.sd_jwt": (run_sd_jwt, ("claims", "error")),
    "verify.sd_jwt.disclosure": (run_sd_jwt_disclosure, ("digest", "name", "value", "error")),
    "validity.check": (run_validity, ("valid", "error")),
    "codec.encode": (run_codec_encode, ("cbor",)),
    "record.envelope": (run_record, record_expected),
}


def load_cases(path):
    try:
        document = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, []
    if not isinstance(document, dict):
        return None, []
    if document.get("operation") in DOCUMENT_OPERATIONS:
        return document, []
    if not isinstance(document.get("cases"), list):
        return None, []
    return document, [case for case in document["cases"] if isinstance(case, dict)]


HERE = pathlib.Path(__file__).resolve().parent
MAX_PRINTED_FAILURES = 100


def frozen_runner(version):
    # RT8, OP-119 m.7
    return HERE / "versions" / f"core-{version}" / "run.py"


def replay_frozen(version, directory, scratch):
    runner = frozen_runner(version)
    if not runner.is_file():
        return 0, [(directory, None, {"f0": f"core version {version}"}, {"f0": "not retained"}, None)]
    summary = pathlib.Path(scratch) / f"core-{version}.json"
    subprocess.run([sys.executable, "-I", str(runner), str(directory), "--summary", str(summary)], check=False)
    counts = json.loads(summary.read_text())
    failures = [(directory, f"#{n}", None, None, "frozen runner") for n in range(counts["failed"])]
    return counts["passed"], failures


def core_version_of(path, root):
    parts = path.relative_to(root).parts
    if len(parts) >= 3 and parts[0] == "core" and parts[1].isdigit():
        return int(parts[1])
    return None


def run_file(path, passed, failures):
    document, cases = load_cases(path)
    if document is not None and document.get("operation") in DOCUMENT_OPERATIONS:
        for case_id, expected, got in DOCUMENT_OPERATIONS[document["operation"]](document):
            if got == expected:
                passed[path] = passed.get(path, 0) + 1
            else:
                failures.append((path, case_id, expected, got, None))
    for case in cases:
        operation = case.get("operation", document.get("operation"))
        if operation not in OPERATIONS:
            continue
        runner, fields = OPERATIONS[operation]
        if callable(fields):
            expected = fields(case)
        else:
            expected = {field: case[field] for field in fields if field in case}
        got, reason = runner(case, document)
        if got == expected:
            passed[path] = passed.get(path, 0) + 1
        else:
            failures.append((path, case.get("id"), expected, got, reason))


def main(argv):
    summary_path = None
    if len(argv) == 4 and argv[2] == "--summary":
        summary_path = pathlib.Path(argv[3])
    elif len(argv) != 2:
        print("usage: run.py <vectors dir> [--summary <file>]", file=sys.stderr)
        return 2
    root = pathlib.Path(argv[1])
    passed = {}
    failures = []
    frozen = set()
    for path in sorted(root.rglob("*.json")):
        version = core_version_of(path, root)
        if version is not None and version != CORE_VERSION:
            frozen.add(version)
            continue
        run_file(path, passed, failures)
    with tempfile.TemporaryDirectory() as scratch:
        for version in sorted(frozen):
            directory = root / "core" / str(version)
            count, frozen_failures = replay_frozen(version, directory, scratch)
            passed[directory] = count
            failures.extend(frozen_failures)
    for path, case_id, expected, got, reason in failures[:MAX_PRINTED_FAILURES]:
        print(f"FAIL {path} {case_id}")
        print(f"  expected: {expected}")
        print(f"  got:      {got}" + (f" ({reason})" if reason else ""))
    if len(failures) > MAX_PRINTED_FAILURES:
        print(f"... and {len(failures) - MAX_PRINTED_FAILURES} more failures")
    for path in sorted(set(passed) | {failure[0] for failure in failures}):
        failed_here = sum(1 for failure in failures if failure[0] == path)
        print(f"  {path}: {passed.get(path, 0)} passed, {failed_here} failed")
    total = sum(passed.values())
    print(f"{total} passed, {len(failures)} failed")
    if summary_path is not None:
        summary = {"f0": VERSION, "core": CORE_VERSION, "passed": total, "failed": len(failures)}
        summary_path.write_text(json.dumps(summary) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
