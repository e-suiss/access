"""Re-encodes every "cbor" vector with cbor2 (OP-106 m.24). Usage: python -I cbor_crosscheck.py <vectors dir>"""

import json
import pathlib
import sys

import cbor2


def main():
    checked = failed = 0
    for path in sorted(pathlib.Path(sys.argv[1]).rglob("*.json")):
        try:
            cases = json.loads(path.read_text()).get("cases", [])
        except (json.JSONDecodeError, AttributeError):
            continue
        for case in cases:
            if not isinstance(case, dict):
                continue
            for field in ("cbor", "input", "decision"):
                if field not in case:
                    continue
                want = bytes.fromhex(case[field])
                got = cbor2.dumps(cbor2.loads(want), canonical=True)
                if got == want:
                    checked += 1
                else:
                    failed += 1
                    print(f"FAIL {path} {case['id']}.{field}: re-encoding differs")
    print(f"{checked} vectors identical, {failed} failed")
    sys.exit(1 if failed else 0)


main()
