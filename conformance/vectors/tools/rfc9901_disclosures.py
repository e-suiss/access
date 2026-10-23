"""Extracts every SHA-256 Hash / Disclosure example; name and value decoded independently by Python from RFC 9901.

Usage: python -I rfc9901_disclosures.py rfc9901.txt > external/rfc9901-disclosures.json
"""

import base64
import hashlib
import json
import re
import sys


def main():
    lines = [l for l in open(sys.argv[1]).read().splitlines() if not re.match(r"^(RFC 9901|Fett, et al\.)", l) and "\f" not in l]

    def block(i):
        vals = []
        i += 1
        while i < len(lines) and not lines[i].strip():
            i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].strip().startswith(("-  ", "*  ")):
            vals.append(lines[i].strip())
            i += 1
        return vals, i

    out, i = [], 0
    while i < len(lines):
        if lines[i].strip() != "-  SHA-256 Hash:":
            i += 1
            continue
        h, i = block(i)
        while lines[i].strip() != "-  Disclosure:":
            i += 1
        d, i = block(i)
        while lines[i].strip() != "-  Contents:":
            i += 1
        c, i = block(i)
        disclosure = "".join(d)
        decoded = json.loads(base64.urlsafe_b64decode(disclosure + "=" * (-len(disclosure) % 4)))
        case = {"digest": "".join(h), "disclosure": disclosure,
                "name": decoded[1] if len(decoded) == 3 else None,
                "value": json.dumps(decoded[-1], ensure_ascii=False, separators=(",", ":"))}
        calc = base64.urlsafe_b64encode(hashlib.sha256(case["disclosure"].encode()).digest()).decode().rstrip("=")
        assert calc == case["digest"], case
        out.append(case)
    json.dump({"rule": "CR-55 m.7", "track": "interop", "version": 1, "operation": "verify.sd_jwt.disclosure",
               "source": "RFC 9901, every SHA-256 Hash / Disclosure example; name and value decoded independently by Python", "cases": out},
              sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


main()
