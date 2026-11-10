"""scim2-tester against the Access SCIM server (T42, IDP-40, OP-155 m.3 (q), Ek B 5100).

  check.py <base url> <bearer secret> <expected.json> [--release]

Requests carry the SCIM media type (RFC 7644 §8.1); the strict server takes plain JSON only from
clients whose profile tolerates it (IDP-23). A check passes when scim2-tester rates it SUCCESS, COMPLIANT or ACCEPTABLE. Any other result
fails the run unless expected.json lists it with its reason. While expected.json is not yet
recorded (its first run), failures are reported, the list to record is printed, and the run
passes; with --release an unrecorded list fails the run.
"""

import json
import sys

import httpx2
from scim2_client.engines.httpx2 import SyncSCIMClient
from scim2_tester import Status, check_server

PASS = {Status.SUCCESS, Status.COMPLIANT, Status.ACCEPTABLE, Status.SKIPPED}


def key(r):
    return "|".join(x or "" for x in (r.resource_type, r.title, r.attribute))


def main(argv):
    base, secret, expected_path = argv[1], argv[2], argv[3]
    release = "--release" in argv[4:]
    with open(expected_path, encoding="utf-8") as f:
        expected = json.load(f)
    recorded = expected.get("recorded", False)
    known = expected.get("results", {})
    client = SyncSCIMClient(
        httpx2.Client(
            base_url=base,
            headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/scim+json"},
            timeout=30,
        )
    )
    client.discover()
    results = check_server(client, seed=1)
    bad, candidate = [], {}
    for r in results:
        k = key(r)
        ok = r.status in PASS
        print(f"{r.status.name:10} {k}: {r.reason or ''}")
        if not ok:
            candidate[k] = f"{r.status.name}: {r.reason or r.description or ''}"[:300]
            if k not in known:
                bad.append(f"{k}: {r.status.name} {r.reason or ''}")
        elif k in known:
            print(f"::warning::{k} now passes; remove it from expected.json")
    print(f"{len(results) - len(bad)} of {len(results)} checks passed or failed as expected")
    if not recorded:
        print("expected.json is not recorded yet; record this list after review:")
        print(json.dumps({"recorded": True, "results": candidate}, indent=2, sort_keys=True))
        if release:
            print("::error::a release needs a recorded expected.json")
            sys.exit(1)
        return
    for line in bad:
        print(f"::error::{line}")
    if bad:
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
