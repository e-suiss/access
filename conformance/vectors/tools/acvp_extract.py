"""Extracts the ACVP groups the Kernel uses (CR-51 V8/V9, KAT): ECDSA P-256/SHA2-256 SigVer, Ed25519 pure SigVer, SHA2-256 AFT.

Usage: python -I acvp_extract.py <dir with ECDSA-SigVer-FIPS186-5.json, EDDSA-SigVer-1.0.json, SHA2-256-1.0.json> <external dir>
The inputs are gen-val/json-files/<name>/internalProjection.json from usnistgov/ACVP-Server.
"""

import json
import pathlib
import sys


def groups(path, keep):
    data = json.loads(path.read_text())
    return data, [g for g in data["testGroups"] if keep(g)]


def write(out, name, data, kept, fields):
    tests = [{k: t[k] for k in fields if k in t} for g in kept for t in g["tests"]]
    doc = {
        "source": "usnistgov/ACVP-Server gen-val/json-files/" + name + "/internalProjection.json",
        "algorithm": data["algorithm"],
        "mode": data.get("mode"),
        "revision": data["revision"],
        "groups": [{k: v for k, v in g.items() if k != "tests"} for g in kept],
        "tests": tests,
    }
    (out / ("acvp-" + name.lower() + ".json")).write_text(json.dumps(doc, indent=1) + "\n")


def main():
    src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    data, kept = groups(src / "ECDSA-SigVer-FIPS186-5.json", lambda g: g["curve"] == "P-256" and g["hashAlg"] == "SHA2-256")
    write(out, "ECDSA-SigVer-FIPS186-5", data, kept, ["tcId", "testPassed", "reason", "message", "qx", "qy", "r", "s"])
    data, kept = groups(src / "EDDSA-SigVer-1.0.json", lambda g: g["curve"] == "ED-25519" and not g["preHash"])
    write(out, "EDDSA-SigVer-1.0", data, kept, ["tcId", "testPassed", "reason", "message", "q", "signature"])
    data, kept = groups(src / "SHA2-256-1.0.json", lambda g: g["testType"] == "AFT")
    write(out, "SHA2-256-1.0", data, kept, ["tcId", "msg", "len", "md"])


main()
