#!/usr/bin/env bash
# OP-119 m.3
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .lake

python3 -I - proofs.toml <<'PY' >.lake/axioms.lean
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    pin = tomllib.load(f)
print("import AccessAlgebra")
for t in pin["theorem"]:
    print(f"#print axioms {t['name']}")
PY

lake env lean .lake/axioms.lean >.lake/axioms.out 2>&1 || {
  cat .lake/axioms.out >&2
  exit 1
}

python3 -I - proofs.toml .lake/axioms.out <<'PY'
import re, sys, tomllib
with open(sys.argv[1], "rb") as f:
    pin = tomllib.load(f)
out = open(sys.argv[2], encoding="utf-8").read()
allowed = set(pin["allowed_axioms"])
deps = {}
for m in re.finditer(r"'([^']+)' depends on axioms: \[([^\]]*)\]", out):
    deps[m.group(1)] = {a.strip() for a in m.group(2).split(",") if a.strip()}
for m in re.finditer(r"'([^']+)' does not depend on any axioms", out):
    deps[m.group(1)] = set()
bad = 0
counts = {"proved": 0, "stated": 0}
for t in pin["theorem"]:
    name, status = t["name"], t["status"]
    if status not in counts:
        print(f"{name}: unknown status {status!r}", file=sys.stderr)
        bad += 1
        continue
    counts[status] += 1
    if name not in deps:
        print(f"{name}: not found", file=sys.stderr)
        bad += 1
        continue
    extra = deps[name] - allowed
    if status == "proved" and extra:
        print(f"{name}: marked proved but depends on {sorted(extra)}", file=sys.stderr)
        bad += 1
    if status == "stated" and "sorryAx" not in deps[name]:
        print(f"{name}: marked stated but has a complete proof; mark it proved", file=sys.stderr)
        bad += 1
if bad:
    sys.exit(1)
print(f"axioms: {counts['proved']} proved, {counts['stated']} stated")
PY
