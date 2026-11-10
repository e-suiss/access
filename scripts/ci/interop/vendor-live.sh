#!/usr/bin/env bash
# IDP-40, OP-155 m.3 (q), Ek B 4934, 5024: the vendor-live rows of conformance/interop/lab.toml.
# A row runs only when its CI secret is set in the environment of the interop-lab job, through
# scripts/ci/interop/live/<row>.sh. A set secret without a driver fails the run (fail-closed);
# an unset one skips the row. Third-party test tenants are an account action (Ek B 4665).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"

rows="$(python3 -I - "$root/conformance/interop/lab.toml" <<'PY'
import re, sys, tomllib
with open(sys.argv[1], "rb") as f:
    lab = tomllib.load(f)
for s in lab.get("system", []):
    if s.get("kind") == "live":
        print(re.sub(r"[^a-z0-9]+", "-", s["name"].lower()).strip("-") + "\t" + s["secret"])
PY
)"
if [[ -z "$rows" ]]; then
    echo "no vendor-live rows"
    exit 0
fi
failed=0
while IFS=$'\t' read -r row secret; do
    if [[ -z "${!secret:-}" ]]; then
        echo "skipped $row: the CI secret $secret is not set"
        continue
    fi
    driver="$here/live/$row.sh"
    if [[ ! -x "$driver" ]]; then
        echo "::error::$secret is set but $driver does not exist"
        failed=1
        continue
    fi
    echo "running $row"
    "$driver" || failed=1
done <<<"$rows"
exit "$failed"
