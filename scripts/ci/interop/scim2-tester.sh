#!/usr/bin/env bash
# T42, IDP-40, OP-155 m.3 (q), Ek B 5100: scim2-tester against a real Access SCIM server that the
# access-server test serves on the runner's loopback.
#
#   scripts/ci/interop/scim2-tester.sh <base url> <bearer secret>
# INTEROP_RELEASE=1 refuses an unrecorded expected list.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=images.sh
. "$here/images.sh"
root="$(cd "$here/../../.." && pwd)"
release=()
if [[ "${INTEROP_RELEASE:-}" == 1 ]]; then
    release=(--release)
fi

docker run --rm --network host --volume "$root/conformance/interop/scim:/scim:ro" \
    --env SCIM2_PIP="$SCIM2_PIP" "$PYTHON" sh -ec '
    # shellcheck disable=SC2086
    pip install --quiet --disable-pip-version-check --root-user-action=ignore $SCIM2_PIP
    exec python -I /scim/check.py "$@"
' check "$1" "$2" /scim/expected.json "${release[@]}"
