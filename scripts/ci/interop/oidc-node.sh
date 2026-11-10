#!/usr/bin/env bash
# T42, IDP-40, OP-155 m.3 (q), Ek B 5064, 5100: openid-client signs in against the OIDF
# conformance target, and oidc-provider (the reference, the only oracle) is asked the same
# refused requests as Access.
#
#   scripts/ci/interop/oidc-node.sh <target certificate>
# The target listens on the runner at acme.id.test:9443. INTEROP_RELEASE=1 refuses an unrecorded
# expected list.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=images.sh
. "$here/images.sh"
root="$(cd "$here/../../.." && pwd)"
cert="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
release=()
if [[ "${INTEROP_RELEASE:-}" == 1 ]]; then
    release=(--release)
fi

docker run --rm --network host --volume "$root:/repo:ro" --volume "$cert:/target.pem:ro" \
    --env NODE_EXTRA_CA_CERTS=/target.pem --env ACCESS_RESOLVE=acme.id.test:127.0.0.1 \
    "$NODE" sh -ec '
    cp -r /repo/conformance/interop/node /tmp/differential
    cd /tmp/differential
    npm ci --no-audit --no-fund
    exec node differential.mjs "$@"
' differential https://acme.id.test:9443 /repo/conformance/oidf /repo/conformance/interop/node/expected.json "${release[@]}"
