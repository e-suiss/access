#!/usr/bin/env bash
# IDP-30 (2), OP-156 m.3 (m), m.15 (i): the proxy engines for the CI job proxy-engines. Each image
# is the digest deploy/proxy/engines.env pins; nothing here goes into an image.
#
#   scripts/ci/proxy-engines.sh pull   pull the four engine images and export them for the tests
#
# Exports, written to "$GITHUB_ENV" when it is set:
#   ACCESS_TEST_PROXY_RUNNER          docker
#   ACCESS_TEST_PROXY_IMAGE_ENVOY     and _CADDY, _TRAEFIK, _NGINX: the pinned images
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/proxy/engines.env
source "$here/../../deploy/proxy/engines.env"

export_var() {
    echo "$1=$2"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "$1=$2" >>"$GITHUB_ENV"
    fi
}

pull() {
    for image in "$ENVOY_IMAGE" "$CADDY_IMAGE" "$TRAEFIK_IMAGE" "$NGINX_IMAGE"; do
        docker pull --quiet "$image"
    done
    export_var ACCESS_TEST_PROXY_RUNNER docker
    export_var ACCESS_TEST_PROXY_IMAGE_ENVOY "$ENVOY_IMAGE"
    export_var ACCESS_TEST_PROXY_IMAGE_CADDY "$CADDY_IMAGE"
    export_var ACCESS_TEST_PROXY_IMAGE_TRAEFIK "$TRAEFIK_IMAGE"
    export_var ACCESS_TEST_PROXY_IMAGE_NGINX "$NGINX_IMAGE"
}

case "${1:-}" in
    pull) pull ;;
    *)
        echo "usage: $0 pull" >&2
        exit 2
        ;;
esac
