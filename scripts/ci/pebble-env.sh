#!/usr/bin/env bash
# OP-156 m.3 (i): Pebble, the ACME test server, and its DNS for CI only. Both containers are pinned
# by digest, use the host network, and go into no image. challtestsrv answers every name with
# 127.0.0.1, so Pebble's TLS-ALPN-01 validation reaches the test's listener on port 5001.
#
#   scripts/ci/pebble-env.sh up     start challtestsrv and Pebble, wait for the directory
#   scripts/ci/pebble-env.sh down   stop them
#
# Exports for the tests, written to "$GITHUB_ENV" when it is set:
#   ACCESS_TEST_PEBBLE_DIRECTORY   the ACME directory URL
#   ACCESS_TEST_PEBBLE_CA          the PEM CA of Pebble's own HTTPS (its minica)
#   ACCESS_TEST_PEBBLE_MANAGEMENT  the management origin that serves the issuing root
set -euo pipefail

PEBBLE="ghcr.io/letsencrypt/pebble@sha256:68cf1ec8a8db96f64244d5f559c448bc8e54f2934e0dd53a414eabffda7a6f22" # 2.10.0
CHALLTESTSRV="ghcr.io/letsencrypt/pebble-challtestsrv@sha256:df85447c39114cd2b3da971e751682ad2db19a996034b47d5392cd4a0f43406a" # 2.10.0
MINICA_URL="https://raw.githubusercontent.com/letsencrypt/pebble/v2.10.0/test/certs/pebble.minica.pem"
MINICA_SHA256="0c502e52627ff7de972c7e9e065640103b4589b4e2d23d3fcf21bef1e3c8c67c"
CA="${RUNNER_TEMP:-/tmp}/pebble.minica.pem"

export_var() {
    echo "$1=$2"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "$1=$2" >>"$GITHUB_ENV"
    fi
}

up() {
    curl --fail --silent --show-error --location --output "$CA" "$MINICA_URL"
    echo "$MINICA_SHA256  $CA" | sha256sum --check --strict
    docker run --detach --name access-challtestsrv --network host "$CHALLTESTSRV" \
        -defaultIPv6 "" -defaultIPv4 127.0.0.1
    docker run --detach --name access-pebble --network host \
        --env PEBBLE_VA_NOSLEEP=1 --env PEBBLE_WFE_NONCEREJECT=0 \
        "$PEBBLE" -config /test/config/pebble-config.json -dnsserver 127.0.0.1:8053
    for _ in $(seq 1 60); do
        if curl --fail --silent --cacert "$CA" https://localhost:14000/dir >/dev/null; then
            export_var ACCESS_TEST_PEBBLE_DIRECTORY https://localhost:14000/dir
            export_var ACCESS_TEST_PEBBLE_CA "$CA"
            export_var ACCESS_TEST_PEBBLE_MANAGEMENT https://localhost:15000
            return 0
        fi
        sleep 2
    done
    docker logs access-pebble >&2 || true
    echo "Pebble did not come up" >&2
    return 1
}

down() {
    docker rm --force access-pebble access-challtestsrv >/dev/null 2>&1 || true
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *)
        echo "usage: $0 up|down" >&2
        exit 2
        ;;
esac
