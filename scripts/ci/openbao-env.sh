#!/usr/bin/env bash
# OP-156 m.3 (x), m.5: OpenBao as the secret store behind the secret-release seam, CI only. The
# container is pinned by digest, uses the host network and goes into no image. Its storage is in
# memory; it is initialised with one unseal key, unsealed, and gets a KV v2 mount at `secret/`.
#
#   scripts/ci/openbao-env.sh up     start OpenBao, initialise, unseal, mount KV v2
#   scripts/ci/openbao-env.sh down   stop it
#
# Exports for the tests, written to "$GITHUB_ENV" when it is set:
#   ACCESS_TEST_OPENBAO_ADDR    127.0.0.1:8200 (HTTP on the loopback only)
#   ACCESS_TEST_OPENBAO_TOKEN   the root token of this throwaway instance
set -euo pipefail

OPENBAO="ghcr.io/openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f" # 2.7.2
DIR="${RUNNER_TEMP:-/tmp}/access-openbao"
ADDR="127.0.0.1:8200"

export_var() {
    echo "$1=$2"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "$1=$2" >>"$GITHUB_ENV"
    fi
}

up() {
    mkdir -p "$DIR"
    cat >"$DIR/ci.hcl" <<'HCL'
storage "inmem" {}
listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}
disable_mlock = true
api_addr      = "http://127.0.0.1:8200"
HCL
    chmod 0644 "$DIR/ci.hcl"
    docker run --detach --name access-openbao --network host \
        --volume "$DIR/ci.hcl:/openbao/config/ci.hcl:ro" "$OPENBAO" server -config=/openbao/config/ci.hcl
    for _ in $(seq 1 60); do
        if curl --silent --output /dev/null "http://$ADDR/v1/sys/seal-status"; then
            break
        fi
        sleep 1
    done
    local init key token
    init="$(curl --fail --silent --show-error --request PUT \
        --data '{"secret_shares":1,"secret_threshold":1}' "http://$ADDR/v1/sys/init")"
    key="$(jq --raw-output '.keys_base64[0]' <<<"$init")"
    token="$(jq --raw-output '.root_token' <<<"$init")"
    echo "::add-mask::$key"
    echo "::add-mask::$token"
    curl --fail --silent --show-error --output /dev/null --request PUT \
        --data "{\"key\":\"$key\"}" "http://$ADDR/v1/sys/unseal"
    curl --fail --silent --show-error --output /dev/null --request POST \
        --header "X-Vault-Token: $token" --data '{"type":"kv","options":{"version":"2"}}' \
        "http://$ADDR/v1/sys/mounts/secret"
    for _ in $(seq 1 60); do
        if curl --fail --silent --output /dev/null --header "X-Vault-Token: $token" \
            "http://$ADDR/v1/secret/config"; then
            export_var ACCESS_TEST_OPENBAO_ADDR "$ADDR"
            export_var ACCESS_TEST_OPENBAO_TOKEN "$token"
            return 0
        fi
        sleep 1
    done
    docker logs access-openbao >&2 || true
    echo "OpenBao did not come up" >&2
    return 1
}

down() {
    docker rm --force access-openbao >/dev/null 2>&1 || true
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *)
        echo "usage: $0 up|down" >&2
        exit 2
        ;;
esac
