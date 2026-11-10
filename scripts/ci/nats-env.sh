#!/usr/bin/env bash
# OP-156 m.1 (d), m.3 (j), Ek B 5383: a real nats-server 2.15 with JetStream for the doorbell
# client, for CI only. TLS 1.3 with a client certificate, as Access connects in production; the
# CA and both certificates are made here at run time. The container goes into no image.
#
#   scripts/ci/nats-env.sh up     start nats-server, wait for it
#   scripts/ci/nats-env.sh down   stop it
#
# Exports for the tests, written to "$GITHUB_ENV" when it is set:
#   ACCESS_TEST_NATS_ADDR        host:port
#   ACCESS_TEST_NATS_CA          the CA certificate, PEM
#   ACCESS_TEST_NATS_CERT        the client certificate, PEM
#   ACCESS_TEST_NATS_KEY         the client key, PEM
set -euo pipefail

# the digest deploy/compose/compose.yaml pins
NATS="nats@sha256:ac8f88a6494bffc2c2a5289a0ca61cb28a9145c11ba5677cf24265d07f46d8d4" # 2.15.0-alpine

DIR="${RUNNER_TEMP:-/tmp}/access-nats"

export_var() {
    echo "$1=$2"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "$1=$2" >>"$GITHUB_ENV"
    fi
}

cert() {
    local name="$1" subject="$2" ext="$3"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DIR/$name.key" 2>/dev/null
    openssl req -new -key "$DIR/$name.key" -subj "$subject" -out "$DIR/$name.csr"
    printf '%b' "$ext" >"$DIR/$name.ext"
    openssl x509 -req -in "$DIR/$name.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" -CAcreateserial \
        -days 1 -sha256 -extfile "$DIR/$name.ext" -out "$DIR/$name.pem" 2>/dev/null
    chmod 0600 "$DIR/$name.key"
}

up() {
    rm -rf "$DIR"
    mkdir -p "$DIR"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DIR/ca.key" 2>/dev/null
    openssl req -x509 -new -key "$DIR/ca.key" -subj "/CN=doorbell CI CA" -days 1 -sha256 \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
        -out "$DIR/ca.pem"
    cert server "/CN=localhost" "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n"
    cert client "/CN=access-server" "extendedKeyUsage=clientAuth\n"
    chmod 0644 "$DIR/server.key"
    cat >"$DIR/nats.conf" <<'CONF'
listen: 0.0.0.0:4222
jetstream {
  store_dir: /tmp/jetstream
  max_memory_store: 64MB
  max_file_store: 256MB
}
tls {
  cert_file: /etc/nats/server.pem
  key_file: /etc/nats/server.key
  ca_file: /etc/nats/ca.pem
  verify: true
}
CONF
    docker run --detach --name access-nats --publish 4222:4222 \
        --volume "$DIR:/etc/nats:ro" "$NATS" --config /etc/nats/nats.conf
    for _ in $(seq 1 60); do
        if (exec 3<>/dev/tcp/127.0.0.1/4222) 2>/dev/null; then
            break
        fi
        sleep 1
    done
    docker logs access-nats 2>&1 | tail -5
    export_var ACCESS_TEST_NATS_ADDR "127.0.0.1:4222"
    export_var ACCESS_TEST_NATS_CA "$DIR/ca.pem"
    export_var ACCESS_TEST_NATS_CERT "$DIR/client.pem"
    export_var ACCESS_TEST_NATS_KEY "$DIR/client.key"
}

down() {
    docker rm --force access-nats >/dev/null 2>&1 || true
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *)
        echo "usage: $0 up|down" >&2
        exit 2
        ;;
esac
