#!/usr/bin/env bash
# OP-156 m.1 (d), m.3 (s): MinIO (S3) and syslog-ng for the export adapters, CI only. Both
# containers are pinned by digest, use the host network and go into no image. One throwaway CA
# signs both servers' certificates for localhost; the MinIO credentials are drawn at start.
#
#   scripts/ci/export-env.sh up     start MinIO and syslog-ng, create the bucket, wait for both
#   scripts/ci/export-env.sh down   stop them
#
# Exports for the tests, written to "$GITHUB_ENV" when it is set:
#   ACCESS_TEST_EXPORT_CA       the PEM CA both servers chain to
#   ACCESS_TEST_MINIO_URL       https://localhost:9000
#   ACCESS_TEST_MINIO_KEY       the access key id
#   ACCESS_TEST_MINIO_SECRET    the secret access key
#   ACCESS_TEST_MINIO_BUCKET    the bucket
#   ACCESS_TEST_SYSLOG_PORT     6514, syslog over TLS (RFC 5425)
#   ACCESS_TEST_SYSLOG_OUT      the file syslog-ng writes each received message to
set -euo pipefail

MINIO="cgr.dev/chainguard/minio@sha256:fb893e36fc369d41e92f678b17ec27378fa5bf0576aeef7ac15460c13629ab5a" # latest, 2026-11-10
SYSLOG_NG="balabit/syslog-ng@sha256:c652345a143843731037863abc6bfd75da5ddaf618a94ca42147fa2d59fbcf89" # 4.11.0
DIR="${RUNNER_TEMP:-/tmp}/access-export"
BUCKET="access-audit-lake"

export_var() {
    echo "$1=$2"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "$1=$2" >>"$GITHUB_ENV"
    fi
}

certificates() {
    mkdir -p "$DIR/certs" "$DIR/minio-certs" "$DIR/syslog" "$DIR/out"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
        -subj "/CN=access-export-ci" -keyout "$DIR/certs/ca.key" -out "$DIR/certs/ca.pem" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
        -keyout "$DIR/certs/server.key" -out "$DIR/certs/server.csr" 2>/dev/null
    printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' >"$DIR/certs/ext.cnf"
    openssl x509 -req -in "$DIR/certs/server.csr" -CA "$DIR/certs/ca.pem" -CAkey "$DIR/certs/ca.key" \
        -CAcreateserial -days 1 -extfile "$DIR/certs/ext.cnf" -out "$DIR/certs/server.crt" 2>/dev/null
    cp "$DIR/certs/server.crt" "$DIR/minio-certs/public.crt"
    cp "$DIR/certs/server.key" "$DIR/minio-certs/private.key"
    chmod 0644 "$DIR/minio-certs/"* "$DIR/certs/server.key" "$DIR/certs/server.crt"
    chmod 0777 "$DIR/out"
}

up() {
    certificates
    local key secret
    key="ci$(openssl rand -hex 8)"
    secret="$(openssl rand -hex 24)"
    docker run --detach --name access-minio --network host \
        --env MINIO_ROOT_USER="$key" --env MINIO_ROOT_PASSWORD="$secret" \
        --volume "$DIR/minio-certs:/certs:ro" --tmpfs /data:uid=65532,gid=65532 \
        "$MINIO" server /data --address :9000 --certs-dir /certs
    cat >"$DIR/syslog/syslog-ng.conf" <<'CONF'
@version: 4.11
options { keep-hostname(yes); };
source s_tls {
    syslog(transport("tls") port(6514)
        tls(key-file("/certs/server.key") cert-file("/certs/server.crt") peer-verify(optional-untrusted)));
};
destination d_out { file("/out/messages.log" template("${MSGHDR}${MSG}\n")); };
log { source(s_tls); destination(d_out); };
CONF
    docker run --detach --name access-syslog-ng --network host \
        --volume "$DIR/certs:/certs:ro" --volume "$DIR/syslog/syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf:ro" \
        --volume "$DIR/out:/out" "$SYSLOG_NG"
    for _ in $(seq 1 60); do
        if curl --fail --silent --cacert "$DIR/certs/ca.pem" https://localhost:9000/minio/health/ready >/dev/null \
            && (echo >/dev/tcp/127.0.0.1/6514) 2>/dev/null; then
            curl --fail --silent --show-error --cacert "$DIR/certs/ca.pem" \
                --aws-sigv4 "aws:amz:eu-central-1:s3" --user "$key:$secret" \
                --request PUT "https://localhost:9000/$BUCKET"
            export_var ACCESS_TEST_EXPORT_CA "$DIR/certs/ca.pem"
            export_var ACCESS_TEST_MINIO_URL https://localhost:9000
            export_var ACCESS_TEST_MINIO_KEY "$key"
            echo "::add-mask::$secret"
            export_var ACCESS_TEST_MINIO_SECRET "$secret"
            export_var ACCESS_TEST_MINIO_BUCKET "$BUCKET"
            export_var ACCESS_TEST_SYSLOG_PORT 6514
            export_var ACCESS_TEST_SYSLOG_OUT "$DIR/out/messages.log"
            return 0
        fi
        sleep 2
    done
    docker logs access-minio >&2 || true
    docker logs access-syslog-ng >&2 || true
    echo "MinIO or syslog-ng did not come up" >&2
    return 1
}

down() {
    docker rm --force access-minio access-syslog-ng >/dev/null 2>&1 || true
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *)
        echo "usage: $0 up|down" >&2
        exit 2
        ;;
esac
