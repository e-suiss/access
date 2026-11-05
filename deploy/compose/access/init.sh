#!/bin/sh
# OP-69, CR-28, CR-12, OP-129 m.3, OP-149 m.21: provisions a local deployment once and changes
# nothing on later runs. Generated credentials are random per deployment and live only in its
# volumes: a local CA and leaf certificates, database login passwords, SoftHSM tokens and the
# signers' KEKs.
#
#   /var/lib/access/certs        public: CA and leaf certificates; the PEP client key (0644)
#   /var/lib/access/secrets      this deployment's processes only (0600)
#   /var/lib/access/initdb       what the postgres container reads at its first start (0640)
#   /var/lib/access/product-tls  OP-149 m.23: a server certificate for each host named in
#                                ACCESS_LOCAL_PRODUCT_HOSTS, issued by the local CA, and the CA;
#                                keys are 0640, readable by uid or group 65532
set -eu

certs=/var/lib/access/certs
secrets=/var/lib/access/secrets
initdb=/var/lib/access/initdb
products=/var/lib/access/product-tls

random() {
    openssl rand -hex 24
}

secret() {
    if [ ! -s "$secrets/$1" ]; then
        (umask 077 && random | tr -d '\n' > "$secrets/$1")
    fi
}

ca() {
    if [ ! -s "$certs/ca.crt" ]; then
        (umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$secrets/ca.key")
        openssl req -x509 -new -key "$secrets/ca.key" -sha256 -days 825 \
            -subj "/CN=Access local CA" \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -out "$certs/ca.crt"
    fi
}

# leaf <name> <key path> <eku> [subjectAltName] [certificate directory]
leaf() {
    name="$1" key="$2" eku="$3" san="${4:-}" dir="${5:-$certs}"
    if [ -s "$dir/$name.crt" ]; then
        return
    fi
    (umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$key")
    ext="$(mktemp)"
    {
        echo "basicConstraints=critical,CA:FALSE"
        echo "keyUsage=critical,digitalSignature"
        echo "extendedKeyUsage=$eku"
        if [ -n "$san" ]; then
            echo "subjectAltName=$san"
        fi
    } > "$ext"
    openssl req -new -key "$key" -subj "/CN=$name" \
        | openssl x509 -req -CA "$certs/ca.crt" -CAkey "$secrets/ca.key" -CAcreateserial \
            -CAserial "$secrets/ca.srl" -sha256 -days 365 -extfile "$ext" -out "$dir/$name.crt"
    rm -f "$ext"
}

for role in migrator sequencer app deriver router archive outbox-reader; do
    secret "db-$role"
done
for token in access-server access-signer access-identity-signer; do
    secret "hsm-$token"
done
secret hsm-so
secret postgres

ca
leaf access-server "$secrets/access-server.key" serverAuth "DNS:access-server,DNS:localhost,IP:127.0.0.1"
leaf postgres "$initdb/postgres.key" serverAuth "DNS:postgres"
# OP-141 m.18 (b): a PEP client certificate for products calling /access/v1
leaf pep "$certs/pep.key" clientAuth
chmod 0644 "$certs"/*.crt "$certs/pep.key"
chmod 0640 "$initdb/postgres.key"

# OP-149 m.23: products on the local network serve TLS from the local CA, so Access verifies them
# when it pushes to a declared delivery target (ACCESS_DELIVERY_TARGETS)
for host in ${ACCESS_LOCAL_PRODUCT_HOSTS:-}; do
    case "$host" in
        -* | *[!a-z0-9.-]*)
            echo "access-local-init: product host '$host' is not a lowercase DNS name" >&2
            exit 1
            ;;
    esac
    leaf "$host" "$products/$host.key" serverAuth "DNS:$host" "$products"
    chmod 0644 "$products/$host.crt"
    chmod 0640 "$products/$host.key"
done
if [ -n "${ACCESS_LOCAL_PRODUCT_HOSTS:-}" ]; then
    cp "$certs/ca.crt" "$products/ca.crt"
    chmod 0644 "$products/ca.crt"
fi

# OP-130 m.2: the database administrator's setup, run by the postgres image's first start
mkdir -p "$initdb/sql"
cp /usr/share/access/postgres/roles.sql /usr/share/access/postgres/database.sql "$initdb/sql/"
cp /usr/share/access/postgres/postgres-init.sh "$initdb/10-access.sh"
{
    for role in migrator sequencer app deriver router archive outbox-reader; do
        r="$(echo "$role" | tr - _)"
        echo "access_${r}_login access_${r} $(cat "$secrets/db-$role")"
    done
} > "$initdb/logins"
cp "$secrets/postgres" "$initdb/superuser"
chmod 0640 "$initdb/logins" "$initdb/superuser" "$initdb"/sql/*.sql
chmod 0750 "$initdb/10-access.sh" "$initdb/sql"

# CR-28, OP-94: one token per process, then each signer's KEK
for token in access-server access-signer access-identity-signer; do
    if ! softhsm2-util --show-slots | grep -q "Label:[[:space:]]*${token}[[:space:]]*\$"; then
        softhsm2-util --init-token --free --label "$token" \
            --so-pin "$(cat "$secrets/hsm-so")" --pin "$(cat "$secrets/hsm-$token")" >/dev/null
    fi
done
ACCESS_SIGNER_CONFIG=/etc/access/local/access-signer.toml access-signer init
ACCESS_IDENTITY_SIGNER_CONFIG=/etc/access/local/access-identity-signer.toml access-identity-signer init

echo "access-local-init: provisioned"
