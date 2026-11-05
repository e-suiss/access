#!/bin/sh
# OP-69, CR-28, CR-12, OP-129 m.3, OP-149 m.21: provisions a local deployment once and changes
# nothing on later runs. Generated credentials are random per deployment and live only in its
# volumes: a local CA and leaf certificates, database login passwords, SoftHSM tokens and the
# signers' KEKs.
#
#   /var/lib/access/certs    public: CA and leaf certificates; the PEP client key (0644)
#   /var/lib/access/secrets  this deployment's processes only (0600)
#   /var/lib/access/initdb   what the postgres container reads at its first start (0640)
set -eu

certs=/var/lib/access/certs
secrets=/var/lib/access/secrets
initdb=/var/lib/access/initdb

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

# leaf <name> <key path> <eku> [subjectAltName]
leaf() {
    name="$1" key="$2" eku="$3" san="${4:-}"
    if [ -s "$certs/$name.crt" ]; then
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
            -CAserial "$secrets/ca.srl" -sha256 -days 365 -extfile "$ext" -out "$certs/$name.crt"
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
