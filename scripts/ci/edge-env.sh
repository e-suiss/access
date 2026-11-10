#!/usr/bin/env bash
# OP-155 m.3 (n), (q), Ek B 4664: the Kerberos, LDAP and RADIUS counterparts of the edge gateways,
# for CI only. Every container is pinned by digest and goes into no image.
#
#   scripts/ci/edge-env.sh up     start OpenLDAP, an MIT KDC and FreeRADIUS, seed them, wait
#   scripts/ci/edge-env.sh down   stop them
#
# Exports for the tests, written to "$GITHUB_ENV" when it is set:
#   ACCESS_TEST_LDAP_ADDR, ACCESS_TEST_LDAP_SERVER_NAME, ACCESS_TEST_LDAP_CA,
#   ACCESS_TEST_LDAP_BIND_DN, ACCESS_TEST_LDAP_BIND_PASSWORD, ACCESS_TEST_LDAP_BASE
#                                               the AD-sync source (OpenLDAP over LDAPS, uSNChanged)
#   ACCESS_TEST_KRB5_REALM, ACCESS_TEST_KDC, ACCESS_TEST_KEYTAB_DIR    the MIT KDC
#   ACCESS_TEST_RADCLIENT                       radclient inside the FreeRADIUS container
set -euo pipefail

OPENLDAP="osixia/openldap@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28" # 1.5.0
DEBIAN="debian@sha256:4bcb9db66237237d03b55b969271728dd3d955eaaa254b9db8a3db94550b1885" # 13.2-slim
FREERADIUS="freeradius/freeradius-server@sha256:bbb399476d804b710c8289559c5a6ce4ac20cb81113554ea371614f30ee0ad41" # 3.2.8

PASSWORD="ci-only-not-a-secret"
BASE="dc=corp,dc=example"
REALM="CORP.EXAMPLE"
KEYTABS="${RUNNER_TEMP:-/tmp}/access-keytabs"

export_var() {
    echo "$1=$2"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "$1=$2" >>"$GITHUB_ENV"
    fi
}

wait_for() {
    local what="$1"
    shift
    for _ in $(seq 1 60); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "$what did not come up" >&2
    return 1
}

up() {
    docker run --detach --name access-openldap --hostname ldap.corp.example \
        --publish 6636:636 \
        --env LDAP_ORGANISATION=Corp --env LDAP_DOMAIN=corp.example \
        --env LDAP_ADMIN_PASSWORD="$PASSWORD" --env LDAP_TLS=true \
        --env LDAP_TLS_VERIFY_CLIENT=never \
        "$OPENLDAP"
    wait_for OpenLDAP docker exec access-openldap \
        ldapsearch -x -H ldap://localhost -b "$BASE" -D "cn=admin,$BASE" -w "$PASSWORD" -s base
    # §10.6.4: an AD-shaped source; uSNChanged is AD's change counter
    docker exec -i access-openldap ldapadd -Y EXTERNAL -H ldapi:/// <<'LDIF'
dn: cn=adsync,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: adsync
olcAttributeTypes: ( 1.3.6.1.4.1.99999.1.1 NAME 'uSNChanged' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.1.2 NAME 'objectGUID' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.99999.1.3 NAME 'sAMAccountName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.2.1 NAME 'adSynced' AUXILIARY MAY ( uSNChanged $ objectGUID $ sAMAccountName ) )
LDIF
    docker exec -i access-openldap ldapadd -x -H ldap://localhost -D "cn=admin,$BASE" -w "$PASSWORD" <<LDIF
dn: ou=people,$BASE
objectClass: organizationalUnit
ou: people

dn: ou=groups,$BASE
objectClass: organizationalUnit
ou: groups

dn: cn=Ada Lovelace,ou=people,$BASE
objectClass: inetOrgPerson
objectClass: adSynced
cn: Ada Lovelace
sn: Lovelace
mail: ada@corp.example
sAMAccountName: ada
uSNChanged: 101
objectGUID:: AAECAwQFBgcICQoLDA0ODw==

dn: cn=Grace Hopper,ou=people,$BASE
objectClass: inetOrgPerson
objectClass: adSynced
cn: Grace Hopper
sn: Hopper
mail: grace@corp.example
sAMAccountName: grace
uSNChanged: 102
objectGUID:: EBESExQVFhcYGRobHB0eHw==

dn: cn=staff,ou=groups,$BASE
objectClass: groupOfNames
objectClass: adSynced
cn: staff
member: cn=Ada Lovelace,ou=people,$BASE
uSNChanged: 103
objectGUID:: ICEiIyQlJicoKSorLC0uLw==
LDIF
    docker cp access-openldap:/container/service/slapd/assets/certs/ca.crt "${RUNNER_TEMP:-/tmp}/access-ldap-ca.pem"
    export_var ACCESS_TEST_LDAP_ADDR "127.0.0.1:6636"
    export_var ACCESS_TEST_LDAP_SERVER_NAME "ldap.corp.example"
    export_var ACCESS_TEST_LDAP_CA "${RUNNER_TEMP:-/tmp}/access-ldap-ca.pem"
    export_var ACCESS_TEST_LDAP_BIND_DN "cn=admin,$BASE"
    export_var ACCESS_TEST_LDAP_BIND_PASSWORD "$PASSWORD"
    export_var ACCESS_TEST_LDAP_BASE "$BASE"

    mkdir -p "$KEYTABS"
    docker run --detach --name access-kdc --publish 8888:88 --publish 8888:88/udp \
        --volume "$KEYTABS:/keytabs" "$DEBIAN" sh -ec "
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends krb5-kdc krb5-admin-server >/dev/null
            printf '[libdefaults]\n default_realm = $REALM\n permitted_enctypes = aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96\n[realms]\n $REALM = {\n  kdc = localhost\n }\n' >/etc/krb5.conf
            printf '[realms]\n $REALM = {\n  supported_enctypes = aes256-cts-hmac-sha384-192:normal aes256-cts-hmac-sha1-96:normal\n }\n' >/etc/krb5kdc/kdc.conf
            kdb5_util create -s -r $REALM -P $PASSWORD
            kadmin.local -q 'addprinc -pw $PASSWORD ada'
            kadmin.local -q 'addprinc -randkey HTTP/access.corp.example'
            kadmin.local -q 'ktadd -k /keytabs/http.keytab HTTP/access.corp.example'
            chmod 0644 /keytabs/http.keytab
            exec krb5kdc -n
        "
    wait_for 'MIT KDC' test -s "$KEYTABS/http.keytab"
    export_var ACCESS_TEST_KRB5_REALM "$REALM"
    export_var ACCESS_TEST_KDC "127.0.0.1:8888"
    export_var ACCESS_TEST_KEYTAB_DIR "$KEYTABS"

    docker run --detach --name access-freeradius "$FREERADIUS"
    wait_for FreeRADIUS docker exec access-freeradius radclient -v
    export_var ACCESS_TEST_RADCLIENT "docker exec -i access-freeradius radclient"
}

down() {
    docker rm --force access-openldap access-kdc access-freeradius >/dev/null 2>&1 || true
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *)
        echo "usage: $0 up|down" >&2
        exit 2
        ;;
esac
