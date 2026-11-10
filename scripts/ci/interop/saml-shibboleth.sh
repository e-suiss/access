#!/usr/bin/env bash
# T42, IDP-40, OP-155 m.3 (q), Ek B 4934, 5100: Shibboleth SP 3 (Debian's libapache2-mod-shib
# behind Apache) as the service provider. It loads the signed Access metadata through its
# signature filter, then must open a session for a real Access response posted to its ACS and
# must refuse the tampered one.
#
#   scripts/ci/interop/saml-shibboleth.sh <artifact dir>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=images.sh
. "$here/images.sh"
dir="$(cd "$1" && pwd)"

docker run --rm --volume "$dir:/work:ro" "$DEBIAN" bash -ec '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        apache2 libapache2-mod-shib curl ca-certificates >/dev/null
    . /work/expected.env
    cd /etc/shibboleth
    shib-keygen -f -u _shibd -h shib.sp.test -y 1 >/dev/null 2>&1 || shib-keygen -f -h shib.sp.test -y 1
    cat >shibboleth2.xml <<XML
<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config" xmlns:conf="urn:mace:shibboleth:3.0:native:sp:config" clockSkew="180">
  <ApplicationDefaults entityID="$SP_ENTITY" REMOTE_USER="persistent-id">
    <Sessions lifetime="28800" timeout="3600" relayState="ss:mem" checkAddress="false" handlerSSL="false" cookieProps="https">
      <SSO>SAML2</SSO>
      <Logout>Local</Logout>
      <Handler type="Session" Location="/Session" showAttributeValues="false"/>
    </Sessions>
    <Errors supportContact="root@localhost" helpLocation="/about.html" styleSheet="/shibboleth-sp/main.css"/>
    <MetadataProvider type="XML" validate="true" path="/work/metadata.xml">
      <MetadataFilter type="Signature" certificate="/work/metadata.pem" verifyBackup="false"/>
    </MetadataProvider>
    <AttributeExtractor type="XML" validate="true" reloadChanges="false" path="attribute-map.xml"/>
    <AttributeFilter type="XML" validate="true" path="attribute-policy.xml"/>
    <CredentialResolver type="File" use="signing" key="sp-key.pem" certificate="sp-cert.pem"/>
  </ApplicationDefaults>
  <SecurityPolicyProvider type="XML" validate="true" path="security-policy.xml"/>
  <ProtocolProvider type="XML" validate="true" reloadChanges="false" path="protocols.xml"/>
</SPConfig>
XML
    shibd -t
    cat >/etc/apache2/sites-available/000-default.conf <<CONF
<VirtualHost *:8080>
    ServerName https://shib.sp.test:443
    UseCanonicalName On
    DocumentRoot /var/www/html
    <Location /secure>
        AuthType shibboleth
        ShibRequestSession On
        Require shib-session
    </Location>
</VirtualHost>
CONF
    echo "Listen 8080" >/etc/apache2/ports.conf
    a2enmod shib >/dev/null
    shibd -f
    apache2ctl start
    for _ in $(seq 1 30); do curl -fs -o /dev/null http://127.0.0.1:8080/ && break; sleep 1; done
    post() {
        curl -s -o /dev/null -D - -w "%{http_code}\n" \
            --data-urlencode "SAMLResponse=$1" \
            --data-urlencode "RelayState=https://shib.sp.test/secure" \
            http://127.0.0.1:8080/Shibboleth.sso/SAML2/POST
    }
    good="$(post "$RESPONSE_B64")"
    bad="$(post "$TAMPERED_B64")"
    echo "$good" | grep -qi "^set-cookie: _shibsession_" || {
        echo "Shibboleth SP opened no session for the real response:" >&2
        echo "$good" >&2
        tail -n 50 /var/log/shibboleth/shibd.log >&2 || true
        exit 1
    }
    if echo "$bad" | grep -qi "^set-cookie: _shibsession_"; then
        echo "Shibboleth SP opened a session for the tampered response" >&2
        exit 1
    fi
    echo "Shibboleth SP: the real response opens a session, the tampered one does not"
'
