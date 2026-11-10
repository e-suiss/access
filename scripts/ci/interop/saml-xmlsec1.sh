#!/usr/bin/env bash
# T42, OP-155 m.3 (q), Ek B 5100: xmlsec1 as the XML signature oracle. It must verify the
# response and assertion signatures of a real Access response and the metadata signature, and
# must refuse the same response with its NameID changed.
#
#   scripts/ci/interop/saml-xmlsec1.sh <artifact dir>   (written by the access-server test)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=images.sh
. "$here/images.sh"
dir="$(cd "$1" && pwd)"

docker run --rm --volume "$dir:/work:ro" "$DEBIAN" sh -ec '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends xmlsec1 >/dev/null
    xmlsec1 --version
    ids="--id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor"
    response="/*/*[local-name()=\"Signature\"]"
    assertion="//*[local-name()=\"Assertion\"]/*[local-name()=\"Signature\"]"
    # shellcheck disable=SC2086
    xmlsec1 --verify $ids --pubkey-cert-pem /work/idp.pem --node-xpath "$response" /work/response.xml
    # shellcheck disable=SC2086
    xmlsec1 --verify $ids --pubkey-cert-pem /work/idp.pem --node-xpath "$assertion" /work/response.xml
    # shellcheck disable=SC2086
    xmlsec1 --verify $ids --pubkey-cert-pem /work/metadata.pem --node-xpath "$response" /work/metadata.xml
    for node in "$response" "$assertion"; do
        # shellcheck disable=SC2086
        if xmlsec1 --verify $ids --pubkey-cert-pem /work/idp.pem --node-xpath "$node" /work/tampered.xml 2>/dev/null; then
            echo "xmlsec1 verified a tampered signature ($node)" >&2
            exit 1
        fi
    done
    echo "xmlsec1: signatures verify, the tampered response does not"
'
