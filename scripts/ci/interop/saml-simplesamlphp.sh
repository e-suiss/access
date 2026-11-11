#!/usr/bin/env bash
# T42, IDP-40, OP-155 m.3 (q), Ek B 4934, 5100: SimpleSAMLphp's SAML library
# (simplesamlphp/saml2-legacy, what SimpleSAMLphp 2.5 processes responses with) as the service
# provider: it must accept a real Access response and refuse the tampered one. Its
# simplesamlphp/xml-common needs ext-bcmath, which the composer image does not build in, and
# ships a Composer plugin that a non-interactive install must allow by name.
#
#   scripts/ci/interop/saml-simplesamlphp.sh <artifact dir>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=images.sh
. "$here/images.sh"
dir="$(cd "$1" && pwd)"
root="$(cd "$here/../../.." && pwd)"

docker run --rm --volume "$dir:/work:ro" \
    --volume "$root/conformance/interop/saml/simplesamlphp.php:/check.php:ro" \
    --env SAML2_LEGACY="$SAML2_LEGACY" "$COMPOSER" sh -ec '
    apk add --no-cache $PHPIZE_DEPS >/dev/null
    docker-php-ext-install bcmath >/dev/null
    mkdir /tmp/sp && cd /tmp/sp
    echo "{}" >composer.json
    composer --no-interaction config allow-plugins.simplesamlphp/composer-xmlprovider-installer true
    composer --no-interaction --no-progress require "simplesamlphp/saml2-legacy:$SAML2_LEGACY"
    php /check.php /work
'
