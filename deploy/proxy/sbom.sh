#!/usr/bin/env bash
# IDP-30 (2), OP-156 m.3 (m), F-5: the CycloneDX SBOM of an Access Proxy image, naming the engine
# and its version, and checks that the built image's engine reports that version.
#
#   deploy/proxy/sbom.sh envoy|caddy IMAGE@DIGEST OUT.json
set -euo pipefail

variant="$1"
image="$2"
out="$3"
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/proxy/engines.env
source "$here/engines.env"

case "$variant" in
    envoy)
        engine_image="$ENVOY_IMAGE"
        version="$ENVOY_VERSION"
        reported="$(docker run --rm --entrypoint /usr/local/bin/envoy "$image" --version)"
        purl="pkg:docker/envoyproxy/envoy@${ENVOY_IMAGE##*@}"
        ;;
    caddy)
        engine_image="$CADDY_IMAGE"
        version="$CADDY_VERSION"
        reported="$(docker run --rm --entrypoint /usr/bin/caddy "$image" version)"
        purl="pkg:golang/github.com/caddyserver/caddy/v2@v${CADDY_VERSION}"
        ;;
    *)
        echo "usage: $0 envoy|caddy IMAGE@DIGEST OUT.json" >&2
        exit 2
        ;;
esac

if ! grep -q -- "$version" <<<"$reported"; then
    echo "the image's $variant reports '$reported', not $version" >&2
    exit 1
fi

jq -n \
    --arg variant "$variant" \
    --arg version "$version" \
    --arg engine_image "$engine_image" \
    --arg purl "$purl" \
    --arg image "$image" \
    --arg tool_version "$(grep -m1 '^version' "$here/../../Cargo.toml" | cut -d'"' -f2)" \
    '{
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
      metadata: {
        component: { type: "container", name: ("access-proxy-" + $variant), version: $image }
      },
      components: [
        { type: "application", name: $variant, version: $version, purl: $purl,
          externalReferences: [{ type: "distribution", url: $engine_image }] },
        { type: "application", name: "access-proxy", version: $tool_version,
          purl: ("pkg:cargo/access-proxy@" + $tool_version), licenses: [{ license: { id: "Apache-2.0" } }] }
      ]
    }' >"$out"

jq -e --arg n "$variant" --arg v "$version" \
    '.components[] | select(.name == $n and .version == $v)' "$out" >/dev/null
echo "$out names $variant $version"
