#!/usr/bin/env bash
# OP-159 m.3 (w), F-2
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$root/supply-chain/kani.toml"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-x86_64 ;;
  Linux-aarch64 | Linux-arm64) platform=linux-aarch64 ;;
  Darwin-arm64) platform=macos-aarch64 ;;
  *) echo "kani: no pinned bundle for $(uname -s)-$(uname -m) in $pin" >&2; exit 1 ;;
esac

fields="$(python3 -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    pin = tomllib.load(f)
p = pin["platform"][sys.argv[2]]
print(pin["version"], p["url"], p["bundle_sha256"])
' "$pin" "$platform")"
read -r version url sha256 <<<"$fields"

if command -v sha256sum >/dev/null; then
  sum() { sha256sum "$1" | cut -d' ' -f1; }
else
  sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/kani.tar.gz" "$url"
got="$(sum "$work/kani.tar.gz")"
if [[ "$got" != "$sha256" ]]; then
  echo "kani: bundle sha256 $got does not match the pin $sha256" >&2
  exit 1
fi
cargo install --locked kani-verifier --version "$version"
cargo kani setup --use-local-bundle "$work/kani.tar.gz"
