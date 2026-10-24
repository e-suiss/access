#!/usr/bin/env bash
# OP-105, F-2
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <directory>" >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$root/supply-chain/cvc5.toml"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-x86_64 ;;
  Linux-aarch64 | Linux-arm64) platform=linux-aarch64 ;;
  Darwin-arm64) platform=macos-aarch64 ;;
  *) echo "cvc5: no pinned build for $(uname -s)-$(uname -m) in $pin" >&2; exit 1 ;;
esac

fields="$(python3 -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    pin = tomllib.load(f)
p = pin["platform"][sys.argv[2]]
print(pin["version"], p["url"], p["sha256"], p["binary"], p["binary_sha256"])
' "$pin" "$platform")"
read -r version url sha256 binary binary_sha256 <<<"$fields"

if command -v sha256sum >/dev/null; then
  sum() { sha256sum "$1" | cut -d' ' -f1; }
else
  sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

mkdir -p "$1"
dest="$(cd "$1" && pwd)/$version-$platform"
exe="$dest/$binary"
if [[ -f "$exe" && "$(sum "$exe")" == "$binary_sha256" ]]; then
  echo "$exe"
  exit 0
fi

rm -rf "$dest"
work="$(mktemp -d "$1/download.XXXXXX")"
trap 'rm -rf "$work"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/cvc5.zip" "$url"
got="$(sum "$work/cvc5.zip")"
if [[ "$got" != "$sha256" ]]; then
  echo "cvc5: archive sha256 $got does not match the pin $sha256" >&2
  exit 1
fi
mkdir -p "$work/x"
unzip -q "$work/cvc5.zip" -d "$work/x"
got="$(sum "$work/x/$binary")"
if [[ "$got" != "$binary_sha256" ]]; then
  echo "cvc5: binary sha256 $got does not match the pin $binary_sha256" >&2
  exit 1
fi
mv "$work/x" "$dest"
chmod 0555 "$exe"
echo "$exe"
