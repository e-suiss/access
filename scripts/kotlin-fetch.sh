#!/usr/bin/env bash
# OP-116 m.6, F-2
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <directory>" >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$root/supply-chain/kotlin.toml"

fields="$(python3 -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    pin = tomllib.load(f)
k, j = pin["kotlinc"], pin["jna"]
print(k["version"], k["url"], k["sha256"], j["version"], j["url"], j["sha256"])
' "$pin")"
read -r kversion kurl ksha256 jversion jurl jsha256 <<<"$fields"

if command -v sha256sum >/dev/null; then
  sum() { sha256sum "$1" | cut -d' ' -f1; }
else
  sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

mkdir -p "$1"
dest="$(cd "$1" && pwd)/kotlinc-$kversion-jna-$jversion"
if [[ -f "$dest/.sha256" && "$(cat "$dest/.sha256")" == "$ksha256 $jsha256" \
  && -x "$dest/kotlinc/bin/kotlinc" && "$(sum "$dest/jna.jar")" == "$jsha256" ]]; then
  echo "$dest"
  exit 0
fi

rm -rf "$dest"
work="$(mktemp -d "$1/download.XXXXXX")"
trap 'rm -rf "$work"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/kotlinc.zip" "$kurl"
got="$(sum "$work/kotlinc.zip")"
if [[ "$got" != "$ksha256" ]]; then
  echo "kotlinc: archive sha256 $got does not match the pin $ksha256" >&2
  exit 1
fi
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/jna.jar" "$jurl"
got="$(sum "$work/jna.jar")"
if [[ "$got" != "$jsha256" ]]; then
  echo "jna: jar sha256 $got does not match the pin $jsha256" >&2
  exit 1
fi
mkdir -p "$work/x"
unzip -q "$work/kotlinc.zip" -d "$work/x"
mv "$work/jna.jar" "$work/x/jna.jar"
mv "$work/x" "$dest"
echo "$ksha256 $jsha256" >"$dest/.sha256"
echo "$dest"
