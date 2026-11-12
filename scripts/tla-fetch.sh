#!/usr/bin/env bash
# OP-159 m.3 (x), F-2
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <directory>" >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$root/supply-chain/tla.toml"

fields="$(python3 -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    pin = tomllib.load(f)
print(pin["version"], pin["url"], pin["sha256"])
' "$pin")"
read -r version url sha256 <<<"$fields"

if command -v sha256sum >/dev/null; then
  sum() { sha256sum "$1" | cut -d' ' -f1; }
else
  sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

mkdir -p "$1"
dest="$(cd "$1" && pwd)/tla2tools-$version.jar"
if [[ -f "$dest" && "$(sum "$dest")" == "$sha256" ]]; then
  echo "$dest"
  exit 0
fi

work="$(mktemp -d "$1/download.XXXXXX")"
trap 'rm -rf "$work"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/tla2tools.jar" "$url"
got="$(sum "$work/tla2tools.jar")"
if [[ "$got" != "$sha256" ]]; then
  echo "tla: jar sha256 $got does not match the pin $sha256" >&2
  exit 1
fi
mv "$work/tla2tools.jar" "$dest"
echo "$dest"
