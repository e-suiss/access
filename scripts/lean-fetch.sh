#!/usr/bin/env bash
# OP-119 m.3, F-2
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <directory>" >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$root/supply-chain/lean.toml"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-x86_64 ;;
  Linux-aarch64 | Linux-arm64) platform=linux-aarch64 ;;
  Darwin-arm64) platform=macos-aarch64 ;;
  *) echo "lean: no pinned build for $(uname -s)-$(uname -m) in $pin" >&2; exit 1 ;;
esac

fields="$(python3 -I -c '
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    pin = tomllib.load(f)
p = pin["platform"][sys.argv[2]]
print(pin["version"], p["url"], p["sha256"], p["dir"])
' "$pin" "$platform")"
read -r version url sha256 dir <<<"$fields"

toolchain="$(tr -d '[:space:]' <"$root/conformance/lean/lean-toolchain")"
if [[ "$toolchain" != "leanprover/lean4:v$version" ]]; then
  echo "lean: lean-toolchain says $toolchain, $pin pins $version" >&2
  exit 1
fi

if command -v sha256sum >/dev/null; then
  sum() { sha256sum "$1" | cut -d' ' -f1; }
else
  sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

mkdir -p "$1"
dest="$(cd "$1" && pwd)/$dir"
if [[ -f "$dest/.sha256" && "$(cat "$dest/.sha256")" == "$sha256" && -x "$dest/bin/lake" ]]; then
  echo "$dest/bin"
  exit 0
fi

rm -rf "$dest"
work="$(mktemp -d "$1/download.XXXXXX")"
trap 'rm -rf "$work"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/lean.tar.zst" "$url"
got="$(sum "$work/lean.tar.zst")"
if [[ "$got" != "$sha256" ]]; then
  echo "lean: archive sha256 $got does not match the pin $sha256" >&2
  exit 1
fi
mkdir -p "$work/x"
tar --zstd -xf "$work/lean.tar.zst" -C "$work/x"
rm "$work/lean.tar.zst"
mv "$work/x/$dir" "$dest"
echo "$sha256" >"$dest/.sha256"
echo "$dest/bin"
