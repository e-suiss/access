#!/usr/bin/env bash
# CMP-24
set -euo pipefail

device="${ACCESS_IOS_SIM_DEVICE:-}"
if [[ -z "$device" ]]; then
  device="$(xcrun simctl list devices booted -j | python3 -c 'import json,sys;d=[x["udid"] for v in json.load(sys.stdin)["devices"].values() for x in v];print(d[0] if d else "")')"
fi
if [[ -z "$device" ]]; then
  device="$(xcrun simctl list devices available -j | python3 -c 'import json,sys;d=[x["udid"] for k,v in json.load(sys.stdin)["devices"].items() if "iOS" in k for x in v];print(d[0] if d else "")')"
  [[ -n "$device" ]] || { echo "no iOS simulator available" >&2; exit 1; }
  xcrun simctl boot "$device"
fi
binary="$1"; shift
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
cp "$binary" "$workdir/"
xcrun simctl spawn "$device" "$workdir/$(basename "$binary")" "$@" </dev/null
