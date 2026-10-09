#!/usr/bin/env bash
# CMP-24
set -euo pipefail

binary="$1"; shift
remote="/data/local/tmp/$(basename "$binary")"
adb push "$binary" "$remote" >/dev/null
adb shell chmod 755 "$remote"
exec adb shell "$remote" "$@"
