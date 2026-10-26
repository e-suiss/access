#!/usr/bin/env bash
# F-2, OP-127 m.2
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <vendor-dir> <allowlist>" >&2
  exit 2
fi
vendor="$1"
allowlist="$2"
if command -v sha256sum >/dev/null; then sha=(sha256sum); else sha=(shasum -a 256); fi

found="$(cd "$vendor" && find . -type d \( -name .vscode -o -name .devcontainer -o -name .githooks -o -name .idea \) -prune -print \
  | sed 's|^\./||' | while read -r dir; do find "$dir" -type f; done | LC_ALL=C sort | while read -r f; do "${sha[@]}" "$f"; done)"
allowed="$(grep -v '^#' "$allowlist" | grep . | LC_ALL=C sort -k2 || true)"
unreviewed="$(LC_ALL=C comm -23 <(printf '%s\n' "$found" | grep . | LC_ALL=C sort) <(printf '%s\n' "$allowed" | LC_ALL=C sort) || true)"
if [[ -n "$unreviewed" ]]; then
  echo "vendored IDE/hook files not in $allowlist (F-2):" >&2
  printf '%s\n' "$unreviewed" >&2
  exit 1
fi
