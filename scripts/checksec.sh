#!/usr/bin/env bash
# SA-23, §14.5
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <elf-binary>..." >&2
  exit 2
fi
command -v readelf >/dev/null || { echo "readelf not found (install binutils)" >&2; exit 2; }

status=0
for bin in "$@"; do
  if [[ ! -f "$bin" ]]; then
    echo "FAIL  $bin: not found"; status=1; continue
  fi
  header="$(readelf -h -W "$bin")"
  segments="$(readelf -l -W "$bin")"
  dynamic="$(readelf -d -W "$bin" 2>/dev/null || true)"

  pie=no; relro=no; now=no; nx=no
  if grep -Eq 'Type:[[:space:]]+DYN' <<<"$header"; then
    if grep -Eq 'FLAGS_1.*PIE' <<<"$dynamic" || grep -q 'INTERP' <<<"$segments"; then pie=yes; fi
  fi
  grep -q 'GNU_RELRO' <<<"$segments" && relro=yes
  if grep -Eq '\(BIND_NOW\)|\(FLAGS\).*BIND_NOW|\(FLAGS_1\).*NOW' <<<"$dynamic"; then now=yes; fi
  stack="$(grep 'GNU_STACK' <<<"$segments" || true)"
  if [[ -n "$stack" ]] && ! grep -Eq 'RWE|[[:space:]]E[[:space:]]*0x' <<<"$stack"; then nx=yes; fi

  line="PIE=$pie RELRO=$relro BIND_NOW=$now NX=$nx"
  if [[ "$pie$relro$now$nx" == yesyesyesyes ]]; then
    echo "ok    $bin: $line"
  else
    echo "FAIL  $bin: $line"; status=1
  fi
done
exit "$status"
