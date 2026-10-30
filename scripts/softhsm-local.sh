#!/usr/bin/env bash
# OP-69: a fresh SoftHSM token store under target/softhsm for the PKCS#11 tests; prints the
# configuration path for SOFTHSM2_CONF.
set -euo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)/target/softhsm"
rm -rf "$dir"
mkdir -p "$dir/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$dir/tokens" > "$dir/softhsm2.conf"
echo "$dir/softhsm2.conf"
