#!/usr/bin/env bash
# OP-69, SA-59: nextest wrapper giving each test process its own SoftHSM token store next to the
# one `just test` prepares, so that one process's token initialisation never races another
# process's key writes.
set -euo pipefail
: "${SOFTHSM2_CONF:?run the PKCS#11 tests through just test, which sets SOFTHSM2_CONF (OP-69)}"
root="$(dirname "$SOFTHSM2_CONF")/process"
mkdir -p "$root"
dir="$(mktemp -d "$root/p.XXXXXX")"
trap 'rm -rf "$dir"' EXIT
mkdir "$dir/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$dir/tokens" > "$dir/softhsm2.conf"
SOFTHSM2_CONF="$dir/softhsm2.conf" "$@"
