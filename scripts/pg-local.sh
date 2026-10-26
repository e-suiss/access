#!/usr/bin/env bash
# OP-66, OP-69: a throwaway PostgreSQL cluster under target/pg for store tests, same settings as CI
set -euo pipefail

dir="target/pg"
port="${ACCESS_PG_PORT:-55432}"
bin="${PG_BIN:-$(pg_config --bindir 2>/dev/null || echo /opt/homebrew/opt/postgresql@18/bin)}"
password="local-only-not-a-secret"

case "${1:-}" in
  up)
    if [[ ! -f "$dir/data/PG_VERSION" ]]; then
      mkdir -p "$dir"
      printf '%s\n' "$password" > "$dir/pwfile"
      "$bin/initdb" -D "$dir/data" -U postgres --pwfile="$dir/pwfile" --auth=scram-sha-256 --data-checksums -E UTF8 --locale=C >/dev/null
    fi
    if ! "$bin/pg_ctl" -D "$dir/data" status >/dev/null 2>&1; then
      "$bin/pg_ctl" -D "$dir/data" -l "$dir/log" -w -o "-p $port -k $PWD/$dir -c listen_addresses=127.0.0.1" start >/dev/null
    fi
    echo "postgres://postgres:$password@127.0.0.1:$port/postgres"
    ;;
  down)
    "$bin/pg_ctl" -D "$dir/data" -w stop >/dev/null 2>&1 || true
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
