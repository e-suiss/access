#!/usr/bin/env bash
# OP-24, OP-25, OP-158 m.3 (n): a replicated PostgreSQL 18 cell for failover tests, one primary and
# two synchronous standbys under `synchronous_standby_names = 'ANY 1 (sb_a, sb_b)'`, with the
# fault helpers the tests drive (SIGKILL, SIGSTOP, promote, rejoin, PITR). Native mode runs the
# local binaries; container mode (CI) runs each node in its own container on the host network.
# It never touches the shared store-test cluster (scripts/pg-local.sh).
#
#   ACCESS_PG_HA_PORT  first of three ports (default 55440: primary, sb_a = +1, sb_b = +2)
#   ACCESS_PG_HA_DIR   data directory (default target/pg-ha)
#   ACCESS_PG_HA_MODE  native | container (default native)
#   ACCESS_PG_HA_IMAGE container image (container mode)
set -euo pipefail

port="${ACCESS_PG_HA_PORT:-55440}"
dir="${ACCESS_PG_HA_DIR:-$PWD/target/pg-ha}"
mode="${ACCESS_PG_HA_MODE:-native}"
image="${ACCESS_PG_HA_IMAGE:-postgres:18}"
bin="${PG_BIN:-$(pg_config --bindir 2>/dev/null || echo /opt/homebrew/opt/postgresql@18/bin)}"
password="local-only-not-a-secret"
nodes=(primary sb_a sb_b)
export PGUSER=postgres PGPASSWORD="$password" PGHOST=127.0.0.1 PGDATABASE=postgres PGCONNECT_TIMEOUT=5

die() { echo "pg-ha: $*" >&2; exit 1; }

node_port() {
  case "$1" in
    primary) echo "$port" ;;
    sb_a) echo $((port + 1)) ;;
    sb_b) echo $((port + 2)) ;;
    *) die "unknown node $1" ;;
  esac
}

container() { echo "access-pg-ha-${port}-$1"; }

data() {
  if [[ "$mode" == container ]]; then echo /var/lib/postgresql/data/pgdata; else echo "$dir/$1"; fi
}

# runs a PostgreSQL tool for node $1
tool() {
  local node="$1" name="$2"
  shift 2
  if [[ "$mode" == container ]]; then
    docker exec -u postgres -e PGPASSWORD="$password" "$(container "$node")" "$name" "$@"
  else
    "$bin/$name" "$@"
  fi
}

q() { tool "$1" psql -X -q -A -t -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$(node_port "$1")" -c "$2"; }

conf() {
  cat <<CONF
listen_addresses = '127.0.0.1'
port = $(node_port "$1")
max_connections = 200
password_encryption = 'scram-sha-256'
wal_level = replica
wal_log_hints = on
max_wal_senders = 10
max_replication_slots = 10
hot_standby = on
synchronous_commit = on
synchronous_standby_names = 'ANY 1 (sb_a, sb_b)'
track_commit_timestamp = on
archive_mode = on
archive_command = 'test ! -f $(archive)/%f && cp %p $(archive)/%f'
CONF
}

archive() {
  if [[ "$mode" == container ]]; then echo /var/lib/postgresql/archive; else echo "$dir/archive"; fi
}

start_node() {
  local node="$1"
  if [[ "$mode" == container ]]; then
    docker start "$(container "$node")" >/dev/null
  else
    "$bin/pg_ctl" -D "$(data "$node")" -l "$dir/$node.log" -w -t 60 -o "-k $dir" start >/dev/null
  fi
  wait_up "$node"
}

wait_up() {

  for _ in $(seq 1 300); do
    if tool "$1" pg_isready -q -h 127.0.0.1 -p "$(node_port "$1")" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  die "$1 did not come up"
}

# postmaster pid of node $1 (native mode)
pid() {
  head -1 "$(data "$1")/postmaster.pid" 2>/dev/null || die "$1 is not running"
}

# the postmaster and every backend of node $1
pids() {
  local p
  p="$(pid "$1")"
  echo "$p"
  pgrep -P "$p" || true
}

signal() {
  local sig="$1" node="$2"
  if [[ "$mode" == container ]]; then
    case "$sig" in
      STOP) docker pause "$(container "$node")" >/dev/null ;;
      CONT) docker unpause "$(container "$node")" >/dev/null ;;
      *) docker kill --signal "$sig" "$(container "$node")" >/dev/null ;;
    esac
  else
    # shellcheck disable=SC2046
    kill -s "$sig" $(pids "$node")
  fi
}

standby_of() {
  local node="$1" upstream="$2"
  cat <<CONF
primary_conninfo = 'host=127.0.0.1 port=$(node_port "$upstream") user=postgres password=$password application_name=$node'
CONF
}

stop_all() {
  local n
  set -- "${1:-}" "${2:-}"
  if [[ "$mode" == native && -f "$dir/pitr/postmaster.pid" ]]; then
    "$bin/pg_ctl" -D "$dir/pitr" -m immediate -w stop >/dev/null 2>&1 || true
  fi
  for n in "${nodes[@]}"; do
    if [[ "$mode" == container ]]; then
      docker rm -f "$(container "$n")" >/dev/null 2>&1 || true
      [[ "${2:-}" == wipe ]] && docker volume rm -f "$(volume "$n")" >/dev/null 2>&1 || true
    else
      if [[ -f "$(data "$n")/postmaster.pid" ]]; then
        # shellcheck disable=SC2046
        kill -s CONT $(pids "$n") 2>/dev/null || true
        "$bin/pg_ctl" -D "$(data "$n")" -m immediate -w stop >/dev/null 2>&1 || true
      fi
    fi
  done
}

volume() { echo "access-pg-ha-${port}-$1"; }

run_node() {
  local node="$1"
  shift
  docker run -d --name "$(container "$node")" --network host \
    -v "$(volume "$node"):/var/lib/postgresql/data" -v "$(volume archive):$(archive)" \
    -e POSTGRES_PASSWORD="$password" -e PGDATA="$(data "$node")" "$@" >/dev/null
}

init_primary() {
  if [[ "$mode" == container ]]; then
    run_node primary -e POSTGRES_INITDB_ARGS="--auth=scram-sha-256 --data-checksums" \
      "$image" -c "port=$(node_port primary)"
    wait_up primary
    docker exec -u root "$(container primary)" chown postgres "$(archive)"
    conf primary | docker exec -i -u postgres "$(container primary)" sh -c "cat >> $(data primary)/postgresql.conf"
    echo "host replication postgres 127.0.0.1/32 scram-sha-256" |
      docker exec -i -u postgres "$(container primary)" sh -c "cat >> $(data primary)/pg_hba.conf"
    docker restart "$(container primary)" >/dev/null
    wait_up primary
  else
    printf '%s\n' "$password" > "$dir/pwfile"
    "$bin/initdb" -D "$(data primary)" -U postgres --pwfile="$dir/pwfile" --auth=scram-sha-256 \
      --data-checksums -E UTF8 --locale=C >/dev/null
    conf primary >> "$(data primary)/postgresql.conf"
    echo "host replication postgres 127.0.0.1/32 scram-sha-256" >> "$(data primary)/pg_hba.conf"
    start_node primary
  fi
}

init_standby() {
  local node="$1"
  if [[ "$mode" == container ]]; then
    docker run --rm --network host -v "$(volume "$node"):/var/lib/postgresql/data" \
      -e PGPASSWORD="$password" --entrypoint sh "$image" -c \
      "mkdir -p $(data "$node") && chown postgres $(data "$node") && chmod 700 $(data "$node") &&
       gosu postgres pg_basebackup -h 127.0.0.1 -p $(node_port primary) -U postgres -D $(data "$node") -R -X stream &&
       printf '%s\n' \"port = $(node_port "$node")\" \"$(standby_of "$node" primary)\" >> $(data "$node")/postgresql.auto.conf"
    run_node "$node" "$image"
    wait_up "$node"
  else
    "$bin/pg_basebackup" -h 127.0.0.1 -p "$(node_port primary)" -U postgres -D "$(data "$node")" -R -X stream
    { echo "port = $(node_port "$node")"; standby_of "$node" primary; } >> "$(data "$node")/postgresql.auto.conf"
    start_node "$node"
  fi
}

# waits until $1 sees $2 standbys in the synchronous quorum
wait_sync() {
  local node="${1:-primary}" want="${2:-2}"
  for _ in $(seq 1 300); do
    if [[ "$(q "$node" "SELECT count(*) FROM pg_stat_replication WHERE sync_state IN ('sync', 'quorum')" 2>/dev/null)" == "$want" ]]; then
      return 0
    fi
    sleep 0.1
  done
  die "$node has fewer than $want synchronous standbys"
}

url() { echo "postgres://postgres:$password@127.0.0.1:$(node_port "${1:-primary}")/postgres"; }

role() {
  case "$(q "$1" "SELECT pg_is_in_recovery()" 2>/dev/null || echo down)" in
    f) echo primary ;;
    t) echo standby ;;
    *) echo down ;;
  esac
}

# promotes standby $1 and points the other live standby at it; the old primary stays listed so the
# quorum keeps two names (OP-24) and is satisfied by the live standby
promote() {
  local node="$1" other n
  tool "$node" pg_ctl -D "$(data "$node")" -w -t 60 promote >/dev/null
  for n in "${nodes[@]}"; do
    [[ "$n" == "$node" ]] && continue
    if [[ "$(role "$n")" == standby ]]; then other="$n"; fi
  done
  local names=()
  for n in "${nodes[@]}"; do [[ "$n" != "$node" ]] && names+=("$n"); done
  q "$node" "ALTER SYSTEM SET synchronous_standby_names = 'ANY 1 (${names[0]}, ${names[1]})'"
  q "$node" "SELECT pg_reload_conf()" >/dev/null
  if [[ -n "${other:-}" ]]; then
    q "$other" "ALTER SYSTEM SET primary_conninfo = 'host=127.0.0.1 port=$(node_port "$node") user=postgres password=$password application_name=$other'"
    q "$other" "SELECT pg_reload_conf()" >/dev/null
    wait_sync "$node" 1
  fi
}

# rebuilds the stopped old primary $1 as a fresh standby of the current primary $2
rejoin() {
  local node="$1" upstream="$2"
  [[ "$mode" == native ]] || die "rejoin is native-only"
  "$bin/pg_ctl" -D "$(data "$node")" -m immediate -w stop >/dev/null 2>&1 || true
  rm -rf "$(data "$node")"
  "$bin/pg_basebackup" -h 127.0.0.1 -p "$(node_port "$upstream")" -U postgres -D "$(data "$node")" -R -X stream
  { echo "port = $(node_port "$node")"; standby_of "$node" "$upstream"; } >> "$(data "$node")/postgresql.auto.conf"
  start_node "$node"
}

# restores the base backup taken by `base` into a separate instance on port $2, replayed to the
# recovery target time $1, and prints its URL
pitr() {
  local target="$1" pitr_port="$2" d="$dir/pitr"
  [[ "$mode" == native ]] || die "pitr is native-only"
  [[ -d "$dir/base" ]] || die "no base backup: run base first"
  "$bin/pg_ctl" -D "$d" -m immediate -w stop >/dev/null 2>&1 || true
  rm -rf "$d"
  cp -R "$dir/base" "$d"
  cat >> "$d/postgresql.auto.conf" <<CONF
port = $pitr_port
synchronous_standby_names = ''
archive_mode = off
restore_command = 'cp $dir/archive/%f %p'
recovery_target_time = '$target'
recovery_target_action = 'promote'
CONF
  rm -f "$d/standby.signal"
  touch "$d/recovery.signal"
  "$bin/pg_ctl" -D "$d" -l "$dir/pitr.log" -w -t 120 -o "-k $dir" start >/dev/null

  for _ in $(seq 1 600); do
    if [[ "$("$bin/psql" -X -q -A -t -h 127.0.0.1 -p "$pitr_port" -c 'SELECT pg_is_in_recovery()' 2>/dev/null)" == f ]]; then
      echo "postgres://postgres:$password@127.0.0.1:$pitr_port/postgres"
      return 0
    fi
    sleep 0.1
  done
  die "the PITR instance did not finish recovery"
}

case "${1:-}" in
  up)
    stop_all "" wipe
    [[ "$mode" == container ]] && docker volume rm -f "$(volume archive)" >/dev/null 2>&1 || true
    if [[ "$mode" == native ]]; then
      rm -rf "$dir"
      mkdir -p "$dir/archive"
    fi
    init_primary
    init_standby sb_a
    init_standby sb_b
    wait_sync primary 2
    url primary
    ;;
  down) stop_all ;;
  url) url "${2:-primary}" ;;
  port) node_port "${2:?node}" ;;
  role) role "${2:?node}" ;;
  status) for n in "${nodes[@]}"; do echo "$n $(node_port "$n") $(role "$n")"; done ;;
  kill) signal KILL "${2:?node}" ;;
  stop) signal STOP "${2:?node}" ;;
  cont) signal CONT "${2:?node}" ;;
  start) start_node "${2:?node}" ;;
  promote) promote "${2:?node}" ;;
  rejoin) rejoin "${2:?node}" "${3:?upstream}" ;;
  wait-sync) wait_sync "${2:-primary}" "${3:-2}" ;;
  sql) q "${2:?node}" "${3:?statement}" ;;
  base)
    [[ "$mode" == native ]] || die "base is native-only"
    rm -rf "$dir/base"
    "$bin/pg_basebackup" -h 127.0.0.1 -p "$(node_port "${2:-primary}")" -U postgres -D "$dir/base" -X stream -c fast
    ;;
  pitr) pitr "${2:?target time}" "${3:?port}" ;;
  *)
    echo "usage: $0 up|down|status|url [node]|port node|role node|kill node|stop node|cont node|start node|promote node|rejoin node upstream|wait-sync [node] [n]|sql node statement|base [node]|pitr time port" >&2
    exit 2
    ;;
esac
