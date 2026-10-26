#!/usr/bin/env bash
# OQ-MD3, OP-131: failover and logical-decoding scenarios that need cluster control; local only.
# Builds a primary and a synchronous streaming standby under target/oq-md3 and prints one
# PASS/LOSS line per candidate and scenario.
set -euo pipefail

bin="${PG_BIN:-$(pg_config --bindir 2>/dev/null || echo /opt/homebrew/opt/postgresql@18/bin)}"
root="$PWD/target/oq-md3"
p1=55441
p2=55442
export PGUSER=postgres PGHOST=127.0.0.1 PGDATABASE=postgres

stop() { "$bin/pg_ctl" -D "$1" -m immediate -w stop >/dev/null 2>&1 || true; }
q() { "$bin/psql" -X -q -A -t -v ON_ERROR_STOP=1 -p "$1" -c "$2"; }

cleanup() { stop "$root/primary"; stop "$root/standby"; }
trap cleanup EXIT
cleanup
rm -rf "$root"
mkdir -p "$root"

"$bin/initdb" -D "$root/primary" -U postgres --auth=trust --data-checksums -E UTF8 --locale=C >/dev/null
cat >> "$root/primary/postgresql.conf" <<CONF
listen_addresses = '127.0.0.1'
unix_socket_directories = '$root'
wal_level = logical
max_wal_senders = 8
max_replication_slots = 8
synchronous_commit = on
synchronous_standby_names = 'ANY 1 (standby)'
max_slot_wal_keep_size = 1MB
wal_keep_size = 0
CONF
echo "host replication postgres 127.0.0.1/32 trust" >> "$root/primary/pg_hba.conf"
"$bin/pg_ctl" -D "$root/primary" -l "$root/primary.log" -w -o "-p $p1" start >/dev/null

"$bin/pg_basebackup" -h 127.0.0.1 -p $p1 -U postgres -D "$root/standby" -R -X stream -C -S standby_slot >/dev/null
echo "primary_conninfo = 'host=127.0.0.1 port=$p1 user=postgres application_name=standby'" >> "$root/standby/postgresql.auto.conf"
"$bin/pg_ctl" -D "$root/standby" -l "$root/standby.log" -w -o "-p $p2" start >/dev/null
until [[ "$(q $p1 "SELECT count(*) FROM pg_stat_replication WHERE sync_state IN ('sync','quorum')")" == 1 ]]; do sleep 0.2; done

q $p1 "CREATE TABLE ob (id bigint GENERATED ALWAYS AS IDENTITY, xid xid8 NOT NULL DEFAULT pg_current_xact_id(), v int NOT NULL, PRIMARY KEY (id))"
q $p1 "CREATE TABLE cur (c text PRIMARY KEY, xid xid8 NOT NULL, id bigint NOT NULL)"
q $p1 "INSERT INTO cur VALUES ('a', '0', 0)"

# candidate A poll: everything below the watermark after the stored cursor, then ack
poll_a() {
  q "$1" "WITH b AS (SELECT o.xid, o.id, o.v FROM ob o, cur c WHERE c.c = 'a' AND o.xid < pg_snapshot_xmin(pg_current_snapshot()) AND (o.xid, o.id) > (c.xid, c.id) ORDER BY o.xid, o.id),
          m AS (SELECT xid, id FROM b ORDER BY xid DESC, id DESC LIMIT 1),
          u AS (UPDATE cur SET xid = m.xid, id = m.id FROM m WHERE cur.c = 'a' RETURNING 1)
          SELECT count(*) FROM b, (SELECT count(*) FROM u) x"
}

# --- candidate A, scenario 5: failover to the synchronous standby
q $p1 "INSERT INTO ob (v) SELECT g FROM generate_series(1, 500) g"
got1="$(poll_a $p1)"
q $p1 "INSERT INTO ob (v) SELECT g FROM generate_series(501, 1000) g"
stop "$root/primary"
"$bin/pg_ctl" -D "$root/standby" -w promote >/dev/null
# the promoted standby inherited the primary's settings; it has no standby of its own yet
q $p2 "ALTER SYSTEM SET synchronous_standby_names = ''"
q $p2 "SELECT pg_reload_conf()" >/dev/null
q $p2 "INSERT INTO ob (v) SELECT g FROM generate_series(1001, 1200) g"
got2="$(poll_a $p2)"
if [[ $((got1 + got2)) == 1200 ]]; then echo "A  5 failover                PASS  ($got1 + $got2 of 1200)"; else echo "A  5 failover                LOSS  ($got1 + $got2 of 1200)"; fi

# rebuild a primary with a logical slot for candidate B
stop "$root/standby"
rm -rf "$root/primary" "$root/standby"
"$bin/initdb" -D "$root/primary" -U postgres --auth=trust --data-checksums -E UTF8 --locale=C >/dev/null
cat >> "$root/primary/postgresql.conf" <<CONF
listen_addresses = '127.0.0.1'
unix_socket_directories = '$root'
wal_level = logical
max_wal_senders = 8
max_replication_slots = 8
max_slot_wal_keep_size = 1MB
wal_keep_size = 0
CONF
echo "host replication postgres 127.0.0.1/32 trust" >> "$root/primary/pg_hba.conf"
"$bin/pg_ctl" -D "$root/primary" -l "$root/primary.log" -w -o "-p $p1" start >/dev/null
q $p1 "CREATE TABLE ob (id bigint GENERATED ALWAYS AS IDENTITY, v int NOT NULL, PRIMARY KEY (id))"
q $p1 "SELECT pg_create_logical_replication_slot('b', 'test_decoding')" >/dev/null

changes() { q $p1 "SELECT count(*) FROM pg_logical_slot_get_changes('b', NULL, NULL) WHERE data LIKE 'table public.ob: INSERT%'" 2>/dev/null || echo "slot-gone"; }

# --- candidate B, scenario 4: restart (consumer reconnects)
q $p1 "INSERT INTO ob (v) SELECT g FROM generate_series(1, 100) g"
r="$(changes)"
if [[ "$r" == 100 ]]; then echo "B  4 consumer restart        PASS  ($r of 100)"; else echo "B  4 consumer restart        LOSS  ($r of 100)"; fi

# --- candidate B, scenario 3: consumer away longer than the slot's WAL retention
q $p1 "INSERT INTO ob (v) VALUES (1)"
q $p1 "CREATE TABLE filler AS SELECT g, repeat('x', 200) AS pad FROM generate_series(1, 60000) g"
q $p1 "CHECKPOINT"
q $p1 "SELECT pg_switch_wal()" >/dev/null
q $p1 "CHECKPOINT"
state="$(q $p1 "SELECT coalesce(invalidation_reason, wal_status) FROM pg_replication_slots WHERE slot_name = 'b'")"
r="$(changes)"
if [[ "$r" == 1 ]]; then echo "B  3 outage beyond retention PASS  (slot $state)"; else echo "B  3 outage beyond retention LOSS  (slot $state, got: $r)"; fi

# --- candidate B, scenario 5: failover without slot synchronisation
q $p1 "SELECT pg_create_logical_replication_slot('b2', 'test_decoding')" >/dev/null
"$bin/pg_basebackup" -h 127.0.0.1 -p $p1 -U postgres -D "$root/standby" -R -X stream >/dev/null
"$bin/pg_ctl" -D "$root/standby" -l "$root/standby.log" -w -o "-p $p2" start >/dev/null
q $p1 "INSERT INTO ob (v) SELECT g FROM generate_series(1, 10) g"
sleep 1
stop "$root/primary"
"$bin/pg_ctl" -D "$root/standby" -w promote >/dev/null
slots="$(q $p2 "SELECT count(*) FROM pg_replication_slots WHERE slot_name = 'b2'")"
if [[ "$slots" == 1 ]]; then echo "B  5 failover                PASS"; else echo "B  5 failover                LOSS  (slot missing on the promoted standby)"; fi
