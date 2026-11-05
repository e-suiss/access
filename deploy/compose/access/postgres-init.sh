#!/bin/sh
# OP-130 m.2, OP-55, OP-73: the database administrator's setup for a local deployment, run by
# the postgres image at its first start: the cluster roles, one login per role, the database and
# its per-database setup. Migrations are `access-server migrate`'s job.
set -eu

dir=/docker-entrypoint-initdb.d

psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -f "$dir/sql/roles.sql"
while read -r login role password; do
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres \
        -v login="$login" -v role="$role" -v password="$password" <<'SQL'
CREATE ROLE :"login" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'password' IN ROLE :"role";
SQL
done < "$dir/logins"
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c "CREATE DATABASE access"
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d access -f "$dir/sql/database.sql"
