#!/usr/bin/env bash
# HL-40, OP-48, T8, T36, OP-158 m.3 (p): the small-provider install, one command on one host. It
# needs the three binaries in /usr/local/bin, a reachable PostgreSQL 18 with the Access roles
# (crates/store/bootstrap/roles.sql), a PKCS#11 module with the three tokens, and the configuration
# files of this directory filled in under /etc/access with their secret files beside them.
#
#   sudo deploy/small-provider/install.sh [/etc/access/access.toml]
set -euo pipefail

config="${1:-/etc/access/access.toml}"
here="$(cd "$(dirname "$0")" && pwd)"

fail() {
  echo "install: $*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
for bin in access-server access-signer access-identity-signer; do
  [ -x "/usr/local/bin/$bin" ] || fail "/usr/local/bin/$bin is missing"
done
for file in "$config" /etc/access/access-signer.toml /etc/access/access-identity-signer.toml; do
  [ -r "$file" ] || fail "$file is missing"
done
grep -q '^durability = "single-node"' "$config" ||
  fail "$config does not declare durability = \"single-node\""
if grep -Eiq '^(host|name) *= *"(sqlite|file:)' "$config"; then
  fail "SQLite is not supported; Access runs on PostgreSQL only"
fi

if ! id access >/dev/null 2>&1; then
  useradd --system --uid 65532 --user-group --home-dir /var/lib/access --shell /usr/sbin/nologin access
fi
install -d -m 0750 -o access -g access /var/lib/access
install -d -m 0700 -o access -g access /var/lib/access/signer /var/lib/access/identity-signer
for unit in access-signer access-identity-signer access-server; do
  install -m 0644 "$here/systemd/$unit.service" "/etc/systemd/system/$unit.service"
done
systemctl daemon-reload

echo "install: provisioning the signers' keys"
runuser -u access -- env ACCESS_SIGNER_CONFIG=/etc/access/access-signer.toml \
  /usr/local/bin/access-signer init
runuser -u access -- env ACCESS_IDENTITY_SIGNER_CONFIG=/etc/access/access-identity-signer.toml \
  /usr/local/bin/access-identity-signer init

echo "install: migrating the schema"
runuser -u access -- env ACCESS_CONFIG="$config" /usr/local/bin/access-server migrate

systemctl enable --now access-signer access-identity-signer
if [ -r /etc/access/bootstrap.toml ]; then
  echo "install: bootstrapping the tenants of /etc/access/bootstrap.toml"
  runuser -u access -- env ACCESS_CONFIG="$config" \
    /usr/local/bin/access-server bootstrap /etc/access/bootstrap.toml
fi
systemctl enable --now access-server
echo "install: access-server is starting; it publishes durability: single-node"
