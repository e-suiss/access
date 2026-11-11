#!/usr/bin/env bash
# OP-68: installs Ubuntu packages on a CI runner. The runner's sources point at the Azure package
# mirror; when that name does not resolve, the sources are pointed at the Ubuntu archive and
# security hosts and the install runs again. Nothing is installed from anywhere else, and apt still
# verifies every package against the archive keys.
#
#   scripts/ci/apt-install.sh <package>...
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <package>..." >&2
  exit 2
fi

apt_install() {
  sudo apt-get -o Acquire::Retries=5 update -q &&
    sudo apt-get -o Acquire::Retries=5 install --yes --no-install-recommends "$@"
}

if apt_install "$@"; then
  exit 0
fi

if getent hosts azure.archive.ubuntu.com >/dev/null; then
  echo "::error::apt install failed and the Azure mirror resolves; not a mirror outage" >&2
  exit 1
fi

echo "::warning::azure.archive.ubuntu.com does not resolve; using archive.ubuntu.com" >&2
for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  [[ -f "$f" ]] || continue
  sudo sed -i 's#azure\.archive\.ubuntu\.com#archive.ubuntu.com#g' "$f"
done
apt_install "$@"
