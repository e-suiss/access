#!/usr/bin/env bash
# OP-69, OP-159 m.35: SoftHSM 2.7.0 built from its pinned source. Ubuntu 24.04's 2.6.1 fails a
# token write while another thread or process reads the token (upstream issue 573, fixed in
# 2.7.0), which made the multi-process PKCS#11 tests flaky. Installs where the package would:
# /usr/lib/softhsm/libsofthsm2.so and /usr/bin/softhsm2-util.
#
#   scripts/ci/softhsm.sh [<other apt package>...]
set -euo pipefail

version=2.7.0
commit=13e6e86b83748fef74046dbf0c91f664b7acc1c3
sha256=be14a5820ec457eac5154462ffae51ba5d8a643f6760514d4b4b83a77be91573

here="$(cd "$(dirname "$0")" && pwd)"
"$here/apt-install.sh" autoconf automake libtool pkg-config make g++ libssl-dev "$@"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 5 "https://github.com/softhsm/SoftHSMv2/archive/refs/tags/$version.tar.gz" -o "$work/src.tar.gz"
echo "$sha256  $work/src.tar.gz" | sha256sum --check --strict -
tar -xzf "$work/src.tar.gz" -C "$work"
cd "$work/SoftHSMv2-$version"
sh autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib \
  --with-crypto-backend=openssl --disable-gost --disable-dependency-tracking >/dev/null
make -j"$(nproc)" >/dev/null
sudo make install >/dev/null
sudo mkdir -p /var/lib/softhsm/tokens
softhsm2-util --version | grep -qx "$version"
echo "SoftHSM $version ($commit)"
