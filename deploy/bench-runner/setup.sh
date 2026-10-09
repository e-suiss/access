#!/usr/bin/env bash
# OP-72, OP-84
set -euo pipefail

REPO_URL="https://github.com/e-suiss/access"
RUNNER_VERSION="2.337.0" # F-2: released 2026-08-26
declare -A RUNNER_SHA256=(
  [x64]=70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613
  [arm64]=9b1dc70626422526e3c94767cf024896beb15da5342a3f4819bf2feac13e0393
)
RUNNER_USER="gh-bench"
RUNNER_HOME="/var/lib/gh-bench"
RUNNER_DIR="/opt/actions-runner"
SERVICE="actions-runner-bench"

die() { echo "error: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo $0)"
[[ "$(uname -s)" == Linux ]] || die "Linux only"
command -v systemctl >/dev/null || die "systemd is required"
command -v apt-get >/dev/null || die "this script expects a Debian/Ubuntu host"

case "$(uname -m)" in
  x86_64) arch=x64 ;;
  aarch64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

echo "==> Packages (build tools, git, rustup)"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
  build-essential ca-certificates curl git jq pkg-config rustup linux-cpupower

echo "==> Unprivileged runner user ($RUNNER_USER, no sudo, no login shell)"
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$RUNNER_HOME" --create-home --shell /usr/sbin/nologin "$RUNNER_USER"
fi
install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0750 "$RUNNER_DIR"

echo "==> GitHub Actions runner $RUNNER_VERSION ($arch), checksum verified"
tarball="actions-runner-linux-$arch-$RUNNER_VERSION.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$tarball" "https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/$tarball"
echo "${RUNNER_SHA256[$arch]}  $tmp/$tarball" | sha256sum --check --strict
if [[ ! -f "$RUNNER_DIR/config.sh" ]]; then
  tar -xzf "$tmp/$tarball" -C "$RUNNER_DIR"
  chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"
  "$RUNNER_DIR/bin/installdependencies.sh"
fi

echo "==> Rust toolchain manager for the runner user"
runuser -u "$RUNNER_USER" -- env HOME="$RUNNER_HOME" rustup set profile minimal
runuser -u "$RUNNER_USER" -- env HOME="$RUNNER_HOME" rustup default stable >/dev/null

if [[ ! -f "$RUNNER_DIR/.runner" ]]; then
  echo "==> Registration"
  echo "Create a token: gh api -X POST repos/e-suiss/access/actions/runners/registration-token --jq .token"
  read -r -s -p "Registration token (input hidden, not stored): " token
  echo
  [[ -n "$token" ]] || die "empty token"
  runuser -u "$RUNNER_USER" -- env HOME="$RUNNER_HOME" "$RUNNER_DIR/config.sh" \
    --unattended \
    --url "$REPO_URL" \
    --token "$token" \
    --name "${RUNNER_NAME:-$(hostname -s)}" \
    --labels bench \
    --work _work \
    --replace
  unset token
fi

echo "==> CPU frequency: performance governor, no turbo, at every boot"
cat > /etc/systemd/system/bench-cpu-tuning.service <<'UNIT'
[Unit]
Description=Stable CPU frequency for benchmarks (OP-72)
After=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/cpupower frequency-set --governor performance
ExecStart=/bin/sh -c 'if [ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]; then echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo; fi; if [ -w /sys/devices/system/cpu/cpufreq/boost ]; then echo 0 > /sys/devices/system/cpu/cpufreq/boost; fi'

[Install]
WantedBy=multi-user.target
UNIT

echo "==> Runner service ($SERVICE)"
affinity=""
[[ -n "${BENCH_CPUS:-}" ]] && affinity="CPUAffinity=$BENCH_CPUS"
cat > "/etc/systemd/system/$SERVICE.service" <<UNIT
[Unit]
Description=GitHub Actions runner for Access benchmarks (OP-84)
After=network-online.target bench-cpu-tuning.service
Wants=network-online.target bench-cpu-tuning.service

[Service]
User=$RUNNER_USER
Group=$RUNNER_USER
WorkingDirectory=$RUNNER_DIR
Environment=HOME=$RUNNER_HOME
ExecStart=$RUNNER_DIR/run.sh
Restart=always
RestartSec=10
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=5min
$affinity
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$RUNNER_DIR $RUNNER_HOME
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now bench-cpu-tuning.service
systemctl enable --now "$SERVICE.service"
systemctl --no-pager --lines=5 status "$SERVICE.service" || true
echo "Done. Check the runner at $REPO_URL/settings/actions/runners."
