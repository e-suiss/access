#!/usr/bin/env bash
# CR-39 m.5, OP-84, OP-159 m.1 (a)
#
#   deploy/bench-runner/preflight.sh
#
# Refuses to start a constant-time measurement on a noisy machine: isolated cores, the
# `performance` governor, turbo and SMT off, no second job, and the machine idle. Every check
# fails closed: a value it cannot read is a failure, never a pass.
set -euo pipefail

IDLE_LOAD="${BENCH_IDLE_LOAD:-0.30}"
IDLE_WAIT_S="${BENCH_IDLE_WAIT_S:-600}"
IDLE_STEP_S=15
SYS=/sys/devices/system/cpu

failures=0
fail() { echo "preflight: $*" >&2; failures=$((failures + 1)); }
ok() { echo "preflight: ok: $*"; }

[[ "$(uname -s)" == Linux ]] || { echo "preflight: Linux only" >&2; exit 1; }

isolated="$(cat "$SYS/isolated" 2>/dev/null || true)"
if [[ -n "$isolated" ]]; then
  ok "isolated cores $isolated"
else
  fail "no isolated cores; boot with isolcpus=<cores> nohz_full=<cores> rcu_nocbs=<cores>"
fi

affinity="$(taskset -cp $$ 2>/dev/null | awk -F': ' '{print $2}')"
if [[ -n "$isolated" && "$affinity" == "$isolated" ]]; then
  ok "job pinned to $affinity"
else
  fail "job runs on cores '${affinity:-unknown}', not on the isolated cores '${isolated:-none}'; set BENCH_CPUS in setup.sh"
fi

governors=0
for g in "$SYS"/cpu[0-9]*/cpufreq/scaling_governor; do
  [[ -r "$g" ]] || continue
  governors=$((governors + 1))
  value="$(cat "$g")"
  [[ "$value" == performance ]] || fail "$g is '$value', not performance"
done
if [[ "$governors" -gt 0 ]]; then ok "$governors governors read"; else fail "no cpufreq governor readable"; fi

if [[ -r "$SYS/intel_pstate/no_turbo" ]]; then
  if [[ "$(cat "$SYS/intel_pstate/no_turbo")" == 1 ]]; then ok "turbo off (intel_pstate)"; else fail "turbo on (intel_pstate/no_turbo is not 1)"; fi
elif [[ -r "$SYS/cpufreq/boost" ]]; then
  if [[ "$(cat "$SYS/cpufreq/boost")" == 0 ]]; then ok "boost off"; else fail "boost on (cpufreq/boost is not 0)"; fi
else
  fail "turbo state unreadable (no intel_pstate/no_turbo, no cpufreq/boost)"
fi

smt="$(cat "$SYS/smt/control" 2>/dev/null || echo unknown)"
case "$smt" in
  off | forceoff | notsupported) ok "SMT $smt" ;;
  *) fail "SMT is '$smt'; switch it off (echo off > $SYS/smt/control)" ;;
esac

workers="$(pgrep -c -f 'Runner.Worker' 2>/dev/null || true)"
if [[ "${workers:-0}" -le 1 ]]; then
  ok "one job on this machine"
else
  fail "$workers runner jobs at once; the bench runner takes one job at a time"
fi

if [[ "$failures" -gt 0 ]]; then
  echo "preflight: $failures check(s) failed; no measurement taken" >&2
  exit 1
fi

waited=0
while :; do
  load="$(cut -d' ' -f1 /proc/loadavg)"
  if awk -v l="$load" -v m="$IDLE_LOAD" 'BEGIN { exit !(l < m) }'; then
    ok "idle (1-minute load $load < $IDLE_LOAD) after ${waited}s"
    break
  fi
  if [[ "$waited" -ge "$IDLE_WAIT_S" ]]; then
    echo "preflight: not idle after ${IDLE_WAIT_S}s (1-minute load $load); no measurement taken" >&2
    exit 1
  fi
  sleep "$IDLE_STEP_S"
  waited=$((waited + IDLE_STEP_S))
done

{
  echo "kernel: $(uname -srm)"
  echo "cmdline: $(cat /proc/cmdline)"
  echo "isolated: $isolated"
  echo "affinity: $affinity"
  echo "smt: $smt"
  echo "load: $(cat /proc/loadavg)"
} | tee "${BENCH_PREFLIGHT_OUT:-/dev/null}"
