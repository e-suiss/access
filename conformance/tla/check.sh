#!/usr/bin/env bash
# CR-48 m.5, F20, OP-159 m.3 (x)
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tla2tools.jar>" >&2
  exit 2
fi
jar="$1"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$here"

tlc() {
  java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -deadlock -cleanup \
    -metadir "$work/$1-$2" -config "$2.cfg" "$1.tla"
}

for run in Commit:Commit HandoverRecovery:HandoverRecovery HandoverRecovery:HandoverRecoveryLossy \
  AckBeforeWitness:AckBeforeWitness PqReanchor:PqReanchor; do
  model="${run%%:*}"
  cfg="${run##*:}"
  echo "== $model with $cfg.cfg"
  tlc "$model" "$cfg"
done

echo "== Commit with CommitUnfenced.cfg (must give a counterexample)"
if tlc Commit CommitUnfenced >"$work/unfenced.log" 2>&1; then
  cat "$work/unfenced.log"
  echo "tla: the unfenced commit model found no counterexample" >&2
  exit 1
fi
if ! grep -q "Invariant AtMostOneWriter is violated" "$work/unfenced.log"; then
  cat "$work/unfenced.log"
  echo "tla: the unfenced commit model failed for another reason" >&2
  exit 1
fi
echo "counterexample found, as expected"
