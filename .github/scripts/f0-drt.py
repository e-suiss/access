"""Kernel/F0 differential (DRT) summaries and the semantic release gate (OP-112 m.4, OP-119 m.6).

  f0-drt.py shard <shard> <dir>                       sum the run.py --summary files of one shard
  f0-drt.py night <run-id> <sha> <shards> <dir>       merge shard summaries into the night summary
  f0-drt.py check <night.json>                        zero mismatches, every shard present, >= 10^7 inputs
  f0-drt.py lean <proofs.toml>                        every algebra theorem is `proved`
"""

import json
import pathlib
import sys
import tomllib

MIN_INPUTS = 10_000_000


def fail(message):
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def shard(index, directory):
    batches = [json.loads(path.read_text()) for path in sorted(pathlib.Path(directory).glob("*.json"))]
    passed = sum(batch["passed"] for batch in batches)
    failed = sum(batch["failed"] for batch in batches)
    versions = sorted({batch["f0"] for batch in batches})
    return {"shard": int(index), "batches": len(batches), "inputs": passed + failed, "mismatches": failed, "f0": versions}


def night(run_id, sha, expected, directory):
    shards = {}
    for path in sorted(pathlib.Path(directory).glob("*.json")):
        entry = json.loads(path.read_text())
        shards[entry["shard"]] = entry
    return {
        "run_id": int(run_id),
        "commit": sha,
        "expected_shards": int(expected),
        "shards": sorted(shards),
        "inputs": sum(entry["inputs"] for entry in shards.values()),
        "mismatches": sum(entry["mismatches"] for entry in shards.values()),
        "f0": sorted({version for entry in shards.values() for version in entry["f0"]}),
    }


def check(path):
    summary = json.loads(pathlib.Path(path).read_text())
    if summary["shards"] != list(range(summary["expected_shards"])):
        fail(f"DRT run {summary['run_id']}: shards {summary['shards']} of {summary['expected_shards']}")
    if summary["mismatches"] != 0:
        fail(f"DRT run {summary['run_id']}: {summary['mismatches']} Kernel/F0 mismatches")
    if summary["inputs"] < MIN_INPUTS:
        fail(f"DRT run {summary['run_id']}: {summary['inputs']} inputs, fewer than {MIN_INPUTS}")
    print(f"DRT run {summary['run_id']} at {summary['commit']}: {summary['inputs']} inputs, 0 mismatches")


def lean(path):
    # OP-119 m.3, m.6: every [[theorem]] whose rule cites the algebra (L0-ALG-*) is `proved`
    theorems = tomllib.loads(pathlib.Path(path).read_text()).get("theorem", [])
    algebra = [entry for entry in theorems if "L0-ALG-" in entry.get("rule", "")]
    if not algebra:
        fail(f"{path}: no algebra theorems declared")
    pending = [f"{entry.get('name', '?')} ({entry.get('status', 'no status')})" for entry in algebra if entry.get("status") != "proved"]
    if pending:
        fail(f"{path}: algebra theorems not proved: {', '.join(pending)}")
    print(f"{path}: {len(algebra)} algebra theorems proved")


def main(argv):
    commands = {"shard": (shard, 2), "night": (night, 4), "check": (check, 1), "lean": (lean, 1)}
    if len(argv) < 2 or argv[1] not in commands or len(argv) - 2 != commands[argv[1]][1]:
        print(__doc__, file=sys.stderr)
        return 2
    function, _ = commands[argv[1]]
    result = function(*argv[2:])
    if result is not None:
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
