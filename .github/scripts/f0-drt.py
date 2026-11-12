"""Kernel/F0/Lean differential (DRT) summaries and the semantic release gate (OP-112 m.4, OP-119 m.6, OP-159 m.3 (v), (z)).

  f0-drt.py shard <shard> <dir>                       sum the run.py and lake exe drt --summary files of one shard
  f0-drt.py night <run-id> <sha> <shards> <dir>       merge shard summaries into the night summary
  f0-drt.py check <night.json>                        zero mismatches, every shard present, >= 10^7 F0 and Lean inputs
  f0-drt.py lean <proofs.toml>                        every gate theorem is declared and `proved`
  f0-drt.py stale <changed-paths-file>                the DRT is void if the semantics changed since it ran
  f0-drt.py jobs <jobs.json>                          the `lean` and `formal` jobs passed on the tagged commit
"""

import json
import pathlib
import sys
import tomllib

MIN_INPUTS = 10_000_000

# OP-159 m.3 (v): the four Decision Combinator theorems join the algebra in the gate set
GATE_THEOREMS = (
    "Access.Combinator.forbid_trumps_permit",
    "Access.Combinator.default_deny",
    "Access.Combinator.allowed_only_if_explicitly_permitted",
    "Access.Combinator.order_and_dup_independent",
)

# OP-119 m.6, OP-159 m.3 (z)
SEMANTIC_PATHS = (
    "crates/kernel/",
    "conformance/reference/f0/",
    "conformance/vectors/",
    "conformance/cddl/",
    "conformance/lean/",
)
OUTSIDE_SEMANTICS = ("crates/kernel/benches/",)

# OP-159 m.3 (z)
REQUIRED_JOBS = ("lean", "formal")


class GateError(Exception):
    pass


def fail(message):
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def shard(index, directory):
    batches = [json.loads(path.read_text()) for path in sorted(pathlib.Path(directory).glob("*.json"))]
    f0 = [batch for batch in batches if "lean_cases" not in batch]
    lean = [batch for batch in batches if "lean_cases" in batch]
    passed = sum(batch["passed"] for batch in f0)
    failed = sum(batch["failed"] for batch in f0)
    versions = sorted({batch["f0"] for batch in f0})
    return {
        "shard": int(index),
        "batches": len(f0),
        "inputs": passed + failed,
        "mismatches": failed,
        "f0": versions,
        "lean_batches": len(lean),
        "lean_cases": sum(batch["lean_cases"] for batch in lean),
        "lean_mismatches": sum(batch["lean_mismatches"] for batch in lean),
    }


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
        "lean_cases": sum(entry.get("lean_cases", 0) for entry in shards.values()),
        "lean_mismatches": sum(entry.get("lean_mismatches", 0) for entry in shards.values()),
    }


def verify_summary(summary):
    run = summary.get("run_id", "?")
    if summary["shards"] != list(range(summary["expected_shards"])):
        raise GateError(f"DRT run {run}: shards {summary['shards']} of {summary['expected_shards']}")
    if summary["mismatches"] != 0:
        raise GateError(f"DRT run {run}: {summary['mismatches']} Kernel/F0 mismatches")
    if summary["inputs"] < MIN_INPUTS:
        raise GateError(f"DRT run {run}: {summary['inputs']} inputs, fewer than {MIN_INPUTS}")
    # OP-159 m.3 (v), SA-T4
    if "lean_cases" not in summary or "lean_mismatches" not in summary:
        raise GateError(f"DRT run {run}: no Lean step in the summary")
    if summary["lean_mismatches"] != 0:
        raise GateError(f"DRT run {run}: {summary['lean_mismatches']} Kernel/Lean mismatches")
    if summary["lean_cases"] < MIN_INPUTS:
        raise GateError(f"DRT run {run}: {summary['lean_cases']} Lean cases, fewer than {MIN_INPUTS}")
    return (
        f"DRT run {run} at {summary['commit']}: {summary['inputs']} F0 inputs and "
        f"{summary['lean_cases']} Lean cases, 0 mismatches"
    )


def verify_theorems(theorems):
    algebra = [entry for entry in theorems if "L0-ALG-" in entry.get("rule", "")]
    if not algebra:
        raise GateError("no algebra theorems declared")
    names = {entry.get("name") for entry in theorems}
    missing = [name for name in GATE_THEOREMS if name not in names]
    if missing:
        raise GateError(f"gate theorems not declared: {', '.join(missing)}")
    gate = algebra + [entry for entry in theorems if entry.get("name") in GATE_THEOREMS]
    pending = [f"{entry.get('name', '?')} ({entry.get('status', 'no status')})" for entry in gate if entry.get("status") != "proved"]
    if pending:
        raise GateError(f"gate theorems not proved: {', '.join(pending)}")
    return f"{len(algebra)} algebra and {len(GATE_THEOREMS)} combinator theorems proved"


def semantic_changes(paths):
    return sorted(
        path
        for path in paths
        if path.startswith(SEMANTIC_PATHS) and not path.startswith(OUTSIDE_SEMANTICS)
    )


def verify_fresh(paths):
    changed = semantic_changes(paths)
    if changed:
        raise GateError(f"Kernel, F0, vectors, CDDL or the Lean model changed since the nightly DRT: {', '.join(changed[:10])}")
    return "the nightly DRT ran on the tagged semantics"


def verify_jobs(jobs):
    outcome = {}
    for job in jobs:
        base = job.get("name", "").split(" (", 1)[0]
        outcome.setdefault(base, []).append(job.get("conclusion"))
    for name in REQUIRED_JOBS:
        conclusions = outcome.get(name)
        if not conclusions:
            raise GateError(f"the {name} job did not run on the tagged commit")
        bad = [c for c in conclusions if c != "success"]
        if bad:
            raise GateError(f"the {name} job did not pass on the tagged commit: {', '.join(str(c) for c in bad)}")
    return f"jobs {', '.join(REQUIRED_JOBS)} passed on the tagged commit"


def gated(function, *args):
    try:
        print(function(*args))
    except GateError as error:
        fail(str(error))


def check(path):
    gated(verify_summary, json.loads(pathlib.Path(path).read_text()))


def lean(path):
    theorems = tomllib.loads(pathlib.Path(path).read_text()).get("theorem", [])
    gated(verify_theorems, theorems)


def stale(path):
    paths = [line.strip() for line in pathlib.Path(path).read_text().splitlines() if line.strip()]
    gated(verify_fresh, paths)


def jobs(path):
    gated(verify_jobs, json.loads(pathlib.Path(path).read_text()).get("jobs", []))


def main(argv):
    commands = {
        "shard": (shard, 2),
        "night": (night, 4),
        "check": (check, 1),
        "lean": (lean, 1),
        "stale": (stale, 1),
        "jobs": (jobs, 1),
    }
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
