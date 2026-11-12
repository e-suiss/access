"""Tests of f0-drt.py: the semantic release gate refuses a release when any condition is missing (U56, OP-159 m.3 (z))."""

import importlib.util
import json
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("f0_drt", HERE.parent / "f0-drt.py")
f0_drt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f0_drt)

TEN_MILLION = 10_000_000


def summary(**changes):
    base = {
        "run_id": 7,
        "commit": "abc",
        "expected_shards": 2,
        "shards": [0, 1],
        "inputs": TEN_MILLION,
        "mismatches": 0,
        "f0": ["0.2.0"],
        "lean_cases": TEN_MILLION,
        "lean_mismatches": 0,
    }
    base.update(changes)
    return base


def theorems(**status):
    entries = [{"name": "Access.authLe_trans", "rule": "L0-ALG-5", "status": "proved"}]
    entries += [{"name": name, "rule": "CR-48 m.2", "status": "proved"} for name in f0_drt.GATE_THEOREMS]
    entries.append({"name": "Access.Holding.lazy_eq_eager", "rule": "CR-48 m.3", "status": "stated"})
    for entry in entries:
        entry["status"] = status.get(entry["name"], entry["status"])
    return entries


class Summary(unittest.TestCase):
    # U56, SA-T4
    def test_a_complete_summary_passes(self):
        self.assertIn("0 mismatches", f0_drt.verify_summary(summary()))

    # U56
    def test_each_missing_condition_refuses_the_release(self):
        cases = {
            "missing shard": summary(shards=[0]),
            "F0 mismatch": summary(mismatches=1),
            "too few F0 inputs": summary(inputs=TEN_MILLION - 1),
            "Lean mismatch": summary(lean_mismatches=1),
            "too few Lean cases": summary(lean_cases=TEN_MILLION - 1),
        }
        no_lean = summary()
        del no_lean["lean_cases"]
        del no_lean["lean_mismatches"]
        cases["no Lean step"] = no_lean
        for name, value in cases.items():
            with self.subTest(name), self.assertRaises(f0_drt.GateError):
                f0_drt.verify_summary(value)


class Theorems(unittest.TestCase):
    # U56, OP-159 m.3 (v)
    def test_gate_theorems_proved_pass_and_other_statuses_do_not_block(self):
        self.assertIn("combinator", f0_drt.verify_theorems(theorems()))

    # U56
    def test_an_unproved_or_missing_gate_theorem_refuses_the_release(self):
        for name in (*f0_drt.GATE_THEOREMS, "Access.authLe_trans"):
            with self.subTest(name), self.assertRaises(f0_drt.GateError):
                f0_drt.verify_theorems(theorems(**{name: "stated"}))
        for name in f0_drt.GATE_THEOREMS:
            with self.subTest(f"missing {name}"), self.assertRaises(f0_drt.GateError):
                f0_drt.verify_theorems([entry for entry in theorems() if entry["name"] != name])
        with self.assertRaises(f0_drt.GateError):
            f0_drt.verify_theorems([entry for entry in theorems() if "L0-ALG-" not in entry["rule"]])


class Freshness(unittest.TestCase):
    # U56, OP-159 m.3 (z)
    def test_a_semantic_change_since_the_drt_voids_it(self):
        for path in (
            "crates/kernel/src/algebra.rs",
            "conformance/reference/f0/f0/algebra.py",
            "conformance/vectors/core/1/decision.json",
            "conformance/cddl/kernel.cddl",
            "conformance/lean/AccessAlgebra/Algebra.lean",
        ):
            with self.subTest(path), self.assertRaises(f0_drt.GateError):
                f0_drt.verify_fresh(["README.md", path])

    def test_changes_outside_the_semantics_keep_it(self):
        f0_drt.verify_fresh(["crates/kernel/benches/kernel_wallclock.rs", "crates/http/src/lib.rs", "README.md"])


class Jobs(unittest.TestCase):
    def jobs(self, **conclusions):
        return [{"name": name, "conclusion": conclusion} for name, conclusion in conclusions.items()]

    # U56, OP-159 m.3 (z)
    def test_lean_and_formal_must_pass_on_the_tagged_commit(self):
        f0_drt.verify_jobs(self.jobs(lean="success", formal="success", fmt="success"))
        refused = [
            self.jobs(formal="success"),
            self.jobs(lean="success"),
            self.jobs(lean="success", formal="skipped"),
            self.jobs(lean="failure", formal="success"),
            self.jobs(lean="success", formal="cancelled"),
        ]
        for jobs in refused:
            with self.subTest(jobs), self.assertRaises(f0_drt.GateError):
                f0_drt.verify_jobs(jobs)

    def test_a_matrix_job_counts_only_when_every_leg_passed(self):
        jobs = [
            {"name": "lean", "conclusion": "success"},
            {"name": "formal (kani)", "conclusion": "success"},
            {"name": "formal (tlc)", "conclusion": "failure"},
        ]
        with self.assertRaises(f0_drt.GateError):
            f0_drt.verify_jobs(jobs)


class Aggregation(unittest.TestCase):
    # OP-159 m.3 (v)
    def test_shard_and_night_carry_the_lean_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            batches = pathlib.Path(tmp) / "batches"
            batches.mkdir()
            (batches / "batch-0.json").write_text(json.dumps({"f0": "0.2.0", "core": 1, "passed": 5, "failed": 0}))
            (batches / "lean-0.json").write_text(json.dumps({"lean_cases": 5, "lean_mismatches": 0, "model": "access-algebra"}))
            one = f0_drt.shard("0", batches)
            self.assertEqual((one["inputs"], one["lean_cases"], one["lean_batches"]), (5, 5, 1))
            shards = pathlib.Path(tmp) / "shards"
            shards.mkdir()
            (shards / "drt-shard-0.json").write_text(json.dumps(one))
            merged = f0_drt.night("1", "abc", "1", shards)
            self.assertEqual((merged["lean_cases"], merged["lean_mismatches"]), (5, 0))
            with self.assertRaises(f0_drt.GateError):
                f0_drt.verify_summary(merged)


if __name__ == "__main__":
    unittest.main()
