"""OP-152 m.5 (j), OP-155 m.3 (q): the OIDF driver counts only PASSED and WARNING as passing, and a
plan gates once its expected list is recorded."""

import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "oidf-conformance.py"
SPEC = importlib.util.spec_from_file_location("oidf_conformance", SCRIPT)
OIDF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OIDF)


def summary(*modules):
    return [{"plan": "p", "modules": [{"module": m, "status": s, "result": r} for m, s, r in modules]}]


class Classify(unittest.TestCase):
    # OP-152 m.5 (j)
    def test_skipped_and_review_fail_unless_listed(self):
        bad, _, _ = OIDF.classify(
            summary(("a", "FINISHED", "SKIPPED"), ("b", "FINISHED", "REVIEW"), ("c", "FINISHED", "PASSED")), {"p": {}}
        )
        self.assertEqual(bad, ["p/a: FINISHED SKIPPED", "p/b: FINISHED REVIEW"])

    # OP-152 m.5 (j)
    def test_a_listed_module_is_an_expected_failure(self):
        bad, notes, _ = OIDF.classify(summary(("a", "FINISHED", "SKIPPED")), {"p": {"a": "reason"}})
        self.assertEqual(bad, [])
        self.assertEqual(notes, ["p/a: expected failure (reason)"])

    # OP-152 m.5 (j)
    def test_passed_and_warning_pass_and_a_listed_pass_is_reported(self):
        bad, notes, _ = OIDF.classify(
            summary(("a", "FINISHED", "WARNING"), ("b", "FINISHED", "PASSED")), {"p": {"b": "reason"}}
        )
        self.assertEqual(bad, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("now passes", notes[0])

    # OP-152 m.5 (j)
    def test_an_interrupted_or_timed_out_module_fails(self):
        bad, _, _ = OIDF.classify(summary(("a", "INTERRUPTED", "FAILED"), ("b", "UNKNOWN", "TIMEOUT")), {"p": {}})
        self.assertEqual(len(bad), 2)

    # OP-155 m.3 (q)
    def test_a_first_run_reports_and_writes_the_list_to_record(self):
        bad, notes, candidate = OIDF.classify(summary(("a", "FINISHED", "FAILED"), ("b", "FINISHED", "PASSED")), {})
        self.assertEqual(bad, [])
        self.assertIn("first run", notes[0])
        self.assertEqual(candidate, {"p": {"a": "first run: FINISHED FAILED"}})

    # OP-155 m.3 (q)
    def test_a_release_refuses_a_plan_without_a_recorded_list(self):
        bad, _, _ = OIDF.classify(summary(("a", "FINISHED", "PASSED")), {}, release=True)
        self.assertEqual(len(bad), 1)
        self.assertIn("no recorded expected list", bad[0])
        bad, _, _ = OIDF.classify(summary(("a", "FINISHED", "PASSED")), {"p": {}}, release=True)
        self.assertEqual(bad, [])


class Substitute(unittest.TestCase):
    # OP-155 m.3 (q)
    def test_run_time_values_replace_their_placeholders(self):
        got = OIDF.substitute({"a": ["$runtime:k", {"b": "$runtime:j"}], "c": "x"}, {"k": 1, "j": {"d": 2}}, None)
        self.assertEqual(got, {"a": [1, {"b": {"d": 2}}], "c": "x"})
        with self.assertRaises(SystemExit):
            OIDF.substitute("$runtime:missing", {}, None)


if __name__ == "__main__":
    unittest.main()
