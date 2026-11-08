"""OP-152 m.5 (j): the OIDF driver counts only PASSED and WARNING as passing."""

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
        bad, _ = OIDF.classify(
            summary(("a", "FINISHED", "SKIPPED"), ("b", "FINISHED", "REVIEW"), ("c", "FINISHED", "PASSED")), {}
        )
        self.assertEqual(bad, ["p/a: FINISHED SKIPPED", "p/b: FINISHED REVIEW"])

    # OP-152 m.5 (j)
    def test_a_listed_module_is_an_expected_failure(self):
        bad, notes = OIDF.classify(summary(("a", "FINISHED", "SKIPPED")), {"p": {"a": "reason"}})
        self.assertEqual(bad, [])
        self.assertEqual(notes, ["p/a: expected failure (reason)"])

    # OP-152 m.5 (j)
    def test_passed_and_warning_pass_and_a_listed_pass_is_reported(self):
        bad, notes = OIDF.classify(
            summary(("a", "FINISHED", "WARNING"), ("b", "FINISHED", "PASSED")), {"p": {"b": "reason"}}
        )
        self.assertEqual(bad, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("now passes", notes[0])

    # OP-152 m.5 (j)
    def test_an_interrupted_or_timed_out_module_fails(self):
        bad, _ = OIDF.classify(summary(("a", "INTERRUPTED", "FAILED"), ("b", "UNKNOWN", "TIMEOUT")), {})
        self.assertEqual(len(bad), 2)


if __name__ == "__main__":
    unittest.main()
