"""PI-18, OP-70: a shared-layer change without the decision label fails the pull request."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "decision-label.py"


def run(changed, labels):
    with tempfile.TemporaryDirectory() as d:
        paths = pathlib.Path(d) / "changed.txt"
        names = pathlib.Path(d) / "labels.txt"
        paths.write_text("\n".join(changed) + "\n", encoding="utf-8")
        names.write_text("\n".join(labels) + "\n", encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), str(paths), str(names)],
            capture_output=True,
            text=True,
            check=False,
        ).returncode


class DecisionLabel(unittest.TestCase):
    # PI-18
    def test_a_protocol_change_without_the_label_fails(self):
        self.assertEqual(run(["protocol/l0/algebra.md", "crates/http/src/lib.rs"], ["ci"]), 1)

    # PI-18
    def test_a_vector_change_without_the_label_fails(self):
        self.assertEqual(run(["conformance/vectors/core/1/cose.json"], []), 1)

    # PI-18, OP-70
    def test_a_labelled_shared_change_passes(self):
        self.assertEqual(run(["conformance/cddl/kernel.cddl"], ["decision", "kernel"]), 0)

    # PI-18
    def test_a_change_outside_the_shared_layers_needs_no_label(self):
        self.assertEqual(run(["crates/http/src/lib.rs", "README.md"], []), 0)

    def test_wrong_arguments_are_a_usage_error(self):
        result = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
