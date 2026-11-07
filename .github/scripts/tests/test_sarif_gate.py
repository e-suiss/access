"""F-14: the SARIF gate fails on high findings and on an analysis that wrote nothing."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

GATE = pathlib.Path(__file__).resolve().parent.parent / "sarif-gate.py"


def sarif(severity):
    rule = {"id": "r", "properties": {"security-severity": severity}}
    result = {"ruleId": "r", "message": {"text": "m"}, "locations": [{}]}
    return {"runs": [{"tool": {"driver": {"rules": [rule]}}, "results": [result]}]}


def gate(directory):
    return subprocess.run(
        [sys.executable, "-I", str(GATE), str(directory)], capture_output=True, text=True, check=False
    ).returncode


class SarifGate(unittest.TestCase):
    # F-14
    def test_an_empty_directory_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(gate(d), 1)

    # F-14
    def test_a_high_finding_fails_and_a_low_one_passes(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "rust.sarif"
            path.write_text(json.dumps(sarif("3.1")))
            self.assertEqual(gate(d), 0)
            path.write_text(json.dumps(sarif("7.5")))
            self.assertEqual(gate(d), 1)


if __name__ == "__main__":
    unittest.main()
