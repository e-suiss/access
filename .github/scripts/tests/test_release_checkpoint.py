"""Tests of release-checkpoint.py (U49, F-14)."""

import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("release_checkpoint", HERE.parent / "release-checkpoint.py")
release_checkpoint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_checkpoint)


class ReleaseCheckpoint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.notes = self.dir / "notes.md"
        self.notes.write_text("notes\n", encoding="utf-8")
        self.env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.env)
        self.tmp.cleanup()

    def verifier(self, answer, code):
        tool = self.dir / "verify.sh"
        tool.write_text(f"#!/bin/sh\nprintf '{answer}'\nexit {code}\n", encoding="utf-8")
        tool.chmod(tool.stat().st_mode | stat.S_IEXEC)
        os.environ.update(
            ACCESS_VERIFY=str(tool),
            RELEASE_ORIGIN="sha-256:release",
            RELEASE_LOG_VKEY="log+1+AA",
            RELEASE_COSIGNERS="w+2+BB",
        )

    def listing(self, note):
        path = self.dir / "checkpoints.json"
        path.write_text(json.dumps({"checkpoint": {"note": note} if note else None}), encoding="utf-8")
        return path

    # U49, OP-158 m.3 (j): no witness, no claim
    def test_without_witnesses_the_notes_say_partial(self):
        for key in ("RELEASE_ORIGIN", "RELEASE_LOG_VKEY", "RELEASE_COSIGNERS"):
            os.environ.pop(key, None)
        self.assertEqual(release_checkpoint.main([str(self.dir / "absent.json"), str(self.notes)]), 0)
        self.assertIn("Release checkpoint: partial", self.notes.read_text(encoding="utf-8"))

    # U49, F-7
    def test_a_verified_checkpoint_is_attached(self):
        self.verifier("accept\\nsize: 7\\ncosigned: 1800000000\\n", 0)
        self.assertEqual(release_checkpoint.main([str(self.listing("o\\n7\\n")), str(self.notes)]), 0)
        text = self.notes.read_text(encoding="utf-8")
        self.assertIn("size 7", text)
        self.assertIn("cosigned at 1800000000", text)

    # U49: a configured checkpoint that does not verify stops the release
    def test_a_checkpoint_that_does_not_verify_fails(self):
        self.verifier("reject: note-unverified\\n", 1)
        self.assertEqual(release_checkpoint.main([str(self.listing("o\\n7\\n")), str(self.notes)]), 1)
        self.verifier("accept\\n", 0)
        self.assertEqual(release_checkpoint.main([str(self.listing(None)), str(self.notes)]), 1)


if __name__ == "__main__":
    unittest.main()
