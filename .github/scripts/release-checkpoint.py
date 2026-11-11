"""Attach the release domain's witnessed checkpoint to the release notes (U49, F-7, SA-39).

Every release is an entry in Suiss's release domain log; its checkpoint is cosigned by Access
witnesses and verified here with the open verifier, using the witness keys alone. While no
witness is configured for the release domain the notes say so and the release is labelled
partial; a checkpoint that is configured but does not verify fails the release.

Usage: release-checkpoint.py <checkpoints.json> <notes.md>
Environment: RELEASE_ORIGIN, RELEASE_LOG_VKEY, RELEASE_COSIGNERS (comma-separated vkeys),
ACCESS_VERIFY (the access-verify binary).
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile

PARTIAL = (
    "Release checkpoint: partial. No Access witness cosigns the release domain yet "
    "(OP-158 m.3 (j)), so this release has no witnessed log entry.\n"
)


def main(args):
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    listing, notes = pathlib.Path(args[0]), pathlib.Path(args[1])
    origin = os.environ.get("RELEASE_ORIGIN", "")
    log = os.environ.get("RELEASE_LOG_VKEY", "")
    cosigners = os.environ.get("RELEASE_COSIGNERS", "")
    if not (origin and log and cosigners and listing.is_file()):
        print("::warning::release checkpoint is partial: no witnesses are configured")
        with notes.open("a", encoding="utf-8") as out:
            out.write("\n" + PARTIAL)
        return 0
    document = json.loads(listing.read_text(encoding="utf-8"))
    checkpoint = document.get("checkpoint") or {}
    note = checkpoint.get("note")
    if not isinstance(note, str):
        print("::error::the release domain has no witnessed checkpoint", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "release.note"
        path.write_text(note, encoding="utf-8")
        verified = subprocess.run(
            [
                os.environ.get("ACCESS_VERIFY", "access-verify"),
                "checkpoint",
                "--note", str(path),
                "--origin", origin,
                "--log", log,
                "--cosigners", cosigners,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    if verified.returncode != 0 or not verified.stdout.startswith("accept"):
        print(f"::error::release checkpoint does not verify: {verified.stdout.strip()}", file=sys.stderr)
        return 1
    fields = dict(
        line.split(": ", 1) for line in verified.stdout.splitlines()[1:] if ": " in line
    )
    with notes.open("a", encoding="utf-8") as out:
        out.write(
            f"\nRelease checkpoint: size {fields.get('size', '?')} of `{origin}`, "
            f"cosigned at {fields.get('cosigned', '?')} (verify with "
            "`access-verify checkpoint --cosigners`):\n\n```\n"
            f"{note}```\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
