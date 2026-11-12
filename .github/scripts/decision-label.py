"""PI-18, OP-70: a pull request that changes the layers shared with Work carries the decision label.

The protocol text, the CDDL and the vectors live only under protocol/ and conformance/
(`cargo xtask check shared-layers`). A change there goes through the semantics release gate
and is recorded as a decision, so the pull request must be labelled `decision`.
Usage: decision-label.py <changed-paths-file> <labels-file>
"""

import pathlib
import sys

SHARED = ("protocol/", "conformance/")
LABEL = "decision"


def lines(path):
    return [line.strip() for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def main(args):
    if len(args) != 2:
        print("usage: decision-label.py <changed-paths-file> <labels-file>", file=sys.stderr)
        return 2
    changed = [path for path in lines(args[0]) if path.startswith(SHARED)]
    labels = set(lines(args[1]))
    if not changed:
        print("no shared-layer path changed")
        return 0
    if LABEL in labels:
        print(f"{len(changed)} shared-layer paths changed; labelled {LABEL}")
        return 0
    for path in changed:
        print(f"::error file={path}::changes a layer shared with Work; label the pull request {LABEL} (PI-18, OP-70)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
