"""Assembly snapshot of the constant-time comparisons (CR-39 m.5, SA-T13).

Compiles crates/crypto/asm/snapshot.rs for each server target with the pinned toolchain,
extracts the comparison functions, normalises labels and symbol hashes and compares the
result with crates/crypto/asm/<target>.s. A difference fails and is reviewed; `--bless`
rewrites the snapshots after the review. A call to memcmp or bcmp always fails.

Usage: python3 -I scripts/ct_asm.py [--bless]
"""

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SNAPSHOT_DIR = ROOT / "crates" / "crypto" / "asm"
TARGETS = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
FUNCTIONS = ["ct_eq_32", "ct_eq_bytes_32"]
DEPS = ["secrecy", "subtle", "zeroize"]
FORBIDDEN_CALLS = re.compile(r"\b_?(memcmp|bcmp)\b")


def rlibs(target):
    cmd = ["cargo", "build", "--locked", "--release", "--target", target, "--message-format=json"]
    for dep in DEPS:
        cmd += ["-p", dep]
    out = subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True).stdout
    found = {}
    for line in out.splitlines():
        msg = json.loads(line)
        if msg.get("reason") == "compiler-artifact" and msg["target"]["name"] in DEPS:
            for f in msg["filenames"]:
                if f.endswith(".rlib"):
                    found[msg["target"]["name"]] = f
    missing = set(DEPS) - set(found)
    if missing:
        sys.exit(f"ct-asm: no rlib for {sorted(missing)} on {target}")
    return found


def compile_asm(target):
    out_dir = ROOT / "target" / "ct-asm" / target
    out_dir.mkdir(parents=True, exist_ok=True)
    asm = out_dir / "snapshot.s"
    cmd = [
        "rustc", "--edition", "2024", "--crate-type", "lib", "--crate-name", "ct_asm",
        "--target", target,
        "-C", "opt-level=3", "-C", "codegen-units=1", "-C", "debuginfo=0",
        "-C", "overflow-checks=on", "-C", "panic=unwind",
        "-L", f"dependency={ROOT / 'target' / target / 'release' / 'deps'}",
        "--emit", f"asm={asm}",
    ]
    for name, path in sorted(rlibs(target).items()):
        cmd += ["--extern", f"{name}={path}"]
    cmd.append(str(SNAPSHOT_DIR / "snapshot.rs"))
    subprocess.run(cmd, cwd=ROOT, check=True)
    return asm.read_text()


def symbol_matches(label, function):
    return re.search(r"\d" + re.escape(function) + r"(17h[0-9a-f]{16}E)?$", label) is not None


def normalise(lines):
    labels = {}
    out = []
    for raw in lines:
        line = re.split(r"\s(#|//)\s", " " + raw.strip())[0].strip()
        if not line or line.startswith(("#", "//")):
            continue
        if line.startswith(".") and not re.match(r"^\.L[\w$.]+:$", line):
            continue
        line = re.sub(r"17h[0-9a-f]{16}E", "17hE", line)
        line = re.sub(r"Cs[0-9A-Za-z]+_", "Cs_", line)

        def rename(m):
            return labels.setdefault(m.group(0), f".L{len(labels)}")

        line = re.sub(r"\.L(BB|CPI|tmp|JTI)[\w$.]*", rename, line)
        out.append(re.sub(r"\s+", " ", line))
    return out


def body_at(lines, start):
    body = []
    for nxt in lines[start + 1:]:
        if re.match(r"^\.Lfunc_end\d+:", nxt.strip()):
            return body
        body.append(nxt)
    return body


def extract(asm, function):
    lines = asm.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith(".") and symbol_matches(stripped[:-1], function):
            return body_at(lines, i)
    sys.exit(f"ct-asm: function {function} not found")


def callees(asm, body):
    """Functions the body calls that this crate defines (monomorphised subtle code)."""
    defined = {l.strip()[:-1]: i for i, l in enumerate(asm.splitlines()) if re.match(r"^[\w$.]+:$", l.strip())}
    out = []
    for line in body:
        for token in re.findall(r"[\w$.]+", line):
            if token in defined and not token.startswith(".L"):
                out.append((token, defined[token]))
    return out


def snapshot(target):
    asm = compile_asm(target)
    lines = asm.splitlines()
    text = []
    queue = [(f, extract(asm, f)) for f in FUNCTIONS]
    seen = set()
    while queue:
        name, body = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        norm = normalise(body)
        for line in norm:
            if FORBIDDEN_CALLS.search(line):
                sys.exit(f"ct-asm: {name} on {target} calls `{line}` (CR-39 m.5)")
        text.append(f"{normalise([name + ':'])[0] if name.startswith('.') else re.sub(r'Cs[0-9A-Za-z]+_', 'Cs_', name)}:")
        text.extend("\t" + line for line in norm)
        text.append("")
        queue.extend((callee, body_at(lines, i)) for callee, i in callees(asm, body))
    return "\n".join(text)


def main():
    bless = sys.argv[1:] == ["--bless"]
    if sys.argv[1:] not in ([], ["--bless"]):
        sys.exit(__doc__)
    rustc = subprocess.run(["rustc", "--version"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    failed = False
    for target in TARGETS:
        got = f"# CR-39 m.5: {rustc}, {target}\n\n" + snapshot(target)
        path = SNAPSHOT_DIR / f"{target}.s"
        if bless:
            path.write_text(got)
            print(f"ct-asm: wrote {path.relative_to(ROOT)}")
            continue
        want = path.read_text() if path.exists() else ""
        if got != want:
            failed = True
            (ROOT / "target" / "ct-asm" / f"{target}.s").write_text(got)
            diff = subprocess.run(
                ["diff", "-u", str(path), str(ROOT / "target" / "ct-asm" / f"{target}.s")],
                capture_output=True, text=True,
            ).stdout
            print(f"ct-asm: {target} differs from the snapshot; review and run `just ct-asm --bless`\n{diff}")
        else:
            print(f"ct-asm: {target} matches the snapshot")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
