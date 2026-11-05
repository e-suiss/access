# OQ-MD4, OP-150 m.1 (c)
"""Kernel call cost through the uniffi Python binding, and the summary of a bench-ffi run.

Usage:
  python3 -I bench_ffi.py uniffi <module dir> <inputs.json> [iterations]
  python3 -I bench_ffi.py summary <file.jsonl>...
"""

import json
import sys
import time


def uniffi(module_dir, inputs_path, iters):
    sys.path.insert(0, module_dir)
    import access_kernel_uniffi as k

    inputs = json.loads(open(inputs_path).read())

    def measure(call):
        for _ in range(iters):
            call()
        start = time.perf_counter_ns()
        for _ in range(iters):
            call()
        return round((time.perf_counter_ns() - start) / iters)

    def report(op, ns):
        print(json.dumps({"runtime": "python-uniffi", "op": op, "ns_per_call": ns, "iters": iters}))

    ev = inputs["evaluate"]
    data, fuel = bytes.fromhex(ev["input"]), ev["fuel"]
    report("evaluate", measure(lambda: k.evaluate(data, fuel)))
    cose = inputs["verify_cose_sign1"]
    sign1, keys = bytes.fromhex(cose["sign1"]), bytes.fromhex(cose["key_set"])
    report("verify_cose_sign1", measure(lambda: k.verify_cose_sign1(sign1, keys, cose["content_type"])))


def summary(paths):
    rows = {}
    runtimes = []
    for path in paths:
        for line in open(path):
            line = line.strip()
            if not line.startswith("{"):
                continue
            r = json.loads(line)
            if r["runtime"] not in runtimes:
                runtimes.append(r["runtime"])
            rows.setdefault(r["op"], {})[r["runtime"]] = r["ns_per_call"]
    print("| op | " + " | ".join(runtimes) + " |")
    print("|---|" + "---|" * len(runtimes))
    for op, by in rows.items():
        base = by.get("rust")
        cells = []
        for rt in runtimes:
            ns = by.get(rt)
            if ns is None:
                cells.append("n/a")
            elif base and rt != "rust":
                cells.append(f"{ns / 1000:.1f} µs ({ns / base:.2f}×)")
            else:
                cells.append(f"{ns / 1000:.1f} µs")
        print(f"| {op} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "uniffi":
        uniffi(sys.argv[2], sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else 2000)
    elif mode == "summary":
        summary(sys.argv[2:])
    else:
        sys.exit(__doc__)
