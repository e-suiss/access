"""OIDF conformance suite driver (OP-146 I11, §14.8 SA-T2, B9): runs the test plans of
conformance/oidf/plans.json against the suite's REST API, one module at a time, and writes a
summary and each plan's export.

  oidf-conformance.py <suite-base-url> <conformance/oidf dir> <out dir> [--report-only]

Uses only the standard library. The suite runs in development mode on the runner with its own
self-signed certificate, so its API is called without certificate verification.
"""

import json
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MODULE_TIMEOUT_S = 300
POLL_S = 2
FINAL = {"FINISHED", "INTERRUPTED"}

CONTEXT = ssl.create_default_context()
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE


def fail(message):
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def call(method, url, body=None):
    data = None if body is None else body.encode()
    request = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, context=CONTEXT, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def api(base, path, **query):
    q = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
    return f"{base}api/{path}" + (f"?{q}" if q else "")


def wait_ready(base, timeout_s=600):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _ = call("GET", api(base, "plan", length=1))
            if status == 200:
                return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(5)
    fail(f"the conformance suite at {base} did not become ready")


def run_module(base, plan_id, module):
    variant = module.get("variant")
    status, body = call(
        "POST",
        api(
            base,
            "runner",
            test=module["testModule"],
            plan=plan_id,
            variant=json.dumps(variant) if variant else None,
        ),
    )
    if status != 201:
        return {"module": module["testModule"], "variant": variant, "status": "NOT_CREATED",
                "result": f"HTTP {status} {body[:200]!r}"}
    module_id = json.loads(body)["id"]
    deadline = time.monotonic() + MODULE_TIMEOUT_S
    started = False
    info = {}
    while time.monotonic() < deadline:
        status, body = call("GET", api(base, f"info/{module_id}"))
        if status == 200:
            info = json.loads(body)
            if info.get("status") in FINAL:
                break
            if info.get("status") == "CONFIGURED" and not started:
                call("POST", api(base, f"runner/{module_id}"))
                started = True
        time.sleep(POLL_S)
    return {
        "module": module["testModule"],
        "variant": variant,
        "id": module_id,
        "status": info.get("status", "UNKNOWN"),
        "result": info.get("result", "TIMEOUT" if info.get("status") not in FINAL else None),
    }


def run_plan(base, directory, plan, out):
    config = (directory / plan["config"]).read_text()
    variant = plan.get("variant")
    status, body = call(
        "POST",
        api(base, "plan", planName=plan["name"], variant=json.dumps(variant) if variant else None),
        config,
    )
    if status != 201:
        fail(f"plan {plan['name']} was not created: HTTP {status} {body[:500]!r}")
    created = json.loads(body)
    plan_id = created["id"]
    results = [run_module(base, plan_id, m) for m in created.get("modules", [])]
    for r in results:
        print(f"{plan['name']} {r['module']} {r.get('variant') or ''}: {r['status']} {r['result']}")
    status, export = call("GET", api(base, f"plan/export/{plan_id}"))
    if status == 200:
        (out / f"{plan['name']}-{plan_id}.zip").write_bytes(export)
    return {"plan": plan["name"], "id": plan_id, "variant": variant, "modules": results}


def main(argv):
    if len(argv) < 4:
        fail(__doc__)
    base = argv[1] if argv[1].endswith("/") else argv[1] + "/"
    directory = pathlib.Path(argv[2])
    out = pathlib.Path(argv[3])
    report_only = "--report-only" in argv[4:]
    out.mkdir(parents=True, exist_ok=True)
    plans = json.loads((directory / "plans.json").read_text())["plans"]
    wait_ready(base)
    summary = [run_plan(base, directory, p, out) for p in plans]
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    expected_path = directory / "expected.json"
    expected = json.loads(expected_path.read_text())["plans"] if expected_path.exists() else {}
    ok = ("PASSED", "WARNING", "REVIEW", "SKIPPED")
    bad = []
    for p in summary:
        known = expected.get(p["plan"], {})
        for m in p["modules"]:
            passed = m["status"] == "FINISHED" and m["result"] in ok
            if passed and m["module"] in known:
                print(f"::warning::{p['plan']}/{m['module']} now passes; remove it from expected.json")
            elif not passed and m["module"] in known:
                print(f"{p['plan']}/{m['module']}: expected failure ({known[m['module']]})")
            elif not passed:
                bad.append(f"{p['plan']}/{m['module']}: {m['status']} {m['result']}")
    total = sum(len(p["modules"]) for p in summary)
    print(f"{total - len(bad)} of {total} modules passed or failed as expected")
    if not bad:
        return
    for line in bad:
        print(f"::warning::{line}" if report_only else f"::error::{line}")
    if not report_only:
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
