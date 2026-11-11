"""OIDF conformance suite driver (OP-146 I11, §14.8 SA-T2, B9, OP-155 m.3 (q)): runs the test
plans of conformance/oidf/plans.json against the suite's REST API, one module at a time, and
writes a summary, each plan's export and the expected list each plan would record.

  oidf-conformance.py <suite-base-url> <conformance/oidf dir> <out dir>
      [--group <name>] [--runtime <file>] [--target-ca <file>] [--release] [--report-only]

--group runs only the plans of that group. A config string "$runtime:<name>" becomes the value
<name> of the JSON file the conformance target wrote at start (--runtime: its run-time client
keys, secrets and initial access token); "$entity-jwks:<url>" becomes the jwks of the entity
statement at <url>, fetched over TLS trusting only the target's certificate (--target-ca).

A plan is a breaking gate once expected.json lists it (OP-155 m.3 (q)). Until then it is in its
first run: its failures are reported, and the list to record is written to
expected-candidate.json. --release refuses a plan without a recorded list.

Uses only the standard library. The suite runs in development mode on the runner with its own
self-signed certificate, so its API is called without certificate verification.
"""

import base64
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
PASS = ("PASSED", "WARNING")
NOT_CREATED = "NOT_CREATED"

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


def plan_key(plan):
    return plan.get("id", plan["name"])


def fetch_entity_jwks(url, target_ca):
    context = ssl.create_default_context(cafile=target_ca)
    with urllib.request.urlopen(url, context=context, timeout=30) as response:
        jwt = response.read().decode().strip()
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["jwks"]


def substitute(value, runtime, target_ca):
    """OP-155 m.3 (q): run-time values replace their placeholders; an unknown one fails."""
    if isinstance(value, dict):
        return {k: substitute(v, runtime, target_ca) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, runtime, target_ca) for v in value]
    if isinstance(value, str) and value.startswith("$runtime:"):
        name = value[len("$runtime:"):]
        if name not in runtime:
            fail(f"the conformance target wrote no run-time value {name}")
        return runtime[name]
    if isinstance(value, str) and value.startswith("$entity-jwks:"):
        if not target_ca:
            fail("$entity-jwks needs --target-ca")
        return fetch_entity_jwks(value[len("$entity-jwks:"):], target_ca)
    return value


def run_plan(base, directory, plan, out, runtime=None, target_ca=None):
    raw = json.loads((directory / plan["config"]).read_text())
    config = json.dumps(substitute(raw, runtime or {}, target_ca))
    variant = plan.get("variant")
    status, body = call(
        "POST",
        api(base, "plan", planName=plan["name"], variant=json.dumps(variant) if variant else None),
        config,
    )
    if status != 201:
        print(f"::error::plan {plan['name']} was not created: HTTP {status} {body[:500]!r}")
        return {"plan": plan_key(plan), "id": None, "variant": variant, "modules": [
            {"module": NOT_CREATED, "variant": variant, "status": NOT_CREATED, "result": f"HTTP {status}"}
        ]}
    created = json.loads(body)
    plan_id = created["id"]
    results = [run_module(base, plan_id, m) for m in created.get("modules", [])]
    for r in results:
        print(f"{plan_key(plan)} {r['module']} {r.get('variant') or ''}: {r['status']} {r['result']}")
    status, export = call("GET", api(base, f"plan/export/{plan_id}"))
    if status == 200:
        (out / f"{plan['name']}-{plan_id}.zip").write_bytes(export)
    return {"plan": plan_key(plan), "id": plan_id, "variant": variant, "modules": results}


def option(argv, name):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
        fail(f"{name} needs a value")
    return None


def main(argv):
    if len(argv) < 4:
        fail(__doc__)
    base = argv[1] if argv[1].endswith("/") else argv[1] + "/"
    directory = pathlib.Path(argv[2])
    out = pathlib.Path(argv[3])
    flags = argv[4:]
    report_only = "--report-only" in flags
    release = "--release" in flags
    group = option(flags, "--group")
    runtime_path = option(flags, "--runtime")
    target_ca = option(flags, "--target-ca")
    runtime = json.loads(pathlib.Path(runtime_path).read_text()) if runtime_path else {}
    out.mkdir(parents=True, exist_ok=True)
    plans = json.loads((directory / "plans.json").read_text())["plans"]
    plans = [p for p in plans if group is None or p.get("group") == group]
    if not plans:
        fail(f"no plan in group {group}")
    wait_ready(base)
    summary = [run_plan(base, directory, p, out, runtime, target_ca) for p in plans]
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    expected_path = directory / "expected.json"
    expected = json.loads(expected_path.read_text())["plans"] if expected_path.exists() else {}
    bad, notes, candidate = classify(summary, expected, release)
    (out / "expected-candidate.json").write_text(
        json.dumps({"plans": candidate}, indent=2, sort_keys=True) + "\n"
    )
    for line in notes:
        print(line)
    total = sum(len(p["modules"]) for p in summary)
    print(f"{total - len(bad)} of {total} modules passed or failed as expected")
    if not bad:
        return
    for line in bad:
        print(f"::warning::{line}" if report_only else f"::error::{line}")
    if not report_only:
        sys.exit(1)


def classify(summary, expected, release=False):
    """OP-152 m.5 (j): a module passes only when it finished PASSED or WARNING; SKIPPED, REVIEW
    and every other outcome fail unless expected.json lists the module with its reason.
    OP-155 m.3 (q): a plan expected.json does not list is in its first run; its failures are
    only reported, unless this is a release. A plan the suite refuses to create always fails, and
    the other plans of the group still run."""
    bad, notes, candidate = [], [], {}
    for p in summary:
        recorded = p["plan"] in expected
        known = expected.get(p["plan"], {})
        failed = candidate.setdefault(p["plan"], {})
        for m in p["modules"]:
            passed = m["status"] == "FINISHED" and m["result"] in PASS
            if not passed:
                failed[m["module"]] = known.get(m["module"], f"first run: {m['status']} {m['result']}")
            if passed and m["module"] in known:
                notes.append(f"::warning::{p['plan']}/{m['module']} now passes; remove it from expected.json")
            elif not passed and m["module"] in known:
                notes.append(f"{p['plan']}/{m['module']}: expected failure ({known[m['module']]})")
            elif not passed and (recorded or m["status"] == NOT_CREATED):
                bad.append(f"{p['plan']}/{m['module']}: {m['status']} {m['result']}")
            elif not passed:
                notes.append(f"::warning::{p['plan']}/{m['module']}: first run, {m['status']} {m['result']}")
        if not recorded and release:
            bad.append(f"{p['plan']}: no recorded expected list; a release needs one (OP-155 m.3 (q))")
    return bad, notes, candidate


if __name__ == "__main__":
    main(sys.argv)
