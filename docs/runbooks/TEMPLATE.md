# Runbook: <alert name>

One file per alert (OP-67, OP-70). Copy this template to `docs/runbooks/<alert-name>.md`.

## Meaning
What the alert indicates, in one or two sentences. Link the signal in the specification (§17.8.2).

## Impact
Who or what is affected, and whether authority decisions, sign-ins or audit guarantees are at risk.

## Diagnosis
1. Dashboards and queries to check first.
2. How to tell the likely causes apart.

## Remediation
Step-by-step actions. Never use a path that bypasses a security control (TI-9, SI-22); emergency access goes only through the reserved break-glass Grant.

## Escalation
Who to notify and when, including security incident and CVD/PSIRT triggers (SA-16).
