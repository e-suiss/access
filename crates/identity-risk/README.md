# access-identity-risk

Sign-in risk of the Access identity plane: signals, a deterministic score, shadow and monitor
modes, the GeoIP/ASN source, breached-password checks, canary credentials, a human review queue,
and per-realm analytics.

Risk only narrows. It can ask a user for one more step, tell a relying party that the level
changed, and put an item in front of a person. It never allows anything, and it never locks an
account.

## Three layers

| Layer | What it reads | What it does | Where |
|---|---|---|---|
| **SL0** cryptographic facts | DPoP or mTLS mismatch, bad signature, replay | Refuses the request | protocol checks of the authority and identity planes |
| **SL1** deterministic policy | requirement terms, consequence tier, freshness | RFC 9470 step-up or `REQUIRE_ACTION` | the sign-in requirement model and the decision |
| **SL2** risk | network, device, history, counters, breach corpus, canaries | step-up request, CAEP `risk-level-change`, review item | this crate |

SL2 runs once per sign-in, when the first step has passed. What it asks for is added to the SL1
requirements; nothing SL1 asks for is ever removed.

## Signals

| Signal | Source | Weight |
|---|---|---|
| `canary_hit` | a canary account's credential matched | 100 |
| `impossible_travel` | more than 500 km from the last sign-in place, faster than 1000 km/h | 60 |
| `suspicious_ip` | the address's ASN is on the realm's deny list (no third-party reputation feed) | 40 |
| `breached_password` | the presented password is in the k-anonymity breach range | 40 |
| `brute_force` | the account counted 5 or more failed password attempts before this one | 30 |
| `new_device` | the browser has no valid device marker for the account | 20 |

The level is the sum of the fired weights: below 30 `low`, 30 to 59 `medium`, 60 and above
`high`. When a source could not answer and nothing fired, the level is `unavailable`, never
`low`. The engine never reads how a person types, moves or feels: behavioural biometrics and
emotion inference are not inputs.

## Outputs

- A `risk_level` Claim (one line per account, each level superseding the last) and one
  `risk_signal` Claim per fired signal. Neither carries assurance levels or binds an intent;
  Claim Ingest refuses a risk Claim that does.
- A step-up request to the sign-in flow: a second step from what the account has enrolled. A
  device marker does not stand in for it, and enrolment is not offered at that moment.
- CAEP `risk-level-change`, in the `stepup_caep` stage.
- A review item for a person, for every step-up request (shadowed or real) and every `high`
  level. A canary match ends the sign-in with the generic failure and never creates a session.

## Modes

The realm setting `idp.realm.protection_mode` is configuration like any other `idp.*` action:
written only against a committed decision. Tightening is CT1, loosening is CT2.

| Setting | Values | Default |
|---|---|---|
| `bot`, `suspicious_ip`, `breached_password` | `monitor` (log only) or `enforce` (ask a step-up) | `monitor` |
| `brute_force` | always `enforce`: the login throttle is never switched off | `enforce` |
| `sl2` | `shadow` → `stepup` → `stepup_caep` | `shadow` |

A new realm stays in `shadow` for 14 days whatever is set. Reviewers mark items `confirmed`,
`false_positive` or `dismissed`; the false-positive budget is 0.5 % of step-up requests over 30
days, exported as `access_risk_fp_ratio_ppm` with an alert above 5000.

## Sources

- **GeoIP/ASN.** The `GeoResolver` port and an adapter for any MMDB file (`[risk]
  geo_mmdb_path`). No data is embedded; the file is read again when it changes. Without a file
  geographic signals are unavailable and the management surface states "GeoIP source not
  configured".
- **Breached passwords.** `GET {base}/range/{prefix}` with the first five hex characters of the
  password's SHA-1 (`[risk] breach_range_api`), through the outbound client with a 2 second
  deadline and `Add-Padding: true`; the padding lines (count 0) are dropped. Or a local mirror
  (`[risk] breach_ranges_dir`). Any failure is unavailable, never "not breached".
- **Mirror refresh.** With `[risk] breach_mirror_source`, every 24 hours the mirror downloads
  every range through the padded API into `versions/<id>/` and only a complete download becomes
  `current`, by one rename of a link; a refresh that stops halfway leaves the old version served.
  The replaced version stays on disk and is recorded as archived; nothing is removed.

## Privacy

- An address is never stored. SL2 keeps a keyed pseudonym (HMAC in the token, per realm) and the
  `/24` or `/48` prefix, with a coarse place (a hundredth of a degree), and nothing of it reaches
  telemetry.
- Metrics carry no tenant, realm or domain label.
- Analytics are daily counters per realm (funnel, method distribution, passkey adoption, MFA
  setup, failed logins, risk step-ups and false positives) with no identifier and no pseudonym.
  They are read only through a realm-scoped transaction and are never a decision input.

## Incident order

Containment is a narrowing Exercise; then device registrations, then sessions (a
`session_epoch` step), then tokens. Signals go out last and are information, not security.
