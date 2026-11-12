# GKD test report template (ÖHY ve BS Tebliği m.22/6)

A template for each of the two tests a year of the institution's strong customer
authentication (GKD) on Access. Keep one filled copy per test. The report records what was
tested and what was observed; regulatory conformity is NOT GUARANTEED by this template or by
Access, and the legal assessment is the institution's.

| Field | Value |
|---|---|
| Test period | [first or second half of the year, YYYY] |
| Date | [date] |
| Realm and governing domain | [realm slug, domain identifier] |
| Access version | [version and release checkpoint] |
| Tester | [name, independence from the operating team] |

## Checks

| # | Check | How | Expected | Observed | Pass |
|---|---|---|---|---|---|
| 1 | Realm settings still match the `tr-gkd` template | `access-cli diff` against the applied template | no change | [ ] | [ ] |
| 2 | A payment without an authentication is refused | submit a CT2 payment without a proof | required action | [ ] | [ ] |
| 3 | A payment with an authentication bound to another payment is refused | reuse a proof from another intent | required action | [ ] | [ ] |
| 4 | A payment without the app-controlled factor is refused | approve with the passkey alone | required action | [ ] | [ ] |
| 5 | An SMS code is refused at sign-in | sign in with an SMS code | refused | [ ] | [ ] |
| 6 | An SMS code is refused after a recent SIM change | activate after a SIM change signal | refused | [ ] | [ ] |
| 7 | Platform biometrics alone do not count as an element | approve with biometrics only | required action | [ ] | [ ] |
| 8 | The audit stream records each refusal | read the realm audit stream | one record per refusal | [ ] | [ ] |

## Findings and actions

| Finding | Severity | Action | Owner | Due |
|---|---|---|---|---|
| [ ] | [ ] | [ ] | [ ] | [ ] |

## Sign-off

| Role | Name | Date |
|---|---|---|
| Tester | [ ] | [ ] |
| GKD owner | [ ] | [ ] |
