# L0 Validity Contract

A validity contract is the semantic contract of every reusable artifact: a portable authority proof, a bounds token, a reusable decision, a session or access token. It says until when, for whom, under which freshness rules and within which bounds the artifact may be relied on without asking the domain again.

A validity contract is a value. It carries no authority of its own. The container that embeds it (a portable authority proof or a token) is defined in L2; this part defines the contract's fields and the arithmetic and checks that every verifier applies.

Vectors for the acceptance end and the signing time: [`core/1/validity.json`](../../conformance/vectors/core/1/validity.json), operation `validity.check`.

## 1. Structure

<a id="L0-VAL-1"></a><!-- no-vector: definition: lists the contract fields; their checks are in the rules below -->**L0-VAL-1. Fields.** A validity contract is the CDDL `validity-contract`:

| Field | Meaning |
|---|---|
| `issuing_exercise` | The exercise that issued the contract |
| `basis_ref` | Reference to the authority state the contract was issued against; may be an opaque token |
| `holder` | The holder's key binding; a contract is never a bearer contract |
| `audience` | The verifiers the contract is valid at |
| `bounds` | The authority the artifact can be used for: the Grant's authority intersected with the Mandate and limited to the intended actions, with action prefixes pinned to a catalog |
| `profile` | Connectivity class, variant, the connectivity profile track `version`, and parameters |
| `horizon` | Absolute end of validity (TrustedTime) |
| `max_staleness_ms` | Δ: how old the verifier's status information may be |
| `freshness_sources` | Where the verifier refreshes status |
| `revalidation` | When a new online decision is required |
| `offline_slice` | Budget drawn in advance for offline use |
| `local_requirements` | Requirement terms the verifier checks locally |
| `verifier_profile_ref` | Digest of the verifier profile the contract was issued for |
| `clock` | Accepted clock source class and skew tolerance |
| `must_understand` | Extensions the verifier must understand |

<a id="L0-VAL-2"></a><!-- no-vector: definition: names the derived properties -->**L0-VAL-2. Derived semantic fields.** Three semantic properties are derived from these fields: the horizon (`horizon`), the freshness profile (`profile`, `max_staleness_ms`, `freshness_sources`) and the revalidation condition (`revalidation`).

<a id="L0-VAL-3"></a>**L0-VAL-3. Profile classes and variants.** The class set is closed: `online`, `intermittent`, `offline`, `long-running`. Each variant belongs to exactly one class:

| Variant | Class |
|---|---|
| `online-strict` | `online` |
| `bounded-staleness` | `intermittent` |
| `revalidate-on-reconnect` | `intermittent` |
| `checkpointed-offline` | `offline` |
| `checkpoint-continuation` | `long-running` |

A contract whose `class` is not the class of its `variant` is malformed and MUST be rejected. Class and variant are must-understand. Parameter values are local.

## 2. Computing the horizon

<a id="L0-VAL-5"></a>**L0-VAL-5. Horizon bound.** When a contract is issued, its horizon MUST NOT be later than the earliest dependency bound of the authority it rests on, and MUST NOT exceed the profile's maximum. This computation is part of the core semantics and uses checked arithmetic: the horizon is the smallest of `issued_at + profile_max_ms` and every dependency bound, and an overflow of the addition is `overflow`.

Vectors: [`core/1/horizon.json`](../../conformance/vectors/core/1/horizon.json), operation `validity.horizon`. Each case gives `issued_at`, the `dependency_bounds` and `profile_max_ms`, and either the expected `horizon` or `error: "overflow"`.

<a id="L0-VAL-5a"></a><!-- no-vector: no-operation: dependency bounds are gathered when a contract is issued, which arrives with PAP and token issuance (Ek B Stage 4) -->**L0-VAL-5a. Dependency bounds.** The dependency bounds are the `validity.until` of every hop, and `time + freshness_ms` of every proof the decision relied on that has a `freshness_ms`. The operational key window and budget windows are not dependency bounds.

<a id="L0-VAL-6"></a><!-- no-vector: no-operation: contract narrowing arrives with PAP and token issuance (Ek B Stage 4) -->**L0-VAL-6. Narrowing is monotone.** A contract derived by narrowing another contract MUST NOT have a later horizon or a larger Δ than the contract it narrows.

<a id="L0-VAL-7"></a>**L0-VAL-7. Staleness is consumed.** The staleness window Δ is measured from the verifier's last status refresh. It is consumed as time passes and is never extended by the absence of events, by missing acknowledgements, or by clock drift.

## 3. Verifier checks

A verifier applies these checks before relying on an artifact that carries a validity contract. Each failure is a local DENY: the verifier refuses, and MAY instead ask the domain online where the profile allows it.

<a id="L0-VAL-10"></a>**L0-VAL-10. Local ceilings.** The verifier computes the acceptance end:

```
accept_until = min(horizon, iat + cap)
```

where `iat` is the artifact's signing time and `cap = cap_horizon(class, variant, CT)`: class and variant come from the verifier's own profile, and CT is the consequence tier of the intent the verifier is performing. The ceilings come only from the Domain Metadata and the verifier profile. The artifact's own declaration of a ceiling is never used. The computation is checked ([L0-VAL-20](#L0-VAL-20)).

<a id="L0-VAL-10a"></a>**L0-VAL-10a. Ceiling sources.** Domain Metadata declares its ceilings as `caps.horizon`, a map from CT to milliseconds whose keys are the text strings `"ct0"`, `"ct1"`, `"ct2"` and `"ct3"` (integer map keys are used only in COSE headers, [L0-ENC-4](encoding.md#L0-ENC-4)). The Verifier Profile declares its ceilings in the same form for each class and variant. The effective ceiling `cap` is the smallest of all declared ceilings that apply to the class, variant and CT: the metadata's, the Verifier Profile's, and the protocol default for that class, variant and CT. If neither the metadata nor the Verifier Profile declares one, the protocol default applies.

<a id="L0-VAL-10b"></a>**L0-VAL-10b. Who chooses the ceiling.** Choosing `cap` from the declared tables is the verifier's job. The check of this part takes `cap` and `iat` as given and computes `accept_until` from them; it never reads a ceiling from the contract.

Vectors: `validity.json`: `cap-later-than-horizon-edge`, `cap-later-than-horizon-past`, `cap-earlier-than-horizon-edge`, `cap-earlier-than-horizon-past`, `cap-equal-to-horizon`, `cap-zero`, `cap-zero-past`, `cap-overflow`. Each case gives `iat`, `horizon_cap_ms` and `now`; the contract, audience, `online` and skew are given at file level, and a case may give its own `contract`, `online` or `last_refresh`.

<a id="L0-VAL-11"></a>**L0-VAL-11. Within the horizon.** The horizon is inclusive: `now = horizon` is accepted. With the skew of [L0-VAL-14](#L0-VAL-14), the verifier accepts only when `now ≤ accept_until + skew`.

<a id="L0-VAL-12"></a>**L0-VAL-12. Key window.** The artifact's `iat` MUST lie within the signing key's window `[valid_from, valid_until]` ([L0-SIG-71](signatures.md#L0-SIG-71)). An `iat` outside the window is rejected. No skew is applied to this check.

<a id="L0-VAL-13"></a>**L0-VAL-13. Audience and holder.** The verifier MUST be in `audience`, and the presenter MUST prove possession of the `holder` key.

<a id="L0-VAL-14"></a>**L0-VAL-14. Clock.** The verifier's clock source MUST be of the class named in `clock.source_class`. The skew tolerance is the verifier's parameter for the artifact class; for artifacts produced by the domain itself the default is 60 seconds. The contract's `clock.skew_ms` can only narrow it: the skew used is the smaller of the two.

<a id="L0-VAL-14a"></a>**L0-VAL-14a. Where skew applies.** Skew is applied in exactly two places: at the end of acceptance (`now ≤ accept_until + skew`, [L0-VAL-11](#L0-VAL-11)) and to a future-dated signing time (`iat ≤ now + skew`). It is not applied to the key window ([L0-VAL-12](#L0-VAL-12)). Both additions are checked.

<a id="L0-VAL-14b"></a>**L0-VAL-14b. Future-dated signing time.** If `iat > now + skew`, the artifact is rejected with reason `not-yet-valid`. This check is made before the acceptance end of [L0-VAL-11](#L0-VAL-11). `iat = now + skew` is accepted.

Vectors: `validity.json`: `iat-future-edge`, `iat-future-past`; the contract's own skew narrows the verifier's in `contract-skew-narrows-edge` and `contract-skew-narrows-past`.

<a id="L0-VAL-15"></a><!-- no-vector: no-operation: offline bounds and local-requirement checks arrive with PAP and token verification (Ek B Stage 4) -->**L0-VAL-15. Bounds.** The intent the verifier is about to perform MUST be covered by `bounds` ([L0-EVAL-10](evaluation.md#L0-EVAL-10)), and every term in `local_requirements` MUST be satisfied locally. If a local requirement cannot be satisfied, the artifact is not accepted offline.

<a id="L0-VAL-16"></a>**L0-VAL-16. Staleness.** If the contract has `max_staleness_ms`, the verifier's status information MUST be at most that old. If it is older, the verifier MUST NOT accept the artifact offline and may only ask online.

<a id="L0-VAL-16a"></a>**L0-VAL-16a. Online and offline use.** `online` means the verifier obtains an online decision for this use; the contract is then checked only up to the acceptance end. Without an online decision, the variant decides:

| Variant | Offline use |
|---|---|
| `online-strict` | Rejected: `online-required` |
| `revalidate-on-reconnect` | Accepted up to the acceptance end; the next reconnect requires a new decision ([L0-VAL-17](#L0-VAL-17)) |
| `bounded-staleness` | Accepted while `now − last_refresh ≤ max_staleness_ms`; otherwise `stale` |
| `checkpointed-offline`, `checkpoint-continuation` | Accepted up to the acceptance end |

Under `bounded-staleness`, a missing `max_staleness_ms`, a missing `last_refresh`, or a `last_refresh` later than `now` is `stale` ([L0-VAL-7](#L0-VAL-7)).

<a id="L0-VAL-16b"></a>**L0-VAL-16b. Reason codes.** The checks run in this order and the first failure is the result: `must-understand`, `audience`, `not-yet-valid` ([L0-VAL-14b](#L0-VAL-14b)), `expired` ([L0-VAL-11](#L0-VAL-11)), then the offline rule of [L0-VAL-16a](#L0-VAL-16a) (`online-required`, `stale`). An overflow anywhere is `overflow` ([L0-VAL-20](#L0-VAL-20)).

Vectors: `validity.json`: `online-strict-offline`, `reconnect-offline-accepted`, `reconnect-offline-horizon-edge`, `reconnect-offline-past-horizon`, `bounded-fresh`, `bounded-stale`, `bounded-no-refresh`, `bounded-future-refresh`, `bounded-online-ignores-refresh`, `checkpointed-offline-accepted`, `audience-other`, `must-understand-unknown`. A contract whose class does not match its variant is an `input` rejection: `class-variant-mismatch`.

<a id="L0-VAL-17"></a>**L0-VAL-17. Revalidation.** When a `revalidation` condition is met (a number of uses, a reconnect, or an action of a listed class), the verifier MUST obtain a new online decision before relying on the artifact again. Under `revalidate-on-reconnect` a reconnect always requires a new decision.

<a id="L0-VAL-18"></a><!-- no-vector: no-operation: offline slice consumption arrives with PAP and token verification (Ek B Stage 4) -->**L0-VAL-18. Offline slice.** For a consumption-bearing action the total drawn locally from a slice entry MUST NOT exceed its `amount`, in its `unit`. Consumption beyond the slice cannot happen offline. The slice was drawn from the lineage budgets when the contract was issued, so the same capacity cannot be spent twice centrally.

<a id="L0-VAL-19"></a>**L0-VAL-19. Profile and must-understand.** The verifier MUST NOT accept a contract its own profile does not support, and MUST reject a contract with any `must_understand` entry it does not recognise.

<a id="L0-VAL-20"></a>**L0-VAL-20. Checked arithmetic.** Every addition and comparison in this part uses checked arithmetic ([L0-ENC-7](encoding.md#L0-ENC-7)). An overflow in a verifier makes the artifact invalid.
