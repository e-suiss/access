# L0 Evaluation

This part defines how an evaluator turns a prepared evaluation input into a decision. The evaluator is a pure function: it reads only its input, does no I/O, and returns the same bytes for the same input.

```
evaluate(input: evaluation-input, fuel: uint) -> decision | rejection
```

A decision has one of three outcomes: `allow`, `deny` or `require_action`. There is no fourth outcome. A rejection is not a decision ([§8](#8-rejections-and-decisions)).

## 1. The evaluation input

<a id="L0-EVAL-1"></a>**L0-EVAL-1. Purity.** The evaluator MUST compute its result from the `evaluation-input` and the fuel budget alone. Two conformant evaluators given the same input bytes and the same fuel budget MUST return the same decision bytes or the same rejection kind.

<a id="L0-EVAL-2"></a>**L0-EVAL-2. Input fields.**

| Field | Meaning |
|---|---|
| `mode` | `commit` (a decision relied upon; ALLOW starts an exercise), `continue` (a new decision on a running exercise), `check` (advisory; not recorded, not a promise) |
| `intent`, `intent_digest` | The intent envelope and its digest ([L0-ENC-23](encoding.md#L0-ENC-23)) |
| `now` | Trusted evaluation time |
| `actor_instance` | The authenticated actor Instance, if any |
| `actor_is_agent` | Present and `true` when the actor Instance is a software agent |
| `mandate` | The actor Instance's own limits, if it has any |
| `capacity` | The capacity the actor declares: `own` or `for` a Party |
| `bases` | Candidate bases. Each is a list of hops from hop 0 toward the root, and the capacities the basis permits |
| `restrictions` | The result of each restriction policy that applies |
| `proofs` | The proofs presented with the request |
| `catalog` | Pinned action catalogs, reserved actions, and the declared purpose order |

Each hop carries the Grant's `canonical-authority`, its `status` if it is revoked or lapsed, `conditions_fail` if a while-condition no longer holds, and the state of each budget it draws from. A hop whose stored Grant the reading layer did not understand is exactly `{not_understood: true}` ([L0-ALG-4a](algebra.md#L0-ALG-4a)).

<a id="L0-EVAL-3"></a>**L0-EVAL-3. Decoding.** The input MUST be canonical ([L0-ENC-1](encoding.md#L0-ENC-1) to [L0-ENC-9](encoding.md#L0-ENC-9)), MUST match the CDDL `evaluation-input`, and MUST respect the limits of [L0-ENC-10](encoding.md#L0-ENC-10). A purpose order with a cycle is rejected ([L0-ALG-47](algebra.md#L0-ALG-47)). An input with two catalog entries for the same `catalog` digest, two purpose entries for the same purpose, or two proofs with the same `id` is rejected. An assurance dimension or level outside the closed list ([L0-ALG-60a](algebra.md#L0-ALG-60a)) is rejected. Any failure is an `input` rejection.

Vectors: `decision.json`: `reject-duplicate-proof-id`, `reject-purpose-cycle`, `reject-unknown-field`, `reject-unknown-mode`.

<a id="L0-EVAL-4"></a>**L0-EVAL-4. Prepared facts.** The input is prepared outside the evaluator. In particular, the preparer computes the intent digest, each hop's revocation and lapse status, whether its while-conditions hold, each budget's remaining amount and the demand of this intent in the budget's unit, and each restriction policy's result. The evaluator takes these facts as given. It does not recompute `intent_digest`.

<a id="L0-EVAL-4a"></a>**L0-EVAL-4a. Intent digest.** The evaluator never recomputes `intent_digest`. The Access layer that prepares the input computes it from the canonical `intent` ([L0-ENC-23](encoding.md#L0-ENC-23)). A digest supplied by the caller is never input: a preparer MUST NOT copy a requester's digest into `intent_digest`.

## 2. Intent coverage

<a id="L0-EVAL-10"></a>**L0-EVAL-10. Coverage.** An authority set covers an intent when all of these hold:

- the intent's action is covered by the authority's action set ([L0-ALG-33](algebra.md#L0-ALG-33));
- every resource of the intent is within the authority's resource selector ([L0-ALG-41](algebra.md#L0-ALG-41));
- for every parameter the authority bounds, the intent has a value for it and the value is within the bound ([L0-ALG-13](algebra.md#L0-ALG-13)), except that a `subject: public` bound is no restriction: it holds whether or not the intent has a value for the parameter;
- if the authority has a `recipient` other than `public`, the intent has a `recipient` and that Party is within the selector ([L0-ALG-45](algebra.md#L0-ALG-45)). A `public` recipient is no restriction: it covers intents with and without a `recipient`;
- if the authority has a `purpose`, the intent has a `purpose` and it is below some element of the authority's purpose set ([L0-ALG-47](algebra.md#L0-ALG-47)).

Parameters the authority does not bound are not checked. Opaque parameters (digests in `opaque`) and context references are never checked against authority.

<a id="L0-EVAL-11"></a>**L0-EVAL-11. Schema mismatch.** An intent action that matches an authority action by identity but carries a different schema digest is not covered ([L0-ALG-30](algebra.md#L0-ALG-30)). On a hop this gives `no-covering-authority`; on the mandate it gives `outside-instance-limits`. The class `schema-not-accepted` belongs to the layer that prepares the input, not to the evaluator.

Vector: `decision.json`: `deny-schema-digest-mismatch`.

## 3. Checks on each hop, the mandate and restrictions

<a id="L0-EVAL-12"></a>**L0-EVAL-12. Coverage on every hop.** Coverage is checked on every hop of the basis separately. Every hop whose authority does not cover the intent contributes its own `no-covering-authority` blocker at that hop.

Vectors: [`core/1/decision.json`](../../conformance/vectors/core/1/decision.json), `combinator.evaluate`: `allow`, `deny-no-covering-authority-hop1`. [`core/1/cve-regressions.json`](../../conformance/vectors/core/1/cve-regressions.json): `recipient-party-other`, `prefix-old-catalog`.

<a id="L0-EVAL-12a"></a>**L0-EVAL-12a. Hop not understood.** A hop written as `{not_understood: true}` covers nothing. It contributes exactly one blocker, `no-covering-authority` at that hop ([L0-EVAL-40](#L0-EVAL-40)), and no requirement terms. No validity, status, condition or budget check is made for it. The other hops of the basis are checked as usual.

Vectors: `decision.json`: `deny-not-understood-hop1-commit`, `deny-not-understood-hop0-continue`, `deny-not-understood-keeps-unmet`, `check-not-understood-then-allow`, `check-not-understood-only`.

<a id="L0-EVAL-13"></a>**L0-EVAL-13. Validity window.** A hop's validity window `[from, until]` is closed. If `now < from`, the hop has not started. If `now > until`, the hop has expired. Each produces the blocker given in [L0-EVAL-40](#L0-EVAL-40).

Vectors: `decision.json`: `deny-expired`, `deny-not-yet-valid`; `cve-regressions.json`: `expired-invitation`.

<a id="L0-EVAL-14"></a>**L0-EVAL-14. Status and conditions.** A hop with `status: "revoked"` produces an `ended/revoked` blocker. A hop with `status: "lapsed"`, or with `conditions_fail: true`, produces an `ended/lapsed` blocker.

Vectors: `decision.json`: `deny-revoked`, `deny-lapsed`.

<a id="L0-EVAL-15"></a>**L0-EVAL-15. Budgets.** For each budget state of a hop, if `demand > remaining` the hop produces a `budget-exhausted` blocker. For a `total` window the blocker routes to the grantor. For a rolling window the blocker tells the requester to wait until `resets_at`.

Vectors: `decision.json`: `deny-budget-rolling`, `deny-budget-total`; `cve-regressions.json`: `invitation-reused`.

<a id="L0-EVAL-15a"></a>**L0-EVAL-15a. Rolling budget without reset time.** A budget state with a rolling window, `demand > remaining` and no `resets_at` makes the whole input an `input` rejection. This check is made for every basis before any evaluation starts, so in `check` mode an early ALLOW does not skip it and the result never depends on the order of the candidates.

Vectors: `decision.json`: `reject-rolling-budget-without-reset`, `reject-check-bad-later-candidate`.

<a id="L0-EVAL-16"></a>**L0-EVAL-16. Mandate.** If the input has a `mandate`, its authority set must cover the intent ([L0-EVAL-10](#L0-EVAL-10)); if it does not, the evaluation produces an `outside-instance-limits` blocker. The mandate's requirement terms are added to the requirements at position `instance`.

Vector: `decision.json`: `deny-outside-instance-limits`.

<a id="L0-EVAL-17"></a>**L0-EVAL-17. Capacity.** The declared `capacity` MUST be one of the basis's `capacities`. If it is not, the basis produces a `capacity-mismatch` blocker at hop 0.

Vectors: `decision.json`: `deny-capacity-mismatch`; `cve-regressions.json`: `impersonate-admin`.

<a id="L0-EVAL-18"></a>**L0-EVAL-18. Restriction results.** Each `policy-result` is handled by its outcome:

- `no_objection`: no effect;
- `deny`: a `restricted` blocker whose subcode is `restricted/policy:` followed by the unpadded base64url encoding of the 16-byte policy reference ([L0-ENC-16](encoding.md#L0-ENC-16)). The `undisclosed` flag does not change the subcode; whether the reason is shown is decided outside L0;
- `require`: each listed requirement term is added to the requirements at position `domain-policy`.

A `deny` outcome whose `policy` or `policy_version` differs from the enclosing result's `policy` or `version` is an `input` rejection. Restrictions can only deny or require; they never cover an intent.

Vectors: `decision.json`: `deny-restricted`, `deny-overrides-require`, `require-from-restriction`, `allow-restriction-no-objection`, `reject-restriction-deny-other-policy`; `cve-regressions.json`: `exclusion-over-covering-grant`, `two-exclusions`, `two-exclusions-reordered`.

<a id="L0-EVAL-19"></a>**L0-EVAL-19. Requirements from hops.** The requirement terms of hop `k` are added to the requirements at position `hop(k)`.

<a id="open-intent-validity"></a><a id="L0-EVAL-5"></a>**L0-EVAL-5. Intent validity.** If `now` is outside the intent's own `validity` window (a closed interval), the input is an `input` rejection. No decision is produced and nothing is recorded.

Vectors: `decision.json`: `reject-intent-expired`, `reject-intent-not-yet-valid`.

## 4. Requirement resolution

Requirement resolution decides which requirement terms the presented proofs satisfy, and which proofs the decision relies on.

<a id="L0-EVAL-20"></a>**L0-EVAL-20. Entries.** The entries to resolve are the pairs (term, position) collected by [L0-EVAL-16](#L0-EVAL-16), [L0-EVAL-18](#L0-EVAL-18) and [L0-EVAL-19](#L0-EVAL-19). The pool starts as all presented proofs.

<a id="L0-EVAL-21"></a>**L0-EVAL-21. One term at a time.** Identical terms are merged: a term that comes from several hops, from the mandate or from restriction results is one term, however often it appears. Its position is the position of its first occurrence, in this order: hops from hop 0 upward, then `instance`, then `domain-policy`. The distinct terms are resolved one after another, in the order of the bytes of their canonical encoding; a single-use proof two terms could use goes to the term that comes first in that order. Each term either is satisfied by a chosen set of proofs or becomes an unmet term.

Vector: `decision.json`: `require-shared-single-use-proof-canonical-order`.

A delegated Grant carries its parent's requirements ([L0-ALG-76](algebra.md#L0-ALG-76)), so counting a term once per hop would ask for the same step-up on every hop.

Vectors: `decision.json`: `allow-inherited-term-counts-once`, `require-inherited-term-at-first-hop`.

<a id="L0-EVAL-22"></a>**L0-EVAL-22. Proof matches term.** A proof matches a term when all of these hold:

- the proof's `kind` equals the term's `proof_kind`, and the classes are equal;
- the binding holds ([L0-EVAL-23](#L0-EVAL-23));
- the time rule holds ([L0-EVAL-24](#L0-EVAL-24));
- the issuer is within the term's `source` selector, if the term has one;
- the assurance rule holds ([L0-EVAL-25](#L0-EVAL-25));
- if the term is `single_use`, the proof is not marked `consumed`.

<a id="L0-EVAL-23"></a>**L0-EVAL-23. Binding.**

| Term `binding` | Holds when |
|---|---|
| none | always |
| `actor_instance` | the input has `actor_instance` and the proof's `bound_instance` equals it |
| `intent_digest` | the proof's `bound_intent` equals `intent_digest` |
| `resource` | the proof's `bound_resource` equals one of the intent's resources |

<a id="L0-EVAL-24"></a>**L0-EVAL-24. Time.** A proof whose `time` is later than `now` never matches, whether or not the term has `freshness_ms`. If the term has `freshness_ms`, the proof matches only when `now − time ≤ freshness_ms`.

Vector: `decision.json`: `require-future-dated-proof`.

<a id="L0-EVAL-25"></a>**L0-EVAL-25. Assurance.** For each dimension in the term's `assurance`, the proof MUST have the same dimension with a level that meets the term's floor: `level ≥ floor`, except for `synced`, where `level ≤ floor` ([L0-ALG-60](algebra.md#L0-ALG-60)). A floor `synced: 0` therefore asks for a key that is not synced. A dimension missing from the proof does not meet the floor.

Vectors: `decision.json`: `allow-assurance-<dimension>-at-floor` and `require-assurance-<dimension>-below-floor` for each dimension other than `synced`, `allow-assurance-loa-eidas-above-floor`, `allow-assurance-synced-unsynced-meets-zero`, `require-assurance-synced-inverted`, `allow-assurance-synced-floor-one-unsynced`, `require-assurance-missing-in-proof`, and the rejections `reject-assurance-unknown-dimension-term`, `reject-assurance-unknown-dimension-proof`, `reject-assurance-auth-time-is-not-a-dimension`, `reject-assurance-aal-zero-term`, `reject-assurance-aal-four-proof`, `reject-assurance-flag-two-term`, `reject-assurance-out-of-range-mandate`.

<a id="L0-EVAL-26"></a>**L0-EVAL-26. Count and independence.** A term needs `count` matching proofs (1 if not written). If the term has `independence`, the chosen proofs MUST all differ in the named field: `party`, `instance` or `issuer`.

<a id="L0-EVAL-27"></a>**L0-EVAL-27. Choosing proofs.** Among all sets of `count` matching proofs from the current pool that meet the independence rule, the evaluator chooses one set as follows:

1. the set whose latest proof has the earliest `position`;
2. on a tie, compare the ascending lists of positions of the sets lexicographically, and take the smaller;
3. on a further tie, order each set's proofs by (`position`, `id`) and compare the lists of ids lexicographically, and take the smaller.

The ids of the chosen proofs are recorded as relied on.

Vector: `decision.json`: `allow-with-proof`.

<a id="L0-EVAL-28"></a>**L0-EVAL-28. Consumption.** When a `single_use` term is satisfied, its chosen proofs leave the pool and cannot satisfy later entries. A proof chosen for a reusable term stays in the pool and can satisfy later entries, including a later `single_use` entry. An unmet entry consumes nothing.

<a id="L0-EVAL-29"></a>**L0-EVAL-29. Unmet terms.** An entry with no acceptable set becomes an `unmet-term` with its term, its position, and `missing = count − s`, where `s` is the size of the largest set of matching proofs that meets the independence rule (at most `count`).

Vectors: `decision.json`: `require-step-up`, `check-first-require`.

<a id="L0-EVAL-30"></a>**L0-EVAL-30. Satisfiable by the actor.** `satisfiable_by_actor` is `false` exactly when the term's `assurance` has `human_presence` greater than 0 and the input has `actor_is_agent: true`. Otherwise it is `true`.

Vectors: `decision.json`: `require-human-presence-agent`, `require-human-presence-zero-agent`.

<a id="L0-EVAL-31"></a>**L0-EVAL-31. Source not accepted.** If an entry is unmet and some proof in the pool matches the term in every respect except the `source` rule, the evaluation produces a `source-not-accepted` blocker in addition to the unmet term.

Vector: `decision.json`: `deny-source-not-accepted`.

## 5. The decision combinator

<a id="L0-EVAL-33"></a>**L0-EVAL-33. Outcome of one basis.** For one candidate basis, the blockers are those of its hops ([L0-EVAL-12](#L0-EVAL-12) to [L0-EVAL-15](#L0-EVAL-15)), its capacity check ([L0-EVAL-17](#L0-EVAL-17)), the mandate ([L0-EVAL-16](#L0-EVAL-16)), the restrictions ([L0-EVAL-18](#L0-EVAL-18)) and requirement resolution ([L0-EVAL-31](#L0-EVAL-31)). Then:

1. if there is any blocker, the outcome is `deny`, and the unmet terms are listed as well;
2. otherwise, if there is any unmet term, the outcome is `require_action`;
3. otherwise the outcome is `allow`.

Deny overrides everything: a restriction DENY wins over a covering Grant and over unmet requirements.

Vectors: `decision.json`: `deny-overrides-require`, `deny-four-blocker-classes`.

<a id="L0-EVAL-34"></a>**L0-EVAL-34. Commit and continue.** In `commit` and `continue` mode, `bases` MUST hold exactly one basis, the one the requester declared. Any other number is an `input` rejection. The outcome is the outcome of that basis.

Vector: `decision.json`: `reject-commit-two-bases` (rejection `input`).

<a id="L0-EVAL-35"></a>**L0-EVAL-35. Check.** In `check` mode the candidate bases are evaluated one by one, in the order given. Evaluation stops at the first candidate whose outcome is `allow`, and the decision is that candidate's `allow`. If no candidate allows and some candidate's outcome is `require_action`, the decision is the first such candidate's `require_action`. Otherwise the decision is `deny` ([L0-EVAL-36](#L0-EVAL-36)).

Vectors: `decision.json`: `check-first-require`.

<a id="L0-EVAL-35a"></a>**L0-EVAL-35a. Check with no basis.** If `bases` is empty in `check` mode, the decision is `deny` with exactly one blocker: `no-covering-authority` at hop 0. The mandate and the restriction results are not evaluated.

Vectors: `decision.json`: `check-no-basis`, `check-no-basis-only-no-covering`.

<a id="L0-EVAL-36"></a>**L0-EVAL-36. Check DENY content.** A `check` DENY carries the union of the blockers of all candidates, as one set ([L0-EVAL-41](#L0-EVAL-41)). It carries no unmet terms.

Vector: `decision.json`: `check-deny-merges-blockers-only`.

<a id="L0-EVAL-37"></a>**L0-EVAL-37. Shared blockers.** Blockers and requirements from the mandate and the restrictions apply to every candidate basis that is evaluated.

## 6. Blockers and the decision encoding

<a id="L0-EVAL-40"></a>**L0-EVAL-40. Blocker table.** Each blocker carries a class, an optional subcode, a position, a resolver class and a remediation code:

| Condition | Class / subcode | Position | Resolver | Remediation |
|---|---|---|---|---|
| Hop does not cover the intent, or is not understood | `no-covering-authority` | `hop(k)` | `grantor_of_hop(k)` | `route-to-coordinator` |
| Mandate does not cover the intent | `outside-instance-limits` | `instance` | `actor-party` | `route-to-coordinator` |
| Restriction DENY | `restricted`, `restricted/policy:<ref>` | `domain-policy` | `restriction-owner` | `not-satisfiable-by-actor` |
| Budget short, rolling window | `budget-exhausted` | `hop(k)` | `time` | `wait_until(resets_at)` |
| Budget short, total window | `budget-exhausted` | `hop(k)` | `grantor_of_hop(k)` | `route-to-coordinator` |
| Hop expired | `ended`, `ended/expired` | `hop(k)` | `grantor_of_hop(k)` | `new-request-required` |
| Hop not yet started | `ended`, `ended/expired` | `hop(k)` | `time` | `wait_until(from)` |
| Hop revoked | `ended`, `ended/revoked` | `hop(k)` | `grantor_of_hop(k)` | `new-request-required` |
| While-condition failed or lapsed | `ended`, `ended/lapsed` | `hop(k)` | `grantor_of_hop(k)` | `new-request-required` |
| Capacity not in the basis | `capacity-mismatch` | `hop(0)` | `actor` | `new-request-required` |
| Proof issuer outside the source | `source-not-accepted` | `actor-side` | `issuer` | `refresh-claim` |

The class set is closed. A reader that meets an unknown subcode reads the blocker as its class.

<a id="L0-EVAL-41"></a>**L0-EVAL-41. Blocker order.** `blockers` is a set like any other ([L0-ENC-6](encoding.md#L0-ENC-6)): sorted by the bytes of each blocker's canonical encoding, with repeats removed.

Vector: `decision.json`: `deny-four-blocker-classes`.

<a id="L0-EVAL-42"></a>**L0-EVAL-42. Decision encoding.** The decision is a canonical `decision` map:

- `outcome` is always written;
- `blockers` is written only when the outcome is `deny`;
- `unmet` is written whenever there is at least one unmet term, including on a `deny` in `commit` or `continue` mode (never on a `check` DENY, [L0-EVAL-36](#L0-EVAL-36)). It is a set ([L0-ENC-6](encoding.md#L0-ENC-6));
- `relied_on` is written only when the outcome is `allow` and some proof was relied on. It is the set of the relied-on proof ids;
- empty lists are not written.

<a id="L0-EVAL-43"></a>**L0-EVAL-43. Versions.** The evaluator never writes `versions` into a decision. The layer that records or signs the decision adds the spec versions.

<a id="L0-EVAL-44"></a><!-- no-vector: definition: names data-model values that no rule of this version produces -->**L0-EVAL-44. Classes not produced here.** The classes `schema-not-accepted`, `nonce-closed` and `foreign-status-unavailable`, the positions `anchor` and `foreign`, and the resolvers `root` and `domain-admin` are part of the data model but are not produced by the rules of this version.

## 7. Fuel

<a id="L0-EVAL-45"></a>**L0-EVAL-45. Cost.** The evaluator is given a fuel budget. For each candidate it evaluates, it spends one unit for each hop it checks, one unit for each restriction result, and one unit for each comparison of one proof with one requirement term (each term is compared with every proof in the current pool). In `check` mode only the candidates evaluated before the stop of [L0-EVAL-35](#L0-EVAL-35) are counted, and restriction results are charged again for each of them.

<a id="L0-EVAL-46"></a>**L0-EVAL-46. Exhaustion.** If the evaluator would spend more fuel than the budget, it stops and returns a `fuel` rejection. Running out of fuel is never a decision. A time limit, if any, is applied outside the evaluator.

## 8. Rejections and decisions

<a id="L0-EVAL-50"></a><!-- no-vector: unreachable: no rule of this version has arithmetic that can overflow (L0-EVAL-50a) -->**L0-EVAL-50. Overflow.** An arithmetic overflow while computing a decision makes the outcome `deny`. It never produces a partial `allow`.

<a id="L0-EVAL-50a"></a><!-- no-vector: unreachable: states that no rule of this version can overflow -->**L0-EVAL-50a. No overflow in this version.** No rule of this version has arithmetic that can overflow. Budgets are compared, never subtracted. `now − time` ([L0-EVAL-24](#L0-EVAL-24)) is computed only when `time ≤ now`, and `count − s` ([L0-EVAL-29](#L0-EVAL-29)) only when `s ≤ count`. The only conversion that can fail gives an `input` rejection. A later rule that adds arithmetic MUST name the blocker its overflow produces; a rule that does not name one cannot enter L0.

<a id="L0-EVAL-60"></a>**L0-EVAL-60. Rejection kinds.** A rejection is a reasoned refusal to evaluate. It has one of two kinds:

| Kind | Causes |
|---|---|
| `input` | Non-canonical encoding, a schema mismatch with the CDDL, an unknown field or choice, an assurance dimension or level outside the closed list, a limit exceeded ([L0-ENC-10](encoding.md#L0-ENC-10)), a selector with too many conditions, an inverted time window, a cyclic purpose order, a duplicate catalog, purpose entry or proof id, a wrong number of bases in `commit` or `continue`, a restriction DENY naming another policy or version, an exhausted rolling budget without `resets_at`, `now` outside the intent's validity |
| `fuel` | Fuel budget exhausted |

<a id="L0-EVAL-61"></a>**L0-EVAL-61. A rejection is not an outcome.** A rejection produces no decision and no record, and does not consume the request nonce or any proof. To a party enforcing decisions, a rejection means only that there is no ALLOW.

<a id="L0-EVAL-62"></a><!-- no-vector: outside-operation: how an enforcing party maps a decision to a boolean -->**L0-EVAL-62. Fail closed.** Only an `allow` decision permits an effect. A party that maps a decision onto a boolean MUST map `deny` and `require_action` to `false`.

Vectors for this part: [`core/1/decision.json`](../../conformance/vectors/core/1/decision.json) and the `combinator.evaluate` cases of [`core/1/cve-regressions.json`](../../conformance/vectors/core/1/cve-regressions.json). Each case gives the canonical `evaluation-input` bytes and either the expected canonical `decision` bytes or the expected rejection kind. The fuel budget is given at file level; a case that gives its own `fuel` uses that instead. `allow-fuel-exact`, `reject-fuel-short`, `check-fuel-exact-recharges-restrictions` and `reject-check-fuel-short` sit on both sides of the cost of [L0-EVAL-45](#L0-EVAL-45).
