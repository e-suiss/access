# L0 Authority Algebra

This part defines the values that describe authority, the closed set of bound types, and three operations on them:

- `c ⊑ p` (subsumption): every concrete use that `c` allows, `p` also allows;
- `a ∩ b` (intersection): the largest value that is below both `a` and `b`;
- `normalize(v)`: the single canonical form of `v`.

It ends with the check that a delegated Grant stays within the Grant it was delegated from.

All comparisons are syntactic. No rule here calls out to a policy engine, a database or the network, and every operation terminates.

## 1. General rules

<a id="L0-ALG-1"></a>**L0-ALG-1. Bottom.** `⊥` is the value that covers nothing. `⊥ ⊑ x` holds for every `x`. `x ∩ ⊥ = ⊥`.

<a id="L0-ALG-2"></a>**L0-ALG-2. Missing means every value.** A dimension or parameter that an authority value does not write is unbounded: it allows every value. A parameter the action schema defines but the authority does not mention is unbounded.

<a id="L0-ALG-3"></a>**L0-ALG-3. Different types do not compare.** If two bounds have different types, `⊑` is false and `∩` is `⊥`. The same holds for two selectors of different kinds, except where a rule below says otherwise (`public`, [L0-ALG-45](#L0-ALG-45)).

<a id="L0-ALG-4"></a>**L0-ALG-4. Must-understand.** An element of an unknown type or kind:

- in new input, is rejected when the input is decoded ([L0-ENC-9](encoding.md#L0-ENC-9));
- in a stored or external artifact, is read as unknown, and an unknown element is never covered: a bound, selector or condition the reader does not understand makes the value that contains it cover nothing.

> **OPEN (O-13):** How is a stored authority that contains an unknown element represented in an evaluation input? The current data model has no form for it.

<a id="L0-ALG-5"></a>**L0-ALG-5. Required properties.** For every type in this part an implementation MUST satisfy:

- `⊑` is sound: if `c ⊑ p`, then every concrete value allowed by `c` is allowed by `p`;
- `⊑` is reflexive and transitive;
- `a ∩ b` is the greatest lower bound of `a` and `b` under `⊑`;
- `normalize` is idempotent, and `normalize(v)` allows exactly what `v` allows;
- all three operations terminate.

<a id="L0-ALG-6"></a>**L0-ALG-6. Empty is a value.** An empty intersection is a valid result. It covers nothing. Issuing a Grant whose authority is empty is denied.

<a id="L0-ALG-7"></a>**L0-ALG-7. No negation.** Positive authority has no negation and no disjunction other than set membership. Exclusions are expressed only as restriction policies, which can deny or require but never allow.

## 2. The nine bound types

A parameter bound (`param-bound`) is a map with exactly one key, which names its type. A parameter value in an intent (`param-value`) is also a one-key map whose key names the matching value type.

<a id="L0-ALG-10"></a>**L0-ALG-10. Bound types.** The bound types form a closed set:

| Bound | Matching value | `c ⊑ p` | `a ∩ b` | `normalize` |
|---|---|---|---|---|
| `enum: [text…]` | `enum: text` | `c` is a subset of `p` | common elements; `⊥` if none | sorted, unique |
| `eq: v` | `eq: v` | `c = p` | `a` if `a = b`, else `⊥` | itself |
| `flag: bool` | `flag: bool` | `c = p` | `a` if `a = b`, else `⊥` | itself |
| `range: {min?, max?, unit}` | `amount: {value, unit}` | units equal ∧ `p.min ≤ c.min` ∧ `c.max ≤ p.max` | units equal: `[max(min), min(max)]`; `⊥` if units differ or result empty | `⊥` if `min > max` |
| `count_max: n` | `count: n` | `c ≤ p` | the smaller | itself |
| `interval: [from, until]` | `interval: [from, until]` | `p.from ≤ c.from` ∧ `c.until ≤ p.until` | overlap; `⊥` if none | itself |
| `resource: selector` | `resource: resource-ref` | [L0-ALG-41](#L0-ALG-41) | [L0-ALG-42](#L0-ALG-42) | itself |
| `subject: selector` | `subject: party-ref` | [L0-ALG-45](#L0-ALG-45) | [L0-ALG-46](#L0-ALG-46) | `pred` conjuncts sorted, unique |
| `purpose: [purpose-ref…]` | `purpose: purpose-ref` | [L0-ALG-48](#L0-ALG-48) | [L0-ALG-48](#L0-ALG-48) | maximal elements |

Equality of two values is equality of their canonical encodings.

<a id="L0-ALG-11"></a>**L0-ALG-11. Intervals.** Time intervals are closed: both ends belong to the interval. Times are in milliseconds. Every `time-window` MUST have `from ≤ until`. This holds for `interval` bounds and values, constraint `validity`, intent `validity`, and every other time window. An inverted window is an `input` rejection.

Vector: [`core/1/decision.json`](../../conformance/vectors/core/1/decision.json), `combinator.evaluate`: `reject-inverted-hop-window`.

<a id="L0-ALG-12"></a>**L0-ALG-12. Ranges.** A range is closed and integer. Either end may be missing; a missing `min` is unbounded below and a missing `max` is unbounded above. So if `p` has a `min` and `c` does not, `c ⊑ p` is false; the same holds for `max`. A range value `v` is within a range bound when the units are equal and `min ≤ v.value ≤ max` for each end that is present.

<a id="L0-ALG-13"></a>**L0-ALG-13. Value within a bound.** An intent value is within a bound when the value type matches the bound type ([L0-ALG-10](#L0-ALG-10)) and:

- `enum`: the value is an element of the bound;
- `eq`, `flag`: the value equals the bound;
- `range`: [L0-ALG-12](#L0-ALG-12);
- `count_max`: the value is at most the bound;
- `interval`: the value interval lies inside the bound interval;
- `resource`: the resource reference is within the selector ([L0-ALG-41](#L0-ALG-41), with the reference read as an `exact` selector);
- `subject`: the party is within the selector ([L0-ALG-45](#L0-ALG-45), with the party read as a `party` selector);
- `purpose`: the purpose is below some element of the bound ([L0-ALG-47](#L0-ALG-47)).

If the value type does not match the bound type, the value is not within the bound.

## 3. Actions

<a id="L0-ALG-30"></a>**L0-ALG-30. Action identity.** An action is identified by `namespace`, `name` and `major`. Its `schema` digest is checked for consistency: two action references with the same identity and different schema digests do not match, and authority that names one does not cover the other. The blocker this produces is given in [L0-EVAL-11](evaluation.md#L0-EVAL-11).

<a id="L0-ALG-31"></a>**L0-ALG-31. Prefixes are pinned.** An action prefix `{namespace, catalog}` covers exactly the actions in the catalog identified by `catalog` whose namespace equals the prefix namespace or begins with the prefix namespace followed by `.`. Actions added in a later catalog version are not covered. A prefix never covers a reserved action.

Vectors: [`core/1/cve-regressions.json`](../../conformance/vectors/core/1/cve-regressions.json), `combinator.evaluate`: `prefix-current-catalog`, `prefix-old-catalog`.

<a id="L0-ALG-32"></a>**L0-ALG-32. Unknown catalog.** If a prefix names a catalog digest that is not present in the input catalog, then: on the covering side (the parent, or the authority checked against an intent) the prefix covers nothing; on the covered side (the child) the subsumption check fails. In `∩`, a prefix with an unknown catalog covers nothing on either side.

<a id="L0-ALG-33"></a>**L0-ALG-33. Action sets.** The actions an action set covers are its `exact` actions together with the actions each `prefix` resolves to under [L0-ALG-31](#L0-ALG-31). Reserved actions are covered only by `exact`. For action sets `c` and `p`, `c ⊑ p` holds when every action covered by `c` (its own prefixes resolved in their own pinned catalogs) is covered by `p`. `c ∩ p` covers exactly the actions covered by both. It is written as the resolved exact actions in `exact`, with no `prefix`.

<a id="L0-ALG-34"></a>**L0-ALG-34. Reserved actions.** The reserved set is the union of the actions the schemas mark as reserved and the actions the domain marks as reserved. Both are given to the evaluator as input (`catalog.reserved`).

## 4. Resources

<a id="L0-ALG-40"></a>**L0-ALG-40. Resource selectors.** A resource selector is either `exact` (one `resource-ref`) or structural: a `namespace`, an optional path `prefix`, an optional `type`, and optional `where` equality conditions. A resource reference includes its `incarnation`, so a resource that is deleted and recreated under the same path is a different resource. Resource identifiers are never reused, so a path prefix covers every resource whose path begins with it.

<a id="L0-ALG-41"></a>**L0-ALG-41. Resource `⊑`.** For child `c` and parent `p`:

| `c` | `p` | `c ⊑ p` holds when |
|---|---|---|
| exact | exact | the two references are equal |
| exact | structural | namespaces equal ∧ `p.prefix` is a leading part of `c.path` (whole segments) ∧ `p` has no `type` ∧ `p` has no `where` |
| structural | structural | namespaces equal ∧ `p.prefix` is a leading part of `c.prefix` ∧ (`p` has no `type` ∨ types equal) ∧ every `where` entry of `p` is in `c` with an equal value |
| structural | exact | never |

A missing prefix is the empty path. Namespaces compare by equality, not by hierarchy.

<a id="L0-ALG-42"></a>**L0-ALG-42. Resource `∩`.**

- exact ∩ exact: the reference if equal, else `⊥`;
- exact ∩ structural: the exact selector if it is within the structural one, else `⊥`;
- structural ∩ structural: `⊥` if namespaces differ, if neither prefix is a leading part of the other, if both have a `type` and the types differ, or if both have a `where` entry with the same key and different values; otherwise the selector with the longer prefix, the `type` that is present, and the union of the `where` entries.

## 5. Subjects

<a id="L0-ALG-45"></a>**L0-ALG-45. Subject `⊑`.** For child `c` and parent `p`:

- every selector is within `public`; `public` is within nothing but `public`;
- `party(x) ⊑ party(y)` when `x = y`;
- `pred(C) ⊑ pred(P)` when every conjunct of `P` is also a conjunct of `C`;
- `foreign(d, a) ⊑ foreign(d', a')` when both are equal;
- there is no subsumption between different kinds: a `party` is not within a `pred` or a `foreign` selector.

A `pred` is a conjunction of conditions. Each condition names a claim class and, optionally, an equality value.

Vectors: `cve-regressions.json`, `combinator.evaluate`: `recipient-party-same`, `recipient-party-other`, `recipient-pred-not-party`, `recipient-foreign-not-party`.

<a id="L0-ALG-46"></a>**L0-ALG-46. Subject `∩`.** If `a ⊑ b` the result is `a`; if `b ⊑ a` it is `b`. Two `pred` selectors intersect to the `pred` holding the union of their conjuncts. Every other pair intersects to `⊥`.

## 6. Purposes

<a id="L0-ALG-47"></a>**L0-ALG-47. Purpose order.** A purpose is a code, a work reference or an aim reference, compared by equality. A purpose is below another only if the schema declares it: the input catalog lists, for a purpose, the purposes directly below it. "Below" is the reflexive and transitive closure of these declarations. A declaration that forms a cycle is rejected. Free text is never a purpose.

<a id="L0-ALG-48"></a>**L0-ALG-48. Purpose sets.** A purpose set is normalized to its maximal elements under "below". For sets `c` and `p`, `c ⊑ p` holds when every element of `c` is below some element of `p`. `c ∩ p` is the set of maximal elements among the purposes below some element of `c` and below some element of `p`; `⊥` if there is none.

## 7. Authority sets

An `authority-set` has five dimensions: `actions`, `resource`, `params`, `recipient` and `purpose`.

<a id="L0-ALG-50"></a>**L0-ALG-50. Authority `⊑`.** `c ⊑ p` holds when all of these hold:

- `c.actions ⊑ p.actions` ([L0-ALG-33](#L0-ALG-33));
- `c.resource ⊑ p.resource` ([L0-ALG-41](#L0-ALG-41));
- for every parameter `p` bounds, `c` bounds the same parameter and `c`'s bound `⊑` `p`'s bound;
- if `p` has a `recipient`, `c` has one and it is `⊑` `p`'s;
- if `p` has a `purpose`, `c` has one and it is `⊑` `p`'s.

<a id="L0-ALG-51"></a>**L0-ALG-51. Authority `∩`.** The intersection is taken dimension by dimension. A parameter, recipient or purpose bounded on one side only keeps that side's bound. If any dimension intersects to `⊥`, or no action is covered by both sides, the whole result is `⊥`. The result is normalized.

<a id="L0-ALG-52"></a>**L0-ALG-52. Authority `normalize`.** Sets are sorted and unique; each bound is normalized; a `⊥` in any dimension makes the whole value `⊥`; unbounded dimensions are not written.

## 8. Constraints, delegation and requirements

<a id="L0-ALG-55"></a>**L0-ALG-55. Constraint set.** A `constraint-set` has one closed validity window, an optional set of while-conditions and an optional set of budget terms.

<a id="L0-ALG-56"></a>**L0-ALG-56. While-conditions.** The kinds form a closed list: `instance_alive` (an Instance is still alive) and `claim_held` (a subject still holds a claim of a class under an acceptance). In normal form the set is sorted and unique.

<a id="L0-ALG-57"></a>**L0-ALG-57. Budget terms.** A budget term counts either uses (`count`) or an amount in a unit. Its window is `total` or a rolling window of a number of seconds. There are no calendar windows. The unit comes from the action schema. Budget terms are not part of `⊑`: every use draws from every budget along the lineage, so a child cannot amplify a parent's budget.

<a id="L0-ALG-58"></a>**L0-ALG-58. Delegation terms.** `delegation-terms` has an optional `depth` and an optional `downstream_holder_class`. A missing `depth` is 0, which means the Grant cannot be delegated further. There is no separate delegable flag.

<a id="L0-ALG-59"></a>**L0-ALG-59. Requirement terms.** A `requirement-term` names a `proof_kind` (`claim`, `contribution`, `authentication`, `foreign_authority`) and a `class`, and optionally:

| Field | Values | Default |
|---|---|---|
| `count` | integer ≥ 2 | 1 |
| `binding` | `actor_instance`, `intent_digest`, `resource` | none |
| `freshness_ms` | milliseconds | no limit |
| `independence` | distinct `party`, `instance` or `issuer` | none |
| `consumption` | `single_use` | reusable |
| `source` | subject selector of accepted issuers | any issuer |
| `assurance` | map from dimension to minimum level | no floor |

<a id="L0-ALG-60"></a>**L0-ALG-60. Assurance.** Each assurance dimension is a closed, ordered list of levels, written as integers; a higher integer is a stronger level.

> **OPEN (O-14):** Which assurance dimensions exist, and what is the ordered list of each? This version names only `human_presence`.

<a id="L0-ALG-61"></a>**L0-ALG-61. Requirement sets.** A requirement set `c` is at least as strict as `p` when every term of `p` appears in `c` with an identical encoding. There is no semantic ordering of terms.

## 9. Child within parent

`child_within_parent(child, parent, holder)` decides whether a Grant with `canonical-authority` `child`, held by `holder`, may be delegated from a Grant with `canonical-authority` `parent`. It returns true or false.

<a id="L0-ALG-70"></a>**L0-ALG-70. Definition.** `child_within_parent` is true exactly when [L0-ALG-71](#L0-ALG-71) to [L0-ALG-76](#L0-ALG-76) all hold.

<a id="L0-ALG-71"></a>**L0-ALG-71. Authority.** `child.authority ⊑ parent.authority`.

Vector: `cve-regressions.json`, `algebra.child_within_parent`: `delegate-above-own-authority`.

<a id="L0-ALG-72"></a>**L0-ALG-72. Validity and while.** The child's validity window lies inside the parent's. The child's while-conditions include every while-condition of the parent; the child may add more.

Vectors: `delegate-keeps-condition`, `delegate-drops-condition`.

<a id="L0-ALG-73"></a>**L0-ALG-73. Depth.** `parent.depth > 0` and `child.depth < parent.depth`.

Vector: `delegate-to-party`.

<a id="L0-ALG-74"></a>**L0-ALG-74. Holder class.** If the parent has a `downstream_holder_class`:

- the holder is within it ([L0-ALG-45](#L0-ALG-45)); a concrete holder is a `party` selector, and a selector holder uses selector subsumption;
- the child has a `downstream_holder_class` and it is within the parent's. This holds even when the child's depth is 0.

<a id="L0-ALG-75"></a>**L0-ALG-75. Public.** `public` appears only as a recipient or as the holder of a Grant that cannot be delegated further:

- if the parent's `downstream_holder_class` is `public`, the check fails;
- if the child's depth is greater than 0 and either the holder or the child's `downstream_holder_class` is `public`, the check fails.

Vectors: `delegate-to-public-leaf` (true), `delegate-onward-to-public` (false), `delegate-public-holder-class` (false).

<a id="L0-ALG-76"></a>**L0-ALG-76. Requirements.** The child's requirement set is at least as strict as the parent's ([L0-ALG-61](#L0-ALG-61)).

<a id="L0-ALG-77"></a>**L0-ALG-77. Outside the check.** Budget terms are not compared ([L0-ALG-57](#L0-ALG-57)). Agency terms (which capacities a holder may act in) are not part of the algebra; they are checked separately when a Grant is issued.

Vectors for this section: [`core/1/cve-regressions.json`](../../conformance/vectors/core/1/cve-regressions.json), operation `algebra.child_within_parent`. Each case gives `child` and `parent` as canonical `canonical-authority` bytes, `holder` as a canonical `subject-selector`, and the expected boolean `within`. The catalog is empty.
