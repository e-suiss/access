# Access algebra model

An executable [Lean 4](https://lean-lang.org) model of the authority algebra in
[`protocol/l0/algebra.md`](../../protocol/l0/algebra.md) and of the Decision Combinator, with
machine-checked proofs of the properties that rule L0-ALG-5 and CR-48 ask for.

The model is written from the L0 text, not from the Kernel source. It covers:

- `⊑` (subsumption), `∩` (intersection, `none` is `⊥`) and `normalize` for the nine bound types
  (`enum`, `eq`, `flag`, `range`, `count_max`, `interval`, `resource`, `subject`, `purpose`), for
  action sets, resource and subject selectors, purpose sets and whole authority sets;
- intent coverage (L0-ALG-13, L0-EVAL-10);
- `child_within_parent` (L0-ALG-70 to L0-ALG-77);
- projections and the validity of a lineage over time (`Grant.lean`);
- the Decision Combinator of [`protocol/l0/evaluation.md`](../../protocol/l0/evaluation.md) over
  prepared facts (`Combinator.lean`);
- holding episodes (`Holding.lean`) and the holding terms of meta-actions (`Meta.lean`).

It uses only the Lean core library. There are no other dependencies.

## Proofs

[`proofs.toml`](proofs.toml) lists every theorem with its rule and a status:

- `proved`: the proof is complete and uses only `propext`, `Classical.choice` and `Quot.sound`;
- `stated`: the statement is written and the proof is still open.

The main results:

| Theorem | Property |
|---|---|
| `authLe_refl`, `authLe_trans` | `⊑` is reflexive and transitive |
| `authLe_sound` | if `c ⊑ p`, every intent `c` covers is covered by `p` |
| `authMeet_le`, `authMeet_greatest` | `a ∩ b` is the greatest lower bound of `a` and `b`, up to coverage |
| `authMeet_normal` | `a ∩ b` of normalized values is normalized |
| `authNorm_idem`, `authNorm_covers` | `normalize` is idempotent and covers exactly what its input covers |
| `delegation_never_widens`, `chain_never_widens` | a delegated Grant never covers more than its parent, along a whole chain |
| `decSubsumes`, `decMeetIs`, `decNormalizesTo` | `⊑`, `∩` and `normalize` are total functions, so their relations are decidable |
| `projection_within_source` | a projection is `⊑` its source and covers nothing the source does not |
| `cascade_monotone` | an ended link ends its lineage, an ended lineage never comes back, and narrowing a link narrows what the lineage permits |
| `Combinator.forbid_trumps_permit` | a denying restriction makes the decision DENY |
| `Combinator.default_deny` | a rejection, no basis, or a hop that is not understood or does not cover on every basis gives no ALLOW |
| `Combinator.allowed_only_if_explicitly_permitted` | ALLOW needs a covering, live basis, its capacity, the mandate, no denying restriction and a proof for every term |
| `Combinator.order_and_dup_independent` | the decision does not depend on the order of proofs or the order and repetition of restriction results |
| `Combinator.sound_slicing` | dropping `no_objection` results and proofs that match no term keeps the decision |
| `Holding.lazy_eq_eager` | the lazy `since`, the last false→true transition, equals the replayed episode |
| `Holding.close_is_terminal`, `Holding.cutoff_lift_never_revives` | a closed episode never comes back, also when a cutoff is lifted |
| `Meta.meta_holding_sound` | a meta-Exercise on a holding basis is allowed only when every link of the holding holds and the pin matches |

The same properties are proved for single bounds (`boundLe_*`, `boundMeet_*`, `boundNorm_*`).
Every function is total, so the three operations terminate by construction.

## Running

```sh
just lean
```

or, inside this directory:

```sh
lake build --wfail AccessAlgebra vectors drt  # model, proofs and runners
./check-axioms.sh                             # fails if a `proved` theorem depends on sorry
lake exe vectors ../vectors/core/*/*.json     # model against the Kernel algebra vectors
```

The toolchain version is pinned in [`lean-toolchain`](lean-toolchain). With
[elan](https://github.com/leanprover/elan) installed, `lake` picks it up automatically. Without
elan, `scripts/lean-fetch.sh` downloads the pinned release and checks its SHA-256 against
`supply-chain/lean.toml`.

`vectors` decodes the `algebra.child_within_parent` cases (canonical CBOR) and compares the
model's answer with the expected one. It exits non-zero on any disagreement.

## Differential testing against the Kernel

The model is executable, so the Rust Kernel is tested against it on random inputs:

```sh
just f0-random 100000 1   # random cases with the Kernel's answers, also run through F0
just lean-drt             # the model on the same cases
```

`just f0-random` writes `target/random-vectors/lean/algebra.cbor`: a CBOR sequence whose first
item holds the catalog (pinned action catalogs, reserved actions, purpose order) and whose other
items are cases of `⊑`, `∩`, `normalize` and `child_within_parent`, each with the Kernel's answer.
`lake exe drt` evaluates the model on every case and counts the disagreements. Sets are compared
as sets, since the model and the Kernel order them differently. Before the real run, `just
lean-drt` feeds the runner a control file with inverted answers and fails if the runner does not
notice.

The nightly workflow runs 10⁷ cases across its shards, and a semantic release needs a summary
with at least 10⁷ cases and no disagreement. This is a differential test: it shows the Kernel and
the model agree on the inputs tried, not on every input.

## Modelling choices

- **Well-formed input.** The decoder rejects inputs that are not values of the data model: empty
  sets where the schema requires one element, inverted time windows, maps with repeated keys.
  Theorems that need this state it as a hypothesis (`AuthWF`, `MeetWF`, `BoundWF`,
  `ParamsSorted`) instead of building it into the types. A prefix whose catalog is not in the
  input covers nothing, on either side of `⊑` (L0-ALG-32).
- **Bottom.** A value that covers nothing is equivalent to `⊥`. `normalize` writes `⊥` only for
  an action set with neither `exact` nor `prefix`, so `authMeet_greatest` states the greatest lower
  bound up to coverage: every lower bound either covers nothing or is below `a ∩ b`.
- **`public`.** A `public` recipient or `subject` bound is no restriction: it covers intents with
  and without a value (L0-EVAL-10). `normalize` does not write it.
- **Canonical order.** Sets and maps are kept sorted and without repeats. The model sorts by a
  structural order on values, not by the bytes of their canonical encoding. Both give one
  representation per set; which order is used does not change any result.
- **Purpose order.** The catalog's "below" relation is taken as a function together with the
  laws L0-ALG-47 requires (`Catalog.Lawful`: a partial order, and only declared purposes sit
  strictly below another). The vector runner uses the empty catalog, where "below" is equality.
- **Opaque values.** Identifiers, digests and requirement terms are compared by equality only.
- **Prepared facts.** The Decision Combinator, holding and meta-action models take the facts that
  L0-EVAL-4 says the preparer computes (coverage, status, conditions, budgets, restriction results,
  which proof fits which term) as input, as the Kernel does. Each requirement term needs one proof;
  `count`, independence and the term's position in the decision are not represented. The fuel rule
  is modelled as a cost over every candidate, an upper bound of L0-EVAL-45.
- **Outside the model.** Budget terms and agency terms (L0-ALG-57, L0-ALG-77) and unknown elements
  in stored artifacts (L0-ALG-4) are not represented. A theorem holds for its model; how closely
  the Kernel follows a model is shown by the vectors and the differential test, not proved.
