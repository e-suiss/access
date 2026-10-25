# Access algebra model

An executable [Lean 4](https://lean-lang.org) model of the authority algebra in
[`protocol/l0/algebra.md`](../../protocol/l0/algebra.md), with machine-checked proofs of the
properties that rule L0-ALG-5 requires.

The model is written from the L0 text, not from the Kernel source. It covers:

- `⊑` (subsumption), `∩` (intersection, `none` is `⊥`) and `normalize` for the nine bound types
  (`enum`, `eq`, `flag`, `range`, `count_max`, `interval`, `resource`, `subject`, `purpose`), for
  action sets, resource and subject selectors, purpose sets and whole authority sets;
- intent coverage (L0-ALG-13, L0-EVAL-10);
- `child_within_parent` (L0-ALG-70 to L0-ALG-77).

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

The same properties are proved for single bounds (`boundLe_*`, `boundMeet_*`, `boundNorm_*`).
Every function is total, so the three operations terminate by construction.

## Running

```sh
just lean
```

or, inside this directory:

```sh
lake build --wfail AccessAlgebra vectors   # model and proofs
./check-axioms.sh                          # fails if a `proved` theorem depends on sorry
lake exe vectors ../vectors/core/*/*.json  # model against the Kernel algebra vectors
```

The toolchain version is pinned in [`lean-toolchain`](lean-toolchain). With
[elan](https://github.com/leanprover/elan) installed, `lake` picks it up automatically. Without
elan, `scripts/lean-fetch.sh` downloads the pinned release and checks its SHA-256 against
`supply-chain/lean.toml`.

`vectors` decodes the `algebra.child_within_parent` cases (canonical CBOR) and compares the
model's answer with the expected one. It exits non-zero on any disagreement.

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
- **Outside the model.** Budget terms and agency terms (L0-ALG-57, L0-ALG-77) and unknown elements
  in stored artifacts (L0-ALG-4) are not represented.
