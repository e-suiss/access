# Changelog

## 0.2.3

No changes; released with `esuiss-crypto`.

## 0.2.2

No changes; released with `esuiss-sandbox`.

## 0.2.1

### Added

- `port`: the `LogStore` storage port and `commit`, one plan–append–advance cycle with the step-down and abandon rules.
- `fence`: the durability fence and the outbox cursor.
- `checkpoint`: `of_head` builds a C2SP `tlog-checkpoint` from the head; `Publication` enforces mirror before witness.
- `replica`: `Follower` checks mirrored leaves against checkpoints and their consistency.
- `time::check_against_witness`.
- `sequencer::Params`: the batch limit, which can only be lowered; `Sequencer::lead_with`.

### Changed

- `PlanError` and `TimeError` are `#[non_exhaustive]`.
- `Sequencer::lead` is no longer `const`.

## 0.1.1

First release: Merkle frontier, sequencer and trusted time.
