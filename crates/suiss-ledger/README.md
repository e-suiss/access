# esuiss-ledger

The engine behind Suiss's append-only logs: a single writer that orders records into a hash-chained Merkle log, decides when its effects may leave, and builds the checkpoints witnesses cosign. It is pure: no I/O, no clock, no randomness and no SQL. Your service feeds it trusted time and the outcome of each storage write, and keeps the tables in its own store.

- **Single writer.** One leader per log under an epoch. A batch gets positions, chain links and a time that never goes back. The head moves only after the store reports a durable write; anything uncertain makes the writer step down and rebuild from storage.
- **Durability fence.** No event that depends on a record leaves before the record is durable.
- **Checkpoints.** C2SP `tlog-checkpoint` bodies built from the head, and a publication order that sends a checkpoint to witnesses only after the replica holds it (mirror before witness).
- **Replica follower.** Rebuilds the tree from mirrored leaves and accepts a checkpoint only if its own copy has the same size and root and the new checkpoint is consistent with the last.
- **Trusted time.** Combines at least two clock sources, refuses jumps and disagreement, and checks the log clock against witness cosignatures.
- **`no_std`.** Builds for `wasm32-unknown-unknown` and `thumbv7em-none-eabihf`.

## Use

```toml
[dependencies]
esuiss-ledger = "=0.2.2"
```

| Module | Contents |
|---|---|
| `sequencer` | `Sequencer`, `Params` (batch limit, can only be lowered), the `Entry` trait your record type implements |
| `port` | `LogStore`, the trait your store implements, and `commit`, one plan–append–advance cycle |
| `fence` | `Fence` and the outbox `Cursor` |
| `merkle` | The RFC 9162 frontier of the log |
| `checkpoint` | `of_head` and the `Publication` order |
| `replica` | `Follower` |
| `time` | `TrustedClock` and `check_against_witness` |

```rust
use suiss_ledger::fence::Fence;
use suiss_ledger::port::commit;
use suiss_ledger::sequencer::Sequencer;

let mut seq = Sequencer::lead(epoch, head_from_storage);
let mut fence = Fence::at(head_from_storage.pos);
let last = commit(&mut seq, &mut fence, &store, trusted_now, &records).await?;
```

Signing and verifying checkpoints is in [`esuiss-crypto`](https://crates.io/crates/esuiss-crypto) (`note` module).

## Versions

Until 1.0, a breaking change raises the minor version. Pin an exact version. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](../../LICENSE).
