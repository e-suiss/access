# esuiss-ledger

The engine behind Suiss's append-only logs: a single writer that orders records into a hash-chained Merkle log, decides when its effects may leave, and builds the checkpoints witnesses cosign. It is pure: no I/O, no clock, no randomness and no SQL. Your service feeds it trusted time and the outcome of each storage write, and keeps the tables in its own store.

- **Single writer.** One leader per log under an epoch. A batch gets positions, chain links and a time that never goes back. The head moves only after the store reports a durable write; anything uncertain makes the writer step down and rebuild from storage.
- **Durability fence.** No event that depends on a record leaves before the record is durable.
- **Checkpoints.** C2SP `tlog-checkpoint` bodies built from the head, and a publication order that sends a checkpoint to witnesses only after the replica holds it (mirror before witness).
- **Replica follower.** Rebuilds the tree from mirrored leaves and accepts a checkpoint only if its own copy has the same size and root and the new checkpoint is consistent with the last.
- **Trusted time.** Combines at least two clock sources, refuses jumps and disagreement, and checks the log clock against witness cosignatures.
- **`no_std`.** Builds for `wasm32-unknown-unknown` and `thumbv7em-none-eabihf`.
- **Doorbell (feature `doorbell`).** After a record is durable, a small NATS JetStream message `{domain, pos, idx}` tells consumers to read the outbox past their cursor. It carries no event content and is deduplicated by the event id (`Nats-Msg-Id`). Losing it only delays consumers, which keep polling. The client is TLS 1.3 with a client certificate only; there is no plaintext mode.

## Use

```toml
[dependencies]
esuiss-ledger = "=0.7.1"
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
| `doorbell` (feature) | `Ring`, the fence `Gate`, the `Bell` a writer rings, and `client`: `Publisher`, `Listener`, `publish`, `listen`, `tls`. Feature `testing` adds an in-process NATS twin and a throwaway PKI |

```rust
use suiss_ledger::fence::Fence;
use suiss_ledger::port::commit;
use suiss_ledger::sequencer::Sequencer;

let mut seq = Sequencer::lead(epoch, head_from_storage);
let mut fence = Fence::at(head_from_storage.pos);
let last = commit(&mut seq, &mut fence, &store, trusted_now, &records).await?;
```

With the doorbell, a writer releases a ring only once the fence covers its record:

```rust
use suiss_ledger::doorbell::{Gate, Ring, client};

let (bell, rings) = client::queue(1024);
tokio::spawn(client::publish(config, rings, stop.clone(), |_| {}));
let mut gate = Gate::new(Fence::at(head_from_storage.pos));
gate.fence().advance(durable_pos)?;
gate.release(Ring { domain, at, id: event_id }, &bell);
```

Signing and verifying checkpoints is in [`esuiss-crypto`](https://crates.io/crates/esuiss-crypto) (`note` module).

## Versions

Until 1.0, a breaking change raises the minor version. Pin an exact version. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](../../LICENSE).
