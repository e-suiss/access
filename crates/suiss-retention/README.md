# esuiss-retention

The retention contract every Suiss product shares: the retention classes, how long a class is kept for a tenant, the litigation and regulator holds that stop destruction, and the one decision that lets a key be destroyed. Access owns the policy and the holds; Work, Relay and One cache them and ask this crate before they crypto-shred anything. It is pure: no I/O, no clock and no storage.

- **Classes.** `Class` names every retention class (`profile`, `kyc`, `work_record`, `one_memory`, …). A key is per subject and class.
- **Schedules.** A `Schedule` gives a tenant's class its legal basis, a period or "until an event" (such as the end of the tenant contract), the event the period counts from, an optional cap and the policy version.
- **Holds.** A `Hold` covers a subject, a set of classes or the whole tenant, from when it is placed until it is lifted. While it is active nothing it covers is destroyed, even past the period and the cap. A hold for a suspicious-activity report never prints its scope.
- **One decision.** `may_destroy` answers `Destroy`, `Retain` or `Defer`, each with a reason. It says `Destroy` only when the period has run, no active hold covers the record and the policy snapshot is less than 24 hours old. Anything it cannot tell defers. Months and years follow the UTC calendar and always end on the later reading, so nothing goes early.
- **Suiss One.** `Schedule::one_default` gives the One classes' defaults; `OneData` maps task records, effect evidence, browser snapshots and consent records to their classes, and `export_class` picks an export package's most restrictive source class.
- **User-keyed data.** `user_keyed` checks the KEK recovery paths a person sets up (at least two, none weaker than what they protect), says plainly when no path is left, and plans an erasure of one record, one class or the whole account: every wrapped copy on the server, in the recovery vault and in TEE jobs goes at once, a disconnected device's copy goes when it reconnects, and a hold suspends destruction without making anything readable.
- **`no_std`.** Builds for `wasm32-unknown-unknown` and `thumbv7em-none-eabihf`.

## Use

```toml
[dependencies]
esuiss-retention = { version = "=0.7.1", features = ["serde"] }
```

```rust
use suiss_retention::{Decision, Occurrence, Record, may_destroy};

let record = Record {
    tenant,
    class,
    subject: Some(subject),
    start: Occurrence::At(recorded_at),
    end: Occurrence::NotYet,
};
match may_destroy(&schedule, &record, &holds, Some(snapshot_age), trusted_now) {
    Decision::Destroy => { /* destroy the key */ }
    Decision::Retain(reason) => { /* keep it; ask again later */ }
    Decision::Defer(reason) => { /* refresh the policy snapshot or the record state first */ }
    _ => { /* new answers are not Destroy */ }
}
```

A record that falls under several schedules goes only when every one of them answers `Destroy`. Until a tenant's schedules arrive, `Schedule::work_default` gives the defaults for the Work classes.

| Feature | Contents |
|---|---|
| `serde` | `Serialize` and `Deserialize` for schedules, holds and records; class names on the wire are the names above |

## Versions

Until 1.0, a breaking change raises the minor version. Pin an exact version. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](../../LICENSE).
