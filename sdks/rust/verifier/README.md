# esuiss-access-verifier

The Access offline verifier for Rust. A device, robot or resource server that cannot reach Access accepts or refuses a use of a Portable Authority Proof on its own, within the horizon, staleness and offline budget slice the proof's ValidityContract declares, and reports what it did when it reconnects.

It builds on the open [`esuiss-access-kernel`](https://crates.io/crates/esuiss-access-kernel) and [`esuiss-crypto`](https://crates.io/crates/esuiss-crypto) only, is `no_std` with `alloc`, and never reads a network, a file or the system clock.

- **Seven steps, in the Kernel.** Key and signature against Domain Metadata and the embedded key excerpt, DomainID, validity, holder proof, bounds and local requirements, slice, freshness and must-understand items, with the optional content-position check.
- **Ceilings the artefact cannot raise.** The horizon a use is accepted for is the smallest of the class table, the Verifier Profile's `cap_horizon` and the Domain Metadata ceilings, by connectivity variant and consequence tier.
- **Verifier Profile.** Declare what the verifier can do; contracts issued against another profile, or that it does not cover, are refused.
- **Trusted time and counters.** Clock and tamper-evident counter are ports with a guard that refuses a clock that jumps, freezes or goes back (measured from its anchor, within a fixed term plus a drift proportional to the elapsed monotonic time) and a counter that is rolled back or wiped. A refusing clock guard, or one after a reboot, is re-anchored only on a time taken from an artefact verified online. A shared counter bounds a verifier group. An emulator ships behind the `testing` feature.
- **Status lists and witnessed metadata.** Token Status Lists are verified under the domain's `status-list` key and inflated within a size limit; Domain Metadata is fresh only while an independent witness has cosigned the domain's checkpoint recently enough.
- **Offline Exercise Report.** Every use of a projection is chained as it happens; a report cut on reconnect carries the unused slice and continues the chain of the last one.

```rust,ignore
use access_verifier::offline::{OfflineVerifier, Use, Verdict};

let mut verifier = OfflineVerifier::new(identity, metadata, clock, guard);
verifier.provision(exercise, budget_term, amount, counter)?;
match verifier.verify(&Use { pap, excerpt, presentation, intent, nonce, satisfied, schema, content_position }) {
    Verdict::Allow(allowed) => apply(allowed),
    Verdict::Deny(denial) => refuse(denial.code()),
}
let report = verifier.report(&exercise)?;
```

## License

[Apache License 2.0](../../../LICENSE).
