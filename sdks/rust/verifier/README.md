# esuiss-access-verifier

The Access offline verifier for Rust. A device, robot or resource server that cannot reach Access accepts or refuses a use of a Portable Authority Proof on its own, within the horizon, staleness and offline budget slice the proof's ValidityContract declares, and reports what it did when it reconnects.

It builds on the open [`esuiss-access-kernel`](https://crates.io/crates/esuiss-access-kernel) and [`esuiss-crypto`](https://crates.io/crates/esuiss-crypto) only.

- **Verifier Profile.** Declare what the verifier can do: connectivity profiles, clock, tamper-evident counter, status sources and local ceilings.
- **Trusted time and counters.** Clock and counter are ports, with an emulator for tests.
- **Offline Exercise Report.** Local uses in a hash chain that shows a hidden or reordered entry.

The crate is early: its modules arrive with the Access releases that serve them.

## License

[Apache License 2.0](../../../LICENSE).
