# esuiss-access-sdk

The Access SDK for Rust: the enforcement side of an Access decision. A service asks Access before an effect and applies the answer before the effect. Anything other than a verified ALLOW for this intent, this audience and this actor is a DENY; there is no fail-open setting.

It builds on the open [`esuiss-access-kernel`](https://crates.io/crates/esuiss-access-kernel) and [`esuiss-crypto`](https://crates.io/crates/esuiss-crypto) only.

- **`authorize`.** Ask for one intent, check the signed receipt of an ALLOW against the intent and your own identity, and hand the effect a value that only exists after that check.

The crate is early: its modules arrive with the Access releases that serve them.

## License

[Apache License 2.0](../../../LICENSE).
