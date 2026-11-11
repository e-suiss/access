//! Named fault-injection tests, one per failure-contract row (§16.7, §16.7.1, OP-158 m.3 (t)),
//! against the real router on real PostgreSQL, sequencer and `SoftHSM`. Lane W8 fills them; the
//! rows are `conformance/catalog/failure-ownership.toml`.

mod database;
mod derived;
mod failover;
mod hot_key;
mod hsm;
mod identity_db;
mod identity_signer;
mod signer;
mod time;
mod witness;
