//! Database primary failover: no acknowledged write is lost, the leader steps down and a new epoch
//! commits (§16.7, FA-1). The promote runs on `scripts/pg-ha.sh` (FO-02, FO-15, FO-16 in
//! `conformance/catalog/failure-ownership.toml`).
