//! Durability on the real server path (§16.6, §16.6.1, OP-158 m.5): real witness and replica
//! processes, two provider installs and replicated PostgreSQL clusters.

mod checkpoint;
mod export;
mod failover;
mod handover;
mod hybrid;
mod recovery;
mod replay;
mod replica;
