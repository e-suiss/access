//! The daemon's adapters: Access over HTTPS, the host's clock, randomness, kept state and
//! socket, and a local security key over `hidraw` on Linux.

#[cfg(target_os = "linux")]
pub mod hidraw;
pub mod https;
pub mod local;
