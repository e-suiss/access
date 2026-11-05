//! Access Offline Verifier SDK (CMP-17, T25): the Kernel plus the device ports an
//! offline verifier needs.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod counter;
#[cfg(feature = "testing")]
pub mod testing;
pub mod time;
