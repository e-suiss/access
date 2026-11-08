//! Experience backend (CMP-16, OP-153 m.3 (v)): the Authority hub's render data. It reads
//! Access only through the public endpoints a third party would use, with the reader's own AIS
//! (XI-18, IA-7), and turns the answers into owner-badged, dated rows (XI-1, XI-16). It holds no
//! authority and has no write path: a write goes from the reader's device to Access directly,
//! and this service only renders what Access recorded (XI-3, IA-4).

pub mod adapters;
pub mod app;
pub mod contract;
pub mod domain;
pub mod feed;
pub mod https;
pub mod ports;
