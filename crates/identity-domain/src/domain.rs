//! Custom domain rules, free of I/O (OP-156 m.3 (i), §10.2.4, §12.1.2, TN-16, TN-17, TN-20):
//! which hosts a realm may register, the two DNS records that verify one, how long a
//! verification and a certificate last, and which RP IDs a realm with passkeys may hold.

pub mod host;
pub mod rp;
pub mod schedule;
pub mod verify;
