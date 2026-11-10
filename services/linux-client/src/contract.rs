//! The daemon's socket contract (OP-156 m.3 (p)): the request operations and answer kinds of
//! `conformance/cddl/linux-client.cddl`.

/// Every request operation the NSS and PAM modules send.
pub const OPS: [&str; 8] = [
    "getpwnam",
    "getpwuid",
    "getgrnam",
    "getgrgid",
    "getgrouplist",
    "authenticate",
    "sudo",
    "poll",
];

/// Every answer kind the daemon sends.
pub const KINDS: [&str; 7] = [
    "passwd",
    "group",
    "groups",
    "pending",
    "done",
    "not_found",
    "unavailable",
];

/// Longest frame on the socket, in bytes.
pub const MAX_FRAME: u32 = 65_536;
