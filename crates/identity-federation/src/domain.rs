//! Social and upstream sign-in, sans I/O (OP-63).

pub mod apple;
pub mod connection;
pub mod key;
pub mod preset;
pub mod rules;
pub mod token;

/// An `https` URL without user info or fragment, at most 2048 bytes.
#[must_use]
pub fn https(u: &str) -> bool {
    u.len() <= 2048
        && u.strip_prefix("https://").is_some_and(|rest| {
            let host = rest.split(['/', '?']).next().unwrap_or("");
            !host.is_empty() && !host.contains('@') && !rest.contains('#')
        })
}
