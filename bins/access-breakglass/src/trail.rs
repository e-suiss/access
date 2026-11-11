//! The local trail (§17.7.3 principle 6): an append-only file of hash-chained lines,
//! `seq at_ms event fields prev hash`, where `hash = SHA-256(prev ‖ "seq at_ms event fields")`.
//! The tool refuses to run when the chain does not verify.

use std::path::{Path, PathBuf};

use access_crypto::breakglass::{hex, unhex};
use access_crypto::webauthn::sha256;

use crate::Failure;
use crate::cell::append;

fn genesis() -> [u8; 32] {
    sha256(b"access/breakglass/trail/v1")
}

/// A verified trail, ready for the next line.
#[derive(Debug)]
pub(crate) struct Trail {
    path: PathBuf,
    next: u64,
    head: [u8; 32],
}

fn field(text: &str) -> bool {
    !text.is_empty() && !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl Trail {
    /// Opens and verifies `path`; a missing file is an empty trail.
    pub(crate) fn open(path: &Path) -> Result<Self, Failure> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(_) => return Err(Failure::Trail),
        };
        let mut next = 1_u64;
        let mut head = genesis();
        for line in text.lines() {
            let parts: Vec<&str> = line.split(' ').collect();
            let [seq, at, event, fields, prev, hash] = parts.as_slice() else {
                return Err(Failure::Trail);
            };
            if seq.parse::<u64>().ok() != Some(next) || unhex(prev).as_deref() != Some(&head[..]) {
                return Err(Failure::Trail);
            }
            let body = format!("{seq} {at} {event} {fields}");
            let mut input = head.to_vec();
            input.extend(body.as_bytes());
            let want = sha256(&input);
            if unhex(hash).as_deref() != Some(&want[..]) {
                return Err(Failure::Trail);
            }
            head = want;
            next = next.checked_add(1).ok_or(Failure::Trail)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            next,
            head,
        })
    }

    /// Appends one line and returns its sequence number. `fields` is `k=v` pairs joined by `,`.
    pub(crate) fn write(&mut self, at_ms: u64, event: &str, fields: &str) -> Result<u64, Failure> {
        let fields = if fields.is_empty() { "-" } else { fields };
        if !field(event) || !field(fields) {
            return Err(Failure::Trail);
        }
        let seq = self.next;
        let body = format!("{seq} {at_ms} {event} {fields}");
        let mut input = self.head.to_vec();
        input.extend(body.as_bytes());
        let hash = sha256(&input);
        append(
            &self.path,
            &format!("{body} {} {}\n", hex(&self.head), hex(&hash)),
        )
        .map_err(|_| Failure::Trail)?;
        self.head = hash;
        self.next = seq.checked_add(1).ok_or(Failure::Trail)?;
        Ok(seq)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // §17.7.3
    #[test]
    fn op_46_a_broken_chain_is_refused() {
        let dir = std::env::temp_dir().join(format!("bg-trail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trail");
        let _ = std::fs::remove_file(&path);
        let mut t = Trail::open(&path).unwrap();
        assert_eq!(t.write(1, "used", "ops=health").unwrap(), 1);
        assert_eq!(t.write(2, "spent", "generation=1").unwrap(), 2);
        assert!(t.write(3, "bad event", "x").is_err());
        let mut again = Trail::open(&path).unwrap();
        assert_eq!(again.write(3, "rotated", "generation=2").unwrap(), 3);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen("ops=health", "ops=config.read", 1)).unwrap();
        assert!(matches!(Trail::open(&path), Err(Failure::Trail)));
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(matches!(Trail::open(&path), Err(Failure::Trail)));
    }
}
