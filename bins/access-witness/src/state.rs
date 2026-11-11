//! The witness's own state, one append-only file per log (OP-158 m.3 (d), OP-73): every line
//! is `<chain hash> <entry>`, the chain hash being SHA-256 over the previous one and the entry,
//! so a changed or dropped line breaks the chain and the witness refuses to start. A line is
//! on disk (fsync) before the cosignature it records leaves the process.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use suiss_crypto::note::{Checkpoint, base64_decode, base64_encode, parse_note};
use suiss_ledger::checkpoint::witness::LogState;

const CONTEXT: &str = "access-witness/state/v1 ";

/// One entry of a log's chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    /// A checkpoint was cosigned; `note` holds the log's signature and this witness's.
    Cosigned {
        /// Tree size.
        size: u64,
        /// Root.
        root: [u8; 32],
        /// Cosignature time, seconds.
        time: u64,
        /// The cosigned note.
        note: String,
    },
    /// The current binding is fenced above `size` (U11).
    Fence {
        /// Largest size it may still sign.
        size: u64,
    },
    /// A checkpoint that contradicts the base, kept as evidence (U9, HL-7).
    Equivocation {
        /// The refused note as received.
        note: String,
    },
}

impl Entry {
    fn text(&self) -> String {
        match self {
            Self::Cosigned {
                size,
                root,
                time,
                note,
            } => format!(
                "cosigned {size} {} {time} {}",
                base64_encode(root),
                b64url_encode(note.as_bytes())
            ),
            Self::Fence { size } => format!("fence {size}"),
            Self::Equivocation { note } => {
                format!("equivocation {}", b64url_encode(note.as_bytes()))
            }
        }
    }

    fn parse(text: &str) -> Option<Self> {
        let mut w = text.split(' ');
        let entry = match w.next()? {
            "cosigned" => Self::Cosigned {
                size: w.next()?.parse().ok()?,
                root: base64_decode(w.next()?).ok()?.try_into().ok()?,
                time: w.next()?.parse().ok()?,
                note: String::from_utf8(b64url_decode(w.next()?).ok()?).ok()?,
            },
            "fence" => Self::Fence {
                size: w.next()?.parse().ok()?,
            },
            "equivocation" => Self::Equivocation {
                note: String::from_utf8(b64url_decode(w.next()?).ok()?).ok()?,
            },
            _ => return None,
        };
        w.next().is_none().then_some(entry)
    }
}

fn link(previous: &[u8; 32], entry: &str) -> [u8; 32] {
    let mut data = Vec::with_capacity(previous.len().saturating_add(entry.len()));
    data.extend_from_slice(previous);
    data.extend_from_slice(entry.as_bytes());
    suiss_crypto::digest::sha256(&data)
}

/// One log's chain: its file, the head hash and what it says.
pub(crate) struct Chain {
    file: File,
    head: [u8; 32],
    /// The witness's view.
    pub(crate) log: LogState,
    /// The last cosigned note.
    pub(crate) latest: Option<String>,
    /// Equivocation evidence entries.
    pub(crate) evidence: usize,
}

/// The chain file of `domain` in `dir`.
pub(crate) fn path(dir: &Path, domain: &Digest) -> PathBuf {
    dir.join(format!("{}.chain", b64url_encode(&domain.0)))
}

impl Chain {
    /// Opens or creates the chain of `domain` and checks every line.
    pub(crate) fn open(dir: &Path, domain: &Digest) -> Result<Self, String> {
        let p = path(dir, domain);
        let text = match std::fs::read_to_string(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("{}: {e}", p.display())),
        };
        let mut head = suiss_crypto::digest::sha256(
            format!("{CONTEXT}{}", b64url_encode(&domain.0)).as_bytes(),
        );
        let (mut base, mut fence, mut latest, mut evidence) = (None, None, None, 0_usize);
        for (n, line) in text.lines().enumerate() {
            let broken = || {
                format!(
                    "{}: chain broken at line {}",
                    p.display(),
                    n.saturating_add(1)
                )
            };
            let (hash, entry_text) = line.split_once(' ').ok_or_else(broken)?;
            let next = link(&head, entry_text);
            if base64_decode(hash).ok().as_deref() != Some(next.as_slice()) {
                return Err(broken());
            }
            head = next;
            match Entry::parse(entry_text).ok_or_else(broken)? {
                Entry::Cosigned {
                    size, root, note, ..
                } => {
                    base = Some((size, root));
                    latest = Some(note);
                }
                Entry::Fence { size } => fence = Some(size),
                Entry::Equivocation { .. } => evidence = evidence.saturating_add(1),
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(Self {
            file,
            head,
            log: LogState::resume(base, fence),
            latest,
            evidence,
        })
    }

    /// Appends `entry` and syncs it to disk before returning.
    pub(crate) fn append(&mut self, entry: &Entry) -> Result<(), String> {
        let text = entry.text();
        let next = link(&self.head, &text);
        let line = format!("{} {text}\n", base64_encode(&next));
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_all())
            .map_err(|e| format!("state: {e}"))?;
        self.head = next;
        match entry {
            Entry::Cosigned {
                size, root, note, ..
            } => {
                let cp =
                    Checkpoint::parse(&parse_note(note).map_err(|e| format!("state: {e}"))?.body)
                        .map_err(|e| format!("state: {e}"))?;
                if (cp.size, cp.root) != (*size, *root) {
                    return Err("state: entry does not match its note".into());
                }
                self.log.cosigned(&cp).map_err(|e| format!("state: {e}"))?;
                self.latest = Some(note.clone());
            }
            Entry::Fence { size } => self.log.fence_at(*size),
            Entry::Equivocation { .. } => self.evidence = self.evidence.saturating_add(1),
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aw-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn note(size: u64, root: [u8; 32]) -> String {
        format!(
            "o\n{size}\n{}\n\n\u{2014} o AAAAAQE=\n",
            base64_encode(&root)
        )
    }

    // OP-158 m.3 (d), OP-73
    #[test]
    fn the_chain_replays_and_refuses_a_changed_line() {
        let d = dir("chain");
        let domain = Digest([5; 32]);
        let mut c = Chain::open(&d, &domain).unwrap();
        assert_eq!(c.log.base(), None);
        c.append(&Entry::Cosigned {
            size: 3,
            root: [1; 32],
            time: 9,
            note: note(3, [1; 32]),
        })
        .unwrap();
        c.append(&Entry::Fence { size: 8 }).unwrap();
        c.append(&Entry::Equivocation {
            note: note(3, [2; 32]),
        })
        .unwrap();
        drop(c);
        let c = Chain::open(&d, &domain).unwrap();
        assert_eq!(c.log.base(), Some((3, [1; 32])));
        assert_eq!(c.log.fence(), Some(8));
        assert_eq!(c.evidence, 1);
        assert_eq!(c.latest.as_deref(), Some(note(3, [1; 32]).as_str()));
        let p = path(&d, &domain);
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replace("fence 8", "fence 9")).unwrap();
        assert!(
            Chain::open(&d, &domain)
                .err()
                .unwrap()
                .contains("chain broken")
        );
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&p, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(Chain::open(&d, &domain).is_err());
    }
}
