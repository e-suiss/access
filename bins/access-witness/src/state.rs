//! The witness's own state (OP-158 m.3 (d), OP-73): per log an append-only file of
//! `witness-state-entry` links, one deterministic CBOR entry in hex per line, each naming the
//! SHA-256 of the previous one, so a changed or dropped line breaks the chain and the witness
//! refuses to start. A line is on disk (fsync) before the cosignature it records leaves the
//! process. Checkpoints refused as contradicting the base are kept in a second append-only
//! file as evidence (U9, HL-7).

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use suiss_crypto::note::{Checkpoint, parse_note};
use suiss_ledger::checkpoint::witness::{LogState, StateEntry};

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(t: &str) -> Option<Vec<u8>> {
    if !t.len().is_multiple_of(2) {
        return None;
    }
    (0..t.len())
        .step_by(2)
        .map(|i| {
            t.get(i..i.checked_add(2)?)
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect()
}

/// One log's chain.
pub(crate) struct Chain {
    file: File,
    evidence_file: PathBuf,
    domain: Digest,
    next_seq: u64,
    prev: [u8; 32],
    /// The witness's view.
    pub(crate) log: LogState,
    /// The last cosigned entry.
    pub(crate) latest: Option<StateEntry>,
    /// Refused checkpoints kept as evidence.
    pub(crate) evidence: usize,
    /// The Ed25519 binding keys learned from handover records, newest last (U11).
    pub(crate) learned: Vec<[u8; 32]>,
    /// Old bindings by kid and the size above which they are not cosigned (U11).
    pub(crate) fenced: std::collections::BTreeMap<[u8; 32], u64>,
}

/// The chain file of `domain` in `dir`.
pub(crate) fn path(dir: &Path, domain: &Digest) -> PathBuf {
    dir.join(format!("{}.chain", b64url_encode(&domain.0)))
}

fn open_append(p: &Path) -> Result<File, String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .map_err(|e| format!("{}: {e}", p.display()))
}

fn read(p: &Path) -> Result<String, String> {
    match std::fs::read_to_string(p) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

impl Chain {
    /// Opens or creates the chain of `domain` and checks every link.
    pub(crate) fn open(dir: &Path, domain: &Digest) -> Result<Self, String> {
        let p = path(dir, domain);
        let text = read(&p)?;
        let mut prev = [0_u8; 32];
        let (mut base, mut fence, mut latest) = (None, None, None);
        let mut learned = Vec::new();
        let mut fenced = std::collections::BTreeMap::new();
        let mut next_seq = 0_u64;
        for (n, line) in text.lines().enumerate() {
            let broken = || {
                format!(
                    "{}: chain broken at line {}",
                    p.display(),
                    n.saturating_add(1)
                )
            };
            let entry = unhex(line)
                .and_then(|b| StateEntry::from_bytes(&b).ok())
                .ok_or_else(broken)?;
            if entry.seq != next_seq || entry.prev != prev || entry.domain != domain.0 {
                return Err(broken());
            }
            prev = entry.hash().map_err(|_| broken())?;
            next_seq = next_seq.checked_add(1).ok_or_else(broken)?;
            match (&entry.keys, entry.fence) {
                (Some(keys), f) => {
                    if let Some(f) = f {
                        fenced.insert(entry.binding, f);
                    }
                    learned.clone_from(keys);
                    fence = None;
                }
                (None, Some(f)) => fence = Some(fence.map_or(f, |g: u64| g.min(f))),
                (None, None) => {}
            }
            if entry.note.is_some() {
                base = Some((entry.size, entry.root));
                latest = Some(entry);
            }
        }
        let evidence_file = dir.join(format!("{}.refused", b64url_encode(&domain.0)));
        let evidence = read(&evidence_file)?.lines().count();
        Ok(Self {
            file: open_append(&p)?,
            evidence_file,
            domain: *domain,
            next_seq,
            prev,
            log: LogState::resume(base, fence),
            latest,
            evidence,
            learned,
            fenced,
        })
    }

    /// U11, §16.6 HO-7: the binding `old` signs nothing larger than `max` from now on and
    /// `keys` are the domain's binding; synced before it returns.
    pub(crate) fn rebind(
        &mut self,
        old: [u8; 32],
        max: u64,
        keys: Vec<[u8; 32]>,
        at: u64,
    ) -> Result<(), String> {
        let (base, root) = self.log.base().unwrap_or((0, [0; 32]));
        self.append(StateEntry {
            seq: 0,
            domain: self.domain.0,
            size: base,
            root,
            binding: old,
            at,
            prev: [0; 32],
            note: None,
            fence: Some(max),
            keys: Some(keys.clone()),
        })?;
        self.fenced.insert(old, max);
        self.learned = keys;
        self.log.rebind();
        Ok(())
    }

    fn append(&mut self, mut entry: StateEntry) -> Result<StateEntry, String> {
        entry.seq = self.next_seq;
        entry.prev = self.prev;
        entry.domain = self.domain.0;
        let bytes = entry.to_bytes().map_err(|e| format!("state: {e}"))?;
        self.file
            .write_all(format!("{}\n", hex(&bytes)).as_bytes())
            .and_then(|()| self.file.sync_all())
            .map_err(|e| format!("state: {e}"))?;
        self.prev = suiss_crypto::digest::sha256(&bytes);
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(entry)
    }

    /// Records the cosignature of `cp` under `binding`, `note` holding the log's signature and
    /// this witness's, and syncs it before returning.
    pub(crate) fn cosigned(
        &mut self,
        cp: &Checkpoint,
        binding: [u8; 32],
        at: u64,
        note: String,
    ) -> Result<(), String> {
        let body = Checkpoint::parse(&parse_note(&note).map_err(|e| format!("state: {e}"))?.body)
            .map_err(|e| format!("state: {e}"))?;
        if (body.size, body.root) != (cp.size, cp.root) {
            return Err("state: entry does not match its note".into());
        }
        let mut probe = self.log;
        probe.cosigned(cp).map_err(|e| format!("state: {e}"))?;
        let entry = self.append(StateEntry {
            seq: 0,
            domain: self.domain.0,
            size: cp.size,
            root: cp.root,
            binding,
            at,
            prev: [0; 32],
            note: Some(note),
            fence: None,
            keys: None,
        })?;
        self.log = probe;
        self.latest = Some(entry);
        Ok(())
    }

    /// Fences `binding` above `size` (U11).
    pub(crate) fn fence(&mut self, binding: [u8; 32], size: u64, at: u64) -> Result<(), String> {
        let (base, root) = self.log.base().unwrap_or((0, [0; 32]));
        self.append(StateEntry {
            seq: 0,
            domain: self.domain.0,
            size: base,
            root,
            binding,
            at,
            prev: [0; 32],
            note: None,
            fence: Some(size),
            keys: None,
        })?;
        self.log.fence_at(size);
        Ok(())
    }

    /// Keeps a checkpoint that contradicts the base as evidence.
    pub(crate) fn refused(&mut self, note: &str) -> Result<(), String> {
        let mut f = open_append(&self.evidence_file)?;
        f.write_all(format!("{}\n", hex(note.as_bytes())).as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("evidence: {e}"))?;
        self.evidence = self.evidence.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]
mod tests {
    use suiss_crypto::note::base64_encode;

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

    fn cp(size: u64, root: [u8; 32]) -> Checkpoint {
        Checkpoint::parse(&parse_note(&note(size, root)).unwrap().body).unwrap()
    }

    // OP-158 m.3 (d), U11, OP-73
    #[test]
    fn the_chain_replays_and_refuses_a_changed_line() {
        let d = dir("chain");
        let domain = Digest([5; 32]);
        let mut c = Chain::open(&d, &domain).unwrap();
        assert_eq!(c.log.base(), None);
        c.cosigned(&cp(3, [1; 32]), [9; 32], 7, note(3, [1; 32]))
            .unwrap();
        c.fence([9; 32], 8, 8).unwrap();
        c.refused(&note(3, [2; 32])).unwrap();
        drop(c);
        let c = Chain::open(&d, &domain).unwrap();
        assert_eq!(c.log.base(), Some((3, [1; 32])));
        assert_eq!(c.log.fence(), Some(8));
        assert_eq!(c.evidence, 1);
        assert_eq!(
            c.latest.as_ref().unwrap().note.as_deref(),
            Some(note(3, [1; 32]).as_str())
        );
        let p = path(&d, &domain);
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut first = StateEntry::from_bytes(&unhex(lines[0]).unwrap()).unwrap();
        first.at += 1;
        let changed = hex(&first.to_bytes().unwrap());
        std::fs::write(&p, format!("{changed}\n{}\n", lines[1])).unwrap();
        assert!(Chain::open(&d, &domain).is_err());
        std::fs::write(&p, format!("{}\n", lines[1])).unwrap();
        assert!(
            Chain::open(&d, &domain)
                .err()
                .unwrap()
                .contains("chain broken")
        );
    }

    // U11, OP-158 m.3 (l)
    #[test]
    fn a_learned_binding_and_the_old_bindings_fence_survive_a_restart() {
        let d = dir("rebind");
        let domain = Digest([6; 32]);
        let mut c = Chain::open(&d, &domain).unwrap();
        c.cosigned(&cp(4, [1; 32]), [9; 32], 7, note(4, [1; 32]))
            .unwrap();
        c.rebind([9; 32], 4, vec![[3; 32]], 8).unwrap();
        assert_eq!(c.log.fence(), None);
        drop(c);
        let c = Chain::open(&d, &domain).unwrap();
        assert_eq!(c.learned, vec![[3; 32]]);
        assert_eq!(c.fenced.get(&[9; 32]), Some(&4));
        assert_eq!(c.log.fence(), None);
        assert_eq!(c.log.base(), Some((4, [1; 32])));
    }
}
