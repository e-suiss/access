//! The HSM usage journal (§17.8.2, SEC19, SA-51, TI-18, OP-157 m.3 (k)): every operation on the
//! token, a binding-key signature or a KEK wrap or unwrap, is a `signer.hsm_used` line with its
//! purpose, key, operation, caller and count, synced to an append-only, hash-chained file in the
//! vault and copied to the log stream, before its result is returned. When the line cannot be
//! written the result is not returned. The journal is not canonical and no decision reads it.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use access_authority_signer::adapters::binding_label;
use access_authority_signer::ports::Bindings;
use access_crypto::breakglass::{hex, unhex};
use access_crypto::webauthn::sha256;
use access_kernel::digest::Digest;
use suiss_crypto::cose::{Algorithm, PublicKey};
use suiss_crypto::envelope::{Dek, EnvelopeError, Kek};
use suiss_crypto::signer::{SignError, Signer};
use zeroize::Zeroizing;

/// The audit taxonomy name of a journal line.
pub(crate) const AUDIT_EVENT: &str = "signer.hsm_used";

/// Why the journal is unusable.
#[derive(Debug, thiserror::Error)]
pub(crate) enum JournalError {
    /// The file cannot be read or written.
    #[error("HSM usage journal unwritable")]
    Io,
    /// A line does not chain to the one before it.
    #[error("HSM usage journal chain broken")]
    Chain,
}

fn genesis() -> [u8; 32] {
    sha256(b"access/signer/hsm-usage/v1")
}

/// The journal file and the head of its chain.
pub(crate) struct Journal {
    path: PathBuf,
    head: Mutex<(u64, [u8; 32])>,
    caller: String,
}

impl Journal {
    /// Opens `path`, verifying its chain; a missing file is an empty journal. `caller` names who
    /// may call the signer (the declared user ids).
    pub(crate) fn open(path: &Path, caller: &str) -> Result<Self, JournalError> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(_) => return Err(JournalError::Io),
        };
        let mut next = 1_u64;
        let mut head = genesis();
        for line in text.lines() {
            let parts: Vec<&str> = line.split(' ').collect();
            let [seq, at, event, fields, prev, hash] = parts.as_slice() else {
                return Err(JournalError::Chain);
            };
            if seq.parse::<u64>().ok() != Some(next) || unhex(prev).as_deref() != Some(&head[..]) {
                return Err(JournalError::Chain);
            }
            let mut input = head.to_vec();
            input.extend(format!("{seq} {at} {event} {fields}").as_bytes());
            let want = sha256(&input);
            if unhex(hash).as_deref() != Some(&want[..]) {
                return Err(JournalError::Chain);
            }
            head = want;
            next = next.checked_add(1).ok_or(JournalError::Chain)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            head: Mutex::new((next, head)),
            caller: caller.to_owned(),
        })
    }

    /// Writes one line for `count` operations `op` on `key` for `purpose`.
    pub(crate) fn used(
        &self,
        purpose: &str,
        key: &str,
        op: &str,
        count: u64,
    ) -> Result<(), JournalError> {
        let mut head = self.head.lock().map_err(|_| JournalError::Io)?;
        let (seq, prev) = *head;
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let fields = format!(
            "purpose={purpose},key={key},op={op},caller={},count={count}",
            self.caller
        );
        let body = format!("{seq} {at} {AUDIT_EVENT} {fields}");
        let mut input = prev.to_vec();
        input.extend(body.as_bytes());
        let hash = sha256(&input);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| JournalError::Io)?;
        f.write_all(format!("{body} {} {}\n", hex(&prev), hex(&hash)).as_bytes())
            .and_then(|()| f.sync_data())
            .map_err(|_| JournalError::Io)?;
        *head = (seq.checked_add(1).ok_or(JournalError::Chain)?, hash);
        drop(head);
        tracing::info!(
            event = "signer.hsm_used",
            purpose,
            key,
            op,
            caller = %self.caller,
            count,
            "HSM operation"
        );
        Ok(())
    }
}

/// Binding keys whose every signature is journaled (CR-29).
pub(crate) struct JournaledBindings<B> {
    inner: B,
    journal: Arc<Journal>,
}

impl<B> JournaledBindings<B> {
    pub(crate) const fn new(inner: B, journal: Arc<Journal>) -> Self {
        Self { inner, journal }
    }
}

impl<B: Bindings> Bindings for JournaledBindings<B> {
    fn binding(&mut self, domain: &Digest) -> Result<Box<dyn Signer + Send>, SignError> {
        let inner = self.inner.binding(domain)?;
        Ok(Box::new(JournaledSigner {
            inner,
            key: binding_label(domain),
            journal: Arc::clone(&self.journal),
        }))
    }
}

struct JournaledSigner {
    inner: Box<dyn Signer + Send>,
    key: String,
    journal: Arc<Journal>,
}

impl Signer for JournaledSigner {
    fn algorithm(&self) -> Algorithm {
        self.inner.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.inner.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let sig = self.inner.sign(message)?;
        self.journal
            .used("binding", &self.key, "sign", 1)
            .map_err(|_| SignError::Key)?;
        Ok(sig)
    }
}

/// The token's KEK, every wrap and unwrap journaled (CR-21 m.3).
pub(crate) struct JournaledKek<K> {
    inner: K,
    journal: Arc<Journal>,
}

impl<K> JournaledKek<K> {
    pub(crate) const fn new(inner: K, journal: Arc<Journal>) -> Self {
        Self { inner, journal }
    }
}

impl<K: Kek> JournaledKek<K> {
    fn used<T>(&self, op: &str, result: T, err: EnvelopeError) -> Result<T, EnvelopeError> {
        self.journal
            .used("kek", self.inner.id(), op, 1)
            .map_err(|_| err)?;
        Ok(result)
    }
}

impl<K: Kek> Kek for JournaledKek<K> {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, EnvelopeError> {
        let out = self.inner.wrap(dek)?;
        self.used("wrap", out, EnvelopeError::Wrap)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, EnvelopeError> {
        let out = self.inner.unwrap(wrapped)?;
        self.used("unwrap", out, EnvelopeError::Wrap)
    }

    fn pepper(&self, context: &[u8], plaintext: &[u8]) -> Result<(u16, Vec<u8>), EnvelopeError> {
        let out = self.inner.pepper(context, plaintext)?;
        self.used("pepper", out, EnvelopeError::Seal)
    }

    fn unpepper(
        &self,
        version: u16,
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let out = self.inner.unpepper(version, context, sealed)?;
        self.used("unpepper", out, EnvelopeError::Open)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use suiss_crypto::envelope::SoftKek;
    use suiss_crypto::signer::SoftSigner;

    use super::*;

    struct Soft;

    impl Bindings for Soft {
        fn binding(&mut self, _: &Digest) -> Result<Box<dyn Signer + Send>, SignError> {
            Ok(Box::new(SoftSigner::generate_ed25519()?.0))
        }
    }

    fn journal(name: &str) -> (PathBuf, Arc<Journal>) {
        let dir = std::env::temp_dir().join(format!("hsm-log-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hsm-usage.log");
        (
            path.clone(),
            Arc::new(Journal::open(&path, "uid:1000").unwrap()),
        )
    }

    // SEC19, OP-157 m.3 (k)
    #[test]
    fn sec19_every_hsm_operation_is_journaled_before_it_returns() {
        let (path, j) = journal("ops");
        let mut b = JournaledBindings::new(Soft, Arc::clone(&j));
        let domain = Digest(sha256(b"domain"));
        let signer = b.binding(&domain).unwrap();
        signer.sign(b"one").unwrap();
        signer.sign(b"two").unwrap();
        let kek = JournaledKek::new(
            SoftKek::new("kek-1", access_crypto::random::bytes::<32>().unwrap()),
            Arc::clone(&j),
        );
        let dek = Dek::generate().unwrap();
        let wrapped = kek.wrap(&dek).unwrap();
        kek.unwrap(&wrapped).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert!(lines.iter().all(|l| l.contains(" signer.hsm_used ")));
        assert!(lines.first().unwrap().contains(&format!(
            "purpose=binding,key={},op=sign,caller=uid:1000,count=1",
            binding_label(&domain)
        )));
        assert!(
            lines
                .get(3)
                .unwrap()
                .contains("purpose=kek,key=kek-1,op=unwrap")
        );
        assert!(Journal::open(&path, "uid:1000").is_ok());
        std::fs::write(&path, text.replacen("op=sign", "op=nope", 1)).unwrap();
        assert!(matches!(
            Journal::open(&path, "uid:1000"),
            Err(JournalError::Chain)
        ));
    }

    // SEC19, OP-157 m.3 (k)
    #[test]
    fn sec19_no_journal_line_no_result() {
        let (path, j) = journal("closed");
        let mut b = JournaledBindings::new(Soft, Arc::clone(&j));
        let signer = b.binding(&Digest(sha256(b"d"))).unwrap();
        std::fs::remove_file(&path).ok();
        std::fs::create_dir_all(&path).unwrap();
        assert!(matches!(signer.sign(b"m"), Err(SignError::Key)));
        let kek = JournaledKek::new(
            SoftKek::new("kek-1", access_crypto::random::bytes::<32>().unwrap()),
            j,
        );
        assert!(kek.wrap(&Dek::generate().unwrap()).is_err());
    }
}
