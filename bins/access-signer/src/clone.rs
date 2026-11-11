//! `access-signer binding-clone` (CR-30, OP-158 m.3 (y)): a domain's binding key goes to the DR
//! token only as a backup wrapped under the trusted clone key both tokens hold, and only while
//! the ceremony has the binding keys activated (the quorum's gate). Each export and import is a
//! `binding.cloned` line in the HSM usage journal. A production HSM clones with its own vendor
//! mechanism; this is the local equivalent on `SoftHSM`.

use std::path::Path;

use access_authority_signer::adapters::binding_label;
use access_crypto::breakglass::{hex, unhex};
use access_kernel::digest::Digest;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::pkcs11::{KeyStore, WrappedBackup};

use crate::hsm_log::Journal;

/// Why a clone step stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CloneError {
    /// The command line is not one of the forms.
    #[error(
        "usage: access-signer binding-clone export|import <domain hex> <clone key label> <file>"
    )]
    Usage,
    /// The token refused: no such key, not cloneable, or another clone key.
    #[error("hsm: {0}")]
    Hsm(String),
    /// The backup file cannot be read or written, or is not a backup.
    #[error("backup file: {0}")]
    File(String),
    /// The journal line could not be written; nothing is returned.
    #[error(transparent)]
    Journal(#[from] crate::hsm_log::JournalError),
}

fn domain(text: &str) -> Result<Digest, CloneError> {
    unhex(text)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(Digest)
        .ok_or(CloneError::Usage)
}

fn encode(b: &WrappedBackup) -> Result<String, CloneError> {
    let (alg, public) = match &b.public {
        PublicKey::Ed25519(p) => ("ed25519", p.to_vec()),
        PublicKey::P256(p) => ("p256", p.clone()),
        PublicKey::MlDsa(..) => return Err(CloneError::Hsm("not a binding key".into())),
    };
    Ok(format!("{alg} {} {}\n", hex(&public), hex(&b.wrapped)))
}

fn decode(text: &str) -> Result<WrappedBackup, CloneError> {
    let bad = || CloneError::File("not a binding key backup".into());
    let parts: Vec<&str> = text.trim().split(' ').collect();
    let [alg, public, wrapped] = parts.as_slice() else {
        return Err(bad());
    };
    let public = unhex(public).ok_or_else(bad)?;
    let public = match *alg {
        "ed25519" => PublicKey::Ed25519(public.try_into().map_err(|_| bad())?),
        "p256" => PublicKey::P256(public),
        _ => return Err(bad()),
    };
    Ok(WrappedBackup {
        wrapped: unhex(wrapped).ok_or_else(bad)?,
        public,
    })
}

/// CR-30: the backup of `domain`'s binding key under `clone_key`, journaled.
pub(crate) fn export(
    store: &KeyStore,
    journal: &Journal,
    domain: &Digest,
    clone_key: &str,
) -> Result<String, CloneError> {
    let label = binding_label(domain);
    let backup = store
        .export_clone(&label, clone_key)
        .map_err(|e| CloneError::Hsm(e.to_string()))?;
    let text = encode(&backup)?;
    journal.cloned(&label, "export")?;
    Ok(text)
}

/// CR-30: unwraps a backup of `domain`'s binding key into this token under `clone_key`,
/// journaled; the clone must sign as the original's public key says.
pub(crate) fn import(
    store: &KeyStore,
    journal: &Journal,
    domain: &Digest,
    clone_key: &str,
    backup: &str,
) -> Result<PublicKey, CloneError> {
    let label = binding_label(domain);
    let backup = decode(backup)?;
    let signer = store
        .import_clone(&label, clone_key, &backup)
        .map_err(|e| CloneError::Hsm(e.to_string()))?;
    journal.cloned(&label, "import")?;
    Ok(suiss_crypto::signer::Signer::public_key(&signer))
}

/// What the command line asks.
pub(crate) enum Step<'a> {
    /// Write the backup to the file.
    Export(Digest, &'a str, &'a Path),
    /// Read the backup from the file.
    Import(Digest, &'a str, &'a Path),
}

/// Parses `export|import <domain hex> <clone key label> <file>`.
///
/// # Errors
/// [`CloneError::Usage`].
pub(crate) fn step(args: &[std::ffi::OsString]) -> Result<Step<'_>, CloneError> {
    fn text(a: &std::ffi::OsString) -> Result<&str, CloneError> {
        a.to_str().ok_or(CloneError::Usage)
    }
    match args {
        [op, d, key, file] if op == "export" => {
            Ok(Step::Export(domain(text(d)?)?, text(key)?, Path::new(file)))
        }
        [op, d, key, file] if op == "import" => {
            Ok(Step::Import(domain(text(d)?)?, text(key)?, Path::new(file)))
        }
        _ => Err(CloneError::Usage),
    }
}

/// Runs one step against the opened token.
///
/// # Errors
/// [`CloneError`].
pub(crate) fn run(store: &KeyStore, journal: &Journal, step: &Step<'_>) -> Result<(), CloneError> {
    match step {
        Step::Export(d, key, file) => {
            let text = export(store, journal, d, key)?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(file)
                .map_err(|e| CloneError::File(e.to_string()))?;
            std::io::Write::write_all(&mut f, text.as_bytes())
                .and_then(|()| f.sync_all())
                .map_err(|e| CloneError::File(e.to_string()))
        }
        Step::Import(d, key, file) => {
            let text =
                std::fs::read_to_string(file).map_err(|e| CloneError::File(e.to_string()))?;
            import(store, journal, d, key, &text).map(drop)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use access_crypto::Secret;
    use suiss_crypto::signer::Signer as _;

    use super::*;

    fn module() -> std::path::PathBuf {
        [
            std::env::var("SUISS_PKCS11_MODULE").unwrap_or_default(),
            String::from("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
            String::from("/usr/lib/softhsm/libsofthsm2.so"),
            String::from("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
            String::from("/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"),
        ]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.is_file())
        .unwrap()
    }

    // CR-30, OP-158
    #[test]
    fn a_binding_key_clones_to_the_dr_token_and_each_step_is_journaled() {
        let labels: Vec<String> = ["clone-primary", "clone-dr"]
            .iter()
            .map(|n| format!("{n}-{}", std::process::id()))
            .collect();
        for l in &labels {
            let out = suiss_crypto::pkcs11::token_tests::init_softhsm_token(
                None,
                l,
                "1234-test-only",
                "5678-test-only",
            )
            .unwrap();
            assert!(out.status.success(), "{out:?}");
        }
        let open = |l: &str| {
            KeyStore::open(&module(), l, &Secret::new(String::from("1234-test-only"))).unwrap()
        };
        let (primary, dr) = (open(&labels[0]), open(&labels[1]));
        let value: [u8; 32] = access_crypto::random::bytes().unwrap();
        let so = Secret::new(String::from("5678-test-only"));
        for t in [&primary, &dr] {
            t.install_clone_key(&so, "access/clone", &Secret::new(value))
                .unwrap();
        }
        let d = Digest([7; 32]);
        let original = primary
            .generate_cloneable(&binding_label(&d), true)
            .unwrap();
        let dir = std::env::temp_dir().join(format!("binding-clone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = Journal::open(&dir.join("hsm-usage.log"), "uid:1000").unwrap();
        let file = dir.join("backup");
        run(&primary, &journal, &Step::Export(d, "access/clone", &file)).unwrap();
        run(&dr, &journal, &Step::Import(d, "access/clone", &file)).unwrap();
        let clone = dr.signer(&binding_label(&d)).unwrap();
        assert_eq!(clone.public_key(), original.public_key());
        let log = std::fs::read_to_string(dir.join("hsm-usage.log")).unwrap();
        let lines: Vec<&str> = log
            .lines()
            .filter(|l| l.contains(" binding.cloned "))
            .collect();
        assert_eq!(lines.len(), 2, "{log}");
        assert!(lines[0].contains("op=export") && lines[1].contains("op=import"));
        assert!(Journal::open(&dir.join("hsm-usage.log"), "uid:1000").is_ok());
        assert!(matches!(
            run(&primary, &journal, &Step::Export(d, "access/clone", &file)),
            Err(CloneError::File(_))
        ));
        assert!(matches!(
            run(
                &primary,
                &journal,
                &Step::Export(Digest([8; 32]), "access/clone", &dir.join("x"))
            ),
            Err(CloneError::Hsm(_))
        ));
        assert_eq!(
            log.lines()
                .filter(|l| l.contains(" binding.cloned "))
                .count(),
            2,
            "a refused step writes no line"
        );
        drop((original, clone));
    }
}
