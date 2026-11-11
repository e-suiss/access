//! The ceremony commands over files, and the signer's binding keys in its own `SoftHSM` token
//! behind the transcript they write (CR-29, OP-69, OP-157 m.3 (x)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt as _;

use access_authority_signer::adapters::{DirVault, HsmBindings, SealedFactory, binding_label};
use access_authority_signer::ceremony::{Gate, Quorate};
use access_authority_signer::domain::Template;
use access_authority_signer::protocol::{Request, Response};
use access_authority_signer::service::Service;
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::SpecVersions;
use suiss_crypto::cose::{Algorithm, PublicKey};
use suiss_crypto::envelope::SoftKek;
use suiss_crypto::signer::Signer as _;

use super::*;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "access-signer-ceremony-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Three ceremony keys as hex PKCS#8 files only their owner reads, and the roster naming them.
fn members(dir: &Path) -> (Vec<PathBuf>, PathBuf) {
    let mut files = Vec::new();
    let mut roster = String::from("threshold = 2\n");
    for i in 0..3 {
        let (signer, doc) = SoftSigner::generate_ed25519().unwrap();
        let path = dir.join(format!("member-{i}.key"));
        std::fs::write(&path, hex(doc.expose())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let PublicKey::Ed25519(public) = signer.public_key() else {
            panic!("ed25519");
        };
        roster.push_str("[[members]]\ned25519 = \"");
        roster.push_str(&hex(&public));
        roster.push_str("\"\n");
        files.push(path);
    }
    let path = dir.join("roster.toml");
    std::fs::write(&path, roster).unwrap();
    (files, path)
}

fn cmd(args: &[&str]) -> Result<(), CommandError> {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    run(&args)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Drafts `op` into `permit` and has `members` approve it.
fn permit(t: &Path, permit: &Path, op: &[&str], keys: &[PathBuf], members: &[u8]) {
    let mut args = vec!["init", s(t), s(permit)];
    args.extend_from_slice(op);
    cmd(&args).unwrap();
    for m in members {
        let m = m.to_string();
        cmd(&[
            "approve",
            s(t),
            s(permit),
            &m,
            "ed25519",
            s(&keys[usize::from(m.parse::<u8>().unwrap())]),
        ])
        .unwrap();
    }
}

fn template(domain: u8) -> Template {
    Template {
        domain: Digest([domain; 32]),
        genesis: Digest([domain ^ 0xff; 32]),
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_alg: Algorithm::Ed25519,
        operational_window_max_ms: 86_400_000,
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
    }
}

// CR-29, FA-6, MD-6, OP-157 m.3 (x), OP-69
#[test]
fn the_binding_key_is_made_and_used_only_under_a_quorate_activation() {
    let dir = temp("quorum");
    let (keys, roster) = members(&dir);
    let t = dir.join("ceremony.transcript");
    let p = dir.join("permit.cbor");

    // init: every member approves; two of three is not enough
    permit(&t, &p, &["roster", s(&roster)], &keys, &[0, 1]);
    assert!(matches!(
        cmd(&["sign", s(&t), s(&p)]),
        Err(CommandError::Ceremony(CeremonyError::QuorumMissing))
    ));
    cmd(&["approve", s(&t), s(&p), "2", "ed25519", s(&keys[2])]).unwrap();
    cmd(&["sign", s(&t), s(&p)]).unwrap();
    let genesis = Transcript::genesis_of(&std::fs::read(&t).unwrap()).unwrap();
    let pin_file = dir.join("genesis");
    std::fs::write(&pin_file, hex(&genesis)).unwrap();
    let config = crate::config::Ceremony {
        transcript: t.clone(),
        genesis_file: pin_file.clone(),
    };
    assert!(crate::activated(&config).is_none(), "not activated yet");

    let bindings = HsmBindings::new(crate::tests::fresh_token("ceremony"));
    let store: &'static suiss_crypto::pkcs11::KeyStore =
        Box::leak(Box::new(crate::tests::reopen("ceremony")));
    let gate = Gate::new(&Policy::AUTHORITY, now_ms);
    let vault = dir.join("vault");
    std::fs::create_dir_all(&vault).unwrap();
    let kek = access_crypto::random::bytes::<32>().unwrap();
    let service = Box::leak(Box::new(
        Service::start(
            SealedFactory::new(SoftKek::new("kek", kek)),
            Quorate::new(bindings, gate.clone()),
            DirVault::new(&vault),
            Policy::AUTHORITY,
            now_ms(),
        )
        .unwrap(),
    ));
    let open =
        |s: &mut Service<_, _, _>, d| s.handle(Request::Open(Box::new(template(d))), now_ms());

    // a binding key operation without a permit is refused, and no key is made
    assert_eq!(
        open(service, 1),
        Response::Error(String::from("signer-binding"))
    );
    assert!(store.signer(&binding_label(&Digest([1; 32]))).is_err());

    // a permit one member signed is refused
    permit(&t, &p, &["activate", "1"], &keys, &[0]);
    assert!(matches!(
        cmd(&["sign", s(&t), s(&p)]),
        Err(CommandError::Ceremony(CeremonyError::QuorumMissing))
    ));
    let pin = ceremony_pin(&pin_file);
    assert!(gate.adopt(pinned(&t, &pin).unwrap().state()).is_err());
    assert_eq!(
        open(service, 1),
        Response::Error(String::from("signer-binding"))
    );

    // the second approval makes it quorate; the signer adopts it and the binding key is made
    cmd(&["approve", s(&t), s(&p), "2", "ed25519", s(&keys[2])]).unwrap();
    cmd(&["sign", s(&t), s(&p)]).unwrap();
    assert!(matches!(
        cmd(&["sign", s(&t), s(&p)]),
        Err(CommandError::Ceremony(CeremonyError::NonceReused))
    ));
    let (started, _, head) = crate::activated(&config).unwrap();
    assert!(started.open());
    let mut seen = [0; 32];
    crate::refresh(&t, &pin, &gate, &mut seen);
    assert_eq!(seen, head);
    assert!(gate.open());
    assert_eq!(open(service, 1), Response::Opened);
    let binding = store.signer(&binding_label(&Digest([1; 32]))).unwrap();
    assert!(matches!(
        service.handle(Request::Metadata(Digest([1; 32])), now_ms()),
        Response::Metadata(_)
    ));

    // deactivation stops the binding key signing
    permit(&t, &p, &["deactivate"], &keys, &[1, 2]);
    cmd(&["sign", s(&t), s(&p)]).unwrap();
    crate::refresh(&t, &pin, &gate, &mut seen);
    assert!(!gate.open());
    assert_eq!(
        open(service, 2),
        Response::Error(String::from("signer-binding"))
    );
    assert!(binding.sign(b"still the HSM's key").is_ok());
    assert!(crate::activated(&config).is_none());
}

fn ceremony_pin(path: &Path) -> [u8; 32] {
    pin(path).unwrap()
}

// CR-29, OP-157 m.3 (x)
#[test]
fn a_broken_transcript_keeps_the_signer_from_starting_and_closes_a_running_one() {
    let dir = temp("broken");
    let (keys, roster) = members(&dir);
    let t = dir.join("ceremony.transcript");
    let p = dir.join("permit.cbor");
    permit(&t, &p, &["roster", s(&roster)], &keys, &[0, 1, 2]);
    cmd(&["sign", s(&t), s(&p)]).unwrap();
    permit(&t, &p, &["activate", "2"], &keys, &[0, 1]);
    cmd(&["sign", s(&t), s(&p)]).unwrap();
    let bytes = std::fs::read(&t).unwrap();
    let pin_file = dir.join("genesis");
    std::fs::write(&pin_file, hex(&Transcript::genesis_of(&bytes).unwrap())).unwrap();
    let config = crate::config::Ceremony {
        transcript: t.clone(),
        genesis_file: pin_file.clone(),
    };
    let (gate, pin, mut head) = crate::activated(&config).unwrap();
    assert!(gate.open());
    cmd(&["transcript", s(&t), &hex(&pin)]).unwrap();

    let mut broken = bytes.clone();
    let last = broken.len() - 3;
    broken[last] ^= 0x40;
    std::fs::write(&t, &broken).unwrap();
    assert!(crate::activated(&config).is_none(), "refuses to start");
    assert!(cmd(&["transcript", s(&t), &hex(&pin)]).is_err());
    crate::refresh(&t, &pin, &gate, &mut head);
    assert!(!gate.open(), "a running signer closes its binding keys");

    std::fs::write(&t, &bytes[..bytes.len() / 2]).unwrap();
    assert!(crate::activated(&config).is_none());

    let (other_keys, other_roster) = members(&temp("other"));
    let other = dir.join("other.transcript");
    permit(
        &other,
        &p,
        &["roster", s(&other_roster)],
        &other_keys,
        &[0, 1, 2],
    );
    cmd(&["sign", s(&other), s(&p)]).unwrap();
    permit(&other, &p, &["activate", "2"], &other_keys, &[0, 1]);
    cmd(&["sign", s(&other), s(&p)]).unwrap();
    std::fs::copy(&other, &t).unwrap();
    assert!(
        crate::activated(&config).is_none(),
        "another roster's transcript does not match the pin"
    );
    assert!(std::fs::remove_file(&pin_file).is_ok());
    assert!(crate::activated(&config).is_none());
}

// CR-29, OP-157 m.3 (x)
#[test]
fn ceremony_inputs_come_from_files_the_operator_names() {
    let dir = temp("inputs");
    let (keys, roster) = members(&dir);
    std::fs::set_permissions(&keys[0], std::fs::Permissions::from_mode(0o644)).unwrap();
    let t = dir.join("ceremony.transcript");
    let p = dir.join("permit.cbor");
    cmd(&["init", s(&t), s(&p), "roster", s(&roster)]).unwrap();
    assert!(matches!(
        cmd(&["approve", s(&t), s(&p), "0", "ed25519", s(&keys[0])]),
        Err(CommandError::Content(..))
    ));
    assert!(matches!(
        cmd(&["approve", s(&t), s(&p), "1", "ed25519", s(&keys[2])]),
        Err(CommandError::Ceremony(CeremonyError::Approval))
    ));
    assert!(matches!(cmd(&["sign", s(&t)]), Err(CommandError::Usage)));
    assert!(matches!(
        cmd(&["init", s(&t), s(&p), "activate", "721"]),
        Err(CommandError::Ceremony(CeremonyError::Window))
    ));
    let one = dir.join("one.toml");
    std::fs::write(&one, "threshold = 1\n[[members]]\ned25519 = \"00\"\n").unwrap();
    assert!(cmd(&["init", s(&t), s(&p), "roster", s(&one)]).is_err());
}
