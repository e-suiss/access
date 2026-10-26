use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;

use super::{SecretFile, SecretFileError, refuse_secret_environment};

fn file(name: &str, body: &str, mode: u32) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("access-secret-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cred");
    fs::File::create(&path)
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

// CR-35, OP-129 m.3
#[test]
fn reads_one_line_from_an_owner_only_file() {
    let p = file("ok", "s3cr3t\n", 0o400);
    assert_eq!(SecretFile::load(&p).unwrap().value().expose(), "s3cr3t");
}

#[test]
fn refuses_files_others_can_read() {
    for mode in [0o440, 0o404, 0o644] {
        let p = file(&format!("mode{mode:o}"), "x", mode);
        assert!(
            matches!(SecretFile::load(&p), Err(SecretFileError::Permissions(_))),
            "{mode:o}"
        );
    }
}

#[test]
fn refuses_empty_multi_line_and_large_files() {
    for (name, body) in [
        ("empty", ""),
        ("lines", "a\nb\n"),
        ("large", &"x".repeat(4097)),
    ] {
        let p = file(name, body, 0o600);
        assert!(
            matches!(SecretFile::load(&p), Err(SecretFileError::Content(_))),
            "{name}"
        );
    }
}

// OP-52: rotation is picked up on the next check
#[test]
fn reloads_when_the_file_changes() {
    let p = file("rotate", "one", 0o600);
    let mut s = SecretFile::load(&p).unwrap();
    assert!(!s.reload_if_changed().unwrap());
    fs::write(&p, "two-longer").unwrap();
    assert!(s.reload_if_changed().unwrap());
    assert_eq!(s.value().expose(), "two-longer");
}

// OP-129 m.3: secrets never come from the environment
#[test]
fn refuses_secret_environment_variables() {
    let names = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert!(
        refuse_secret_environment(names(&[
            "ACCESS_LOG",
            "ACCESS_DATABASE_PASSWORD_FILE",
            "PATH"
        ]))
        .is_ok()
    );
    for bad in [
        "ACCESS_DATABASE_PASSWORD",
        "access_pkcs11_pin",
        "ACCESS_API_TOKEN",
        "ACCESS_SIGNING_PRIVATE_KEY",
    ] {
        let err = refuse_secret_environment(names(&[bad])).unwrap_err();
        assert!(
            matches!(&err, SecretFileError::Environment(n) if n == bad),
            "{bad}"
        );
    }
}
