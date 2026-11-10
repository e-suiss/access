//! The modules' safe halves (OP-156 m.3 (p)): buffer layout as glibc expects it, the PAM
//! request and result, and the refusal when the daemon does not answer.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::Path;
use std::time::Duration;

use access_linux_module::client::{Unanswered, ask, decide};
use access_linux_module::nss::{extra_groups, pack_group, pack_passwd};
use access_linux_module::pam::{PAM_AUTH_ERR, PAM_AUTHINFO_UNAVAIL, PAM_SUCCESS, request, result};
use access_linux_module::wire::{Group, Passwd, Request};

fn ayse() -> Passwd {
    Passwd {
        name: String::from("ayse"),
        uid: 200_001,
        gid: 200_000,
        gecos: String::new(),
        dir: String::from("/home/ayse"),
        shell: String::from("/bin/bash"),
    }
}

// OP-156 m.3 (p)
#[test]
fn a_passwd_entry_is_laid_out_or_refused_for_a_short_buffer() {
    let mut buf = [0xffu8; 64];
    let l = pack_passwd(&ayse(), &mut buf).unwrap();
    let at = |o: usize| {
        let end = o + buf[o..].iter().position(|b| *b == 0).unwrap();
        std::str::from_utf8(&buf[o..end]).unwrap().to_owned()
    };
    assert_eq!(at(l.name), "ayse");
    assert_eq!(at(l.passwd), "x");
    assert_eq!(at(l.dir), "/home/ayse");
    assert_eq!(at(l.shell), "/bin/bash");
    let mut short = [0u8; 20];
    assert!(pack_passwd(&ayse(), &mut short).is_none());
}

// OP-156 m.3 (p)
#[test]
fn a_group_member_array_is_aligned_and_terminated() {
    let g = Group {
        name: String::from("prod-web"),
        gid: 200_000,
        members: vec![String::from("ayse"), String::from("mert")],
    };
    let mut buf = [0u8; 128];
    let base = 0x1001;
    let l = pack_group(&g, &mut buf, base).unwrap();
    let word = std::mem::size_of::<usize>();
    assert_eq!((base + l.members) % word, 0);
    let ptr = |i: usize| {
        let o = l.members + i * word;
        usize::from_ne_bytes(buf[o..o + word].try_into().unwrap())
    };
    assert_eq!(ptr(0) - base, 11);
    assert_eq!(ptr(1) - base, 16);
    assert_eq!(ptr(2), 0);
    assert_eq!(
        extra_groups(&[200_000, 200_005, 200_005], 200_000),
        vec![200_005]
    );
}

// OP-156 m.3 (p)
#[test]
fn pam_asks_a_step_up_for_sudo_and_never_succeeds_undecided() {
    assert!(matches!(
        request("ayse", "sudo", Some("pts/0"), b"sudo\0id\0"),
        Request::Sudo { .. }
    ));
    assert!(matches!(
        request("ayse", "login", Some("tty1"), b""),
        Request::Authenticate { .. }
    ));
    assert_eq!(result(Some(true)), PAM_SUCCESS);
    assert_eq!(result(Some(false)), PAM_AUTH_ERR);
    assert_eq!(result(None), PAM_AUTHINFO_UNAVAIL);
}

// OP-156 m.3 (p), TI-9
#[test]
fn the_modules_refuse_when_the_daemon_is_down() {
    let missing = Path::new("/nonexistent/access-linuxd/socket");
    assert_eq!(
        ask(
            missing,
            &Request::Getpwnam(String::from("ayse")),
            Duration::from_secs(1)
        ),
        Err(Unanswered)
    );
    let login = request("ayse", "login", None, b"");
    assert_eq!(
        decide(missing, &login, Duration::from_secs(1), |_| {}),
        None
    );
    assert_eq!(
        result(decide(missing, &login, Duration::from_secs(1), |_| {})),
        PAM_AUTHINFO_UNAVAIL
    );
}
