#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code"
)]

use proptest::prelude::*;

use super::*;

/// The canonical spelling of a list of decoded segments.
fn encode(segments: &[Vec<u8>]) -> String {
    let mut out = String::new();
    for s in segments {
        out.push('/');
        for &c in s {
            if unreserved(c) || sub_delim(c) || matches!(c, b':' | b'@') {
                out.push(char::from(c));
            } else {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{c:02X}"));
            }
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn decode(path: &str) -> Vec<Vec<u8>> {
    if path == "/" {
        return Vec::new();
    }
    path[1..]
        .split('/')
        .map(|s| {
            let b = s.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'%' {
                    out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            out
        })
        .collect()
}

fn structural(c: u8) -> bool {
    matches!(c, b'/' | b'\\' | b'%') || c < 0x20 || c == 0x7f
}

fn segments() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(
        prop::collection::vec(any::<u8>(), 1..12).prop_filter("segment", |s| {
            s != b"." && s != b".." && !s.iter().copied().any(structural)
        }),
        0..6,
    )
}

// TN-113
#[test]
fn ordinary_paths_are_canonical() {
    for p in [
        "/",
        "/.well-known/openid-configuration/realms/acme",
        "/access/v1/keys/q1w2-e3_r4~",
        "/v1/me/auth-context",
        "/a%20b/%C3%A9",
    ] {
        assert_eq!(check(p), Ok(()), "{p}");
    }
}

// TN-113
#[test]
fn other_spellings_are_refused() {
    for (p, e) in [
        ("", PathError::Shape),
        ("a/b", PathError::Shape),
        ("/a/../b", PathError::Dot),
        ("/a/./b", PathError::Dot),
        ("/a/%2e%2e/b", PathError::Encoding),
        ("/a/%2E%2E/b", PathError::Encoding),
        ("/a//b", PathError::Empty),
        ("/a/", PathError::Empty),
        ("/a%2Fb", PathError::Encoding),
        ("/a%5Cb", PathError::Encoding),
        ("/a\\b", PathError::Character),
        ("/a%41", PathError::Encoding),
        ("/a%c3%a9", PathError::Encoding),
        ("/a%2", PathError::Encoding),
        ("/a%00", PathError::Encoding),
        ("/a%25", PathError::Encoding),
        ("/a b", PathError::Character),
        ("/é", PathError::Character),
    ] {
        assert_eq!(check(p), Err(e), "{p}");
    }
    assert_eq!(
        check(&format!("/{}", "a".repeat(MAX_PATH))),
        Err(PathError::Shape)
    );
}

proptest! {
    // TN-113
    #[test]
    fn canonical_paths_round_trip(segs in segments()) {
        let path = encode(&segs);
        prop_assume!(path.len() <= MAX_PATH);
        prop_assert_eq!(check(&path), Ok(()));
        prop_assert_eq!(decode(&path), segs);
    }

    // TN-113
    #[test]
    fn accepted_paths_are_their_own_canonical_form(raw in "/[a-zA-Z0-9%./\\\\:@!$&'()*+,;=~_-]{0,40}") {
        if check(&raw).is_ok() {
            let segs = decode(&raw);
            for s in &segs {
                prop_assert!(!s.is_empty() && s != b"." && s != b"..");
                prop_assert!(!s.iter().copied().any(structural));
            }
            prop_assert_eq!(encode(&segs), raw);
        }
    }

    // TN-113
    #[test]
    fn alternative_spellings_are_refused(segs in segments().prop_filter("one", |s| !s.is_empty()), at in any::<prop::sample::Index>()) {
        let path = encode(&segs);
        prop_assume!(path.len() < MAX_PATH - 8);
        let cut = path[1..].find('/').map_or(path.len(), |i| i + 1);
        let (head, tail) = path.split_at(cut);
        let dot = format!("{head}/.{tail}");
        let up = format!("{head}/x/..{tail}");
        let empty = format!("{head}/{tail}");
        for other in [dot, up, empty] {
            prop_assert!(check(&other).is_err(), "{}", other);
        }
        let plain: Vec<usize> = path
            .bytes()
            .enumerate()
            .filter(|(_, c)| unreserved(*c))
            .map(|(i, _)| i)
            .collect();
        if !plain.is_empty() {
            let i = plain[at.index(plain.len())];
            let encoded = format!("{}%{:02X}{}", &path[..i], path.as_bytes()[i], &path[i + 1..]);
            prop_assert!(check(&encoded).is_err(), "{}", encoded);
        }
        let hex_letter = path.match_indices('%').map(|(i, _)| i).find(|&i| {
            path.as_bytes()[i + 1..i + 3].iter().any(u8::is_ascii_uppercase)
        });
        if let Some(i) = hex_letter {
            let lower = format!("{}{}{}", &path[..=i], path[i + 1..i + 3].to_ascii_lowercase(), &path[i + 3..]);
            prop_assert!(check(&lower).is_err(), "{}", lower);
        }
    }
}
