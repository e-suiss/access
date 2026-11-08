//! Known-answer vectors from independent implementations: OpenBSD and crypt_blowfish bcrypt,
//! Apache htpasswd, OpenSSL passwd, Python hashlib, RFC 1321, RFC 7914 and the firebase/scrypt
//! README.

// TN-85, OP-153 m.11 (h)

use core::fmt::Write as _;

use super::*;

fn ok(stored: &str, password: &str) -> bool {
    LegacyHash::parse(stored)
        .unwrap()
        .verify(&Transform::identity(), password.as_bytes())
        .unwrap()
}

fn with(stored: &str, spec: &str, password: &str) -> bool {
    LegacyHash::parse(stored)
        .unwrap()
        .verify(&Transform::parse(spec).unwrap(), password.as_bytes())
        .unwrap()
}

fn hexs(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut acc, x| {
        let _ = write!(acc, "{x:02x}");
        acc
    })
}

#[test]
fn blowfish_tables_are_pi() {
    assert_eq!(blowfish_tables::P[0], 0x243f_6a88);
    assert_eq!(blowfish_tables::P[1], 0x85a3_08d3);
    assert_eq!(blowfish_tables::P[17], 0x8979_fb1b);
    assert_eq!(blowfish_tables::S[0][0], 0xd131_0ba6);
    assert_eq!(blowfish_tables::S[3][255], 0x3ac3_72e6);
}

#[test]
fn md5_rfc1321() {
    assert_eq!(hexs(&md5::md5(&[b""])), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(
        hexs(&md5::md5(&[b"abc"])),
        "900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        hexs(&md5::md5(&[
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        ])),
        "57edf4a22be3c955ac49da2e2107b67a"
    );
    assert_eq!(
        hexs(&md5::md5(&[&[b'a'; 1000]])),
        "cabe45dcc9ae5b66ba86600cca6b8ba8"
    );
}

#[test]
fn scrypt_rfc7914() {
    let mut out = [0u8; 64];
    scrypt::scrypt(b"", b"", 16, 1, 1, &mut out).unwrap();
    assert_eq!(
        hexs(&out),
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
    );
    scrypt::scrypt(b"password", b"NaCl", 1024, 8, 16, &mut out).unwrap();
    assert_eq!(
        hexs(&out),
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
    );
}

#[test]
fn bcrypt_openbsd_vectors() {
    assert!(ok(
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
        "U*U"
    ));
    assert!(ok(
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
        "U*U*"
    ));
    assert!(ok(
        "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
        "U*U*U"
    ));
    assert!(!ok(
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
        "U*U*"
    ));
}

#[test]
fn bcrypt_reads_72_bytes() {
    let h = "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui";
    let long = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored";
    assert!(ok(h, long));
    assert!(ok(h, &long[..72]));
    assert!(!ok(h, &long[..71]));
}

#[test]
fn bcrypt_htpasswd_2y() {
    assert!(ok(
        "$2y$05$5Yae6fDxCZ5mN4RmEc1WG.UqRO9krsR53vy51plVko7oUW/zQkKU2",
        "correct horse"
    ));
    assert!(!ok(
        "$2y$05$5Yae6fDxCZ5mN4RmEc1WG.UqRO9krsR53vy51plVko7oUW/zQkKU2",
        "correct horsf"
    ));
    assert!(ok(
        "$2y$04$f6MrOb6NHMcLUGuRiMHRu.yIIzG4PqeuvXSNbhwLviy1f94c8SLc2",
        ""
    ));
}

#[test]
fn bcrypt_over_sha256_hex_is_data() {
    let h = "$2y$04$LZFwi3ljXa8cWF6mlsXfc.d05dS1gBtafe.SHmiWfFy2eBoe3Ryam";
    assert!(with(h, "prehash=sha256-hex", "U*U"));
    assert!(!with(h, "prehash=sha256-hex", "U*U*"));
    assert!(!ok(h, "U*U"));
}

#[test]
fn scrypt_phc_and_kratos_forms() {
    let phc = "$scrypt$ln=10,r=8,p=1$c2FsdHNhbHRzYWx0$JLoeRlAiVzz/fmBbrb3a7QkuecDu7wE6R0zHHE5DC7g";
    let kratos =
        "$scrypt$ln=1024,r=8,p=1$c2FsdHNhbHRzYWx0$JLoeRlAiVzz/fmBbrb3a7QkuecDu7wE6R0zHHE5DC7g=";
    assert!(ok(phc, "correct horse"));
    assert!(ok(kratos, "correct horse"));
    assert!(!ok(phc, "correct horsf"));
}

#[test]
fn firebase_scrypt_readme_vector() {
    let h = "$firescrypt$ln=14,r=8,p=1$42xEC+ixf3L2lw==$lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==$Bw==$jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
    assert!(ok(h, "user1password"));
    assert!(!ok(h, "user2password"));
    assert_eq!(LegacyHash::parse(h).unwrap().scheme(), "firebase-scrypt");
}

#[test]
fn pbkdf2_vectors() {
    for (h, scheme) in [
        (
            "$pbkdf2-sha1$i=1000,l=20$MDEyMzQ1Njc4OWFiY2RlZg$KwthxV9WuFwB/bguLKmJmXZCg0c",
            "pbkdf2-sha1",
        ),
        (
            "$pbkdf2-sha256$i=1000,l=32$MDEyMzQ1Njc4OWFiY2RlZg$ueBbYQVkDHSR2wInfuEbu55EoAdDx3ozbiXKophExIU",
            "pbkdf2-sha256",
        ),
        (
            "$pbkdf2-sha512$i=1000,l=64$MDEyMzQ1Njc4OWFiY2RlZg$Xg4EL7+rA8+/LUT63Xnyx+M07DB00Ik0jgihW+CwUKZ/i0YJ7ls5kTqGHv6FnbyBgjbhv/S9rJboL4EAjFPYtw",
            "pbkdf2-sha512",
        ),
    ] {
        assert!(ok(h, "hunter22"), "{scheme}");
        assert!(!ok(h, "hunter23"), "{scheme}");
        assert_eq!(LegacyHash::parse(h).unwrap().scheme(), scheme);
    }
    let passlib = "$pbkdf2-sha256$2900$..8.ABE$EO3WweK5UqSXYbdclMrrmzjtwCAn1Df7hBN2z9WvQSY";
    assert!(ok(passlib, "passlib"));
    assert!(!ok(passlib, "passlic"));
}

#[test]
fn pepper_suffix_is_data() {
    let h = "$pbkdf2-sha256$i=1000,l=32$MDEyMzQ1Njc4OWFiY2RlZg$B7UL07Ke9V9tCxObNbJG8gF+0F3/tseMeqya/XIiF9U";
    assert!(with(h, "pepper=suffix:cGVwcGVyIQ==", "hunter22"));
    assert!(!with(h, "pepper=prefix:cGVwcGVyIQ==", "hunter22"));
    assert!(!ok(h, "hunter22"));
}

#[test]
fn hmac_pepper_is_data() {
    let h = "$sha256$2HtFj/UT/UMX0qiUYqcvxJwIPkHYuFOweMl3CRsvNDo=";
    assert!(with(h, "pepper=hmac-sha256:aG1hYy1rZXk=", "test"));
    assert!(!with(h, "pepper=hmac-sha256:b3RoZXIta2V5", "test"));
}

#[test]
fn md5_crypt_openssl() {
    assert!(ok("$1$saltstr$QM9HTGmcCulEKt42JFhZ/.", "Hello world!"));
    assert!(!ok("$1$saltstr$QM9HTGmcCulEKt42JFhZ/.", "Hello world?"));
    assert!(ok("$1$x$fwjfZtMwarkdetsjiQreU1", ""));
}

#[test]
fn sha_crypt_openssl() {
    assert!(ok(
        "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
        "Hello world!"
    ));
    assert!(ok(
        "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
        "Hello world!"
    ));
    assert!(ok(
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
        "Hello world!"
    ));
    assert!(ok(
        "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
        "a very much longer text to encrypt.  This one even stretches over morethan one line."
    ));
    assert!(!ok(
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
        "Hello world?"
    ));
}

#[test]
fn ldap_vectors() {
    for h in [
        "{SSHA}V6IyJTCM7M2M65dpPMf/O4Xfm2pOYUNsTmFDbA==",
        "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=",
        "{SSHA256}uyA1OVzWi/AamophRYOwB9wS+/y2Tyl6nJc89YXo9yhOYUNsTmFDbA==",
        "{SSHA512}Ky6eTk09GonmlKsbqtLNBwH533kx9brYgkKY7aHiGGynuO8SOssLFW11XAZY5R9FyvdrHHSRsqwTk/lMrU2qYk5hQ2xOYUNs",
        "{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ==",
        "{SMD5}nGuslPbhqxyhe+cw9BcTPU5hQ2xOYUNs",
    ] {
        assert!(ok(h, "secret"), "{h}");
        assert!(!ok(h, "secreT"), "{h}");
    }
}

#[test]
fn kratos_pattern_vectors() {
    assert!(ok(
        "$md5$pf=e1NBTFR9e1BBU1NXT1JEfQ==$MTIz$q+RdKCgc+ipCAcm5ChQwlQ==",
        "test"
    ));
    assert!(ok("$md5$CY9rzUYh03PK3k6DJie09g==", "test"));
    assert!(ok(
        "$sha256$pf=e1BBU1NXT1JEfS17U0FMVH0=$cGVwYQ==$WYB1c1T40SUivWUQGT1nqO5SOlACx8J8XcGKj4A7Hfo=",
        "test"
    ));
    assert!(ok("$sha1$qUqP5cyxm6YcTAhz05Hph5gvu9M=", "test"));
    assert!(ok(
        "$sha512$pf=e1NBTFR9e1BBU1NXT1JEfQ==$eA==$L27HldYDIdCNXXpGM3oAb18kDO75x3Ym71ND6ImYqyTU/BVD8849H9YpsJtkojq11Brhwv1cghDGxG20rStvwQ==",
        "test"
    ));
    assert!(!ok("$md5$CY9rzUYh03PK3k6DJie09g==", "tesT"));
}

#[test]
fn parse_refusals() {
    assert_eq!(
        LegacyHash::parse("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA").unwrap_err(),
        LegacyHashError::Argon2
    );
    assert!(is_argon2("$argon2i$v=19$m=1,t=1,p=1$x$y"));
    assert_eq!(
        LegacyHash::parse("5f4dcc3b5aa765d61d8327deb882cf99").unwrap_err(),
        LegacyHashError::Unknown
    );
    assert_eq!(
        LegacyHash::parse("$9$whatever").unwrap_err(),
        LegacyHashError::Unknown
    );
    assert_eq!(
        LegacyHash::parse("$2b$21$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")
            .unwrap_err(),
        LegacyHashError::Bound
    );
    assert_eq!(
        LegacyHash::parse("$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOe")
            .unwrap_err(),
        LegacyHashError::Malformed
    );
    assert_eq!(
        LegacyHash::parse("$scrypt$ln=20,r=8,p=1$c2FsdA$aGFzaA").unwrap_err(),
        LegacyHashError::Bound
    );
    assert_eq!(
        LegacyHash::parse("$scrypt$ln=10,r=8,p=17$c2FsdA$aGFzaA").unwrap_err(),
        LegacyHashError::Bound
    );
    assert_eq!(
        LegacyHash::parse("$pbkdf2-sha256$i=10000001$c2FsdA$aGFzaA").unwrap_err(),
        LegacyHashError::Bound
    );
    assert_eq!(
        LegacyHash::parse("$6$rounds=10000001$salt$x").unwrap_err(),
        LegacyHashError::Bound
    );
    assert_eq!(
        LegacyHash::parse("{SSHA}5en6G6MezRroT3XKqkdPOmY/BfQ=").unwrap_err(),
        LegacyHashError::Malformed
    );
    assert_eq!(
        LegacyHash::parse("$pbkdf2-sha256$i=1000$c2Fs!A$aGFzaA").unwrap_err(),
        LegacyHashError::Malformed
    );
}

#[test]
fn transform_spec() {
    assert_eq!(Transform::parse("").unwrap().prehash, Prehash::None);
    let t = Transform::parse("pepper=suffix:cGVwcGVyIQ==; prehash=sha256-hex").unwrap();
    assert_eq!(t.prehash, Prehash::Sha256Hex);
    assert_eq!(t.pepper.as_ref().map(Pepper::kind), Some("suffix"));
    assert_eq!(format!("{:?}", t.pepper), "Some(Pepper::suffix(..))");
    for bad in [
        "prehash=sha3",
        "pepper=suffix:",
        "pepper=zz:cGVw",
        "prehash=none;prehash=none",
        "x=y",
        "prehash",
    ] {
        assert_eq!(
            Transform::parse(bad).unwrap_err(),
            LegacyHashError::Transform,
            "{bad}"
        );
    }
}

#[test]
fn schemes_fit_the_algorithm_column() {
    for h in [
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
        "$1$saltstr$QM9HTGmcCulEKt42JFhZ/.",
        "{SSHA512}Ky6eTk09GonmlKsbqtLNBwH533kx9brYgkKY7aHiGGynuO8SOssLFW11XAZY5R9FyvdrHHSRsqwTk/lMrU2qYk5hQ2xOYUNs",
        "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
    ] {
        let label = format!("legacy-{}", LegacyHash::parse(h).unwrap().scheme());
        assert!(label.len() <= 32);
        assert!(
            label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
        );
        assert!(!format!("{:?}", LegacyHash::parse(h).unwrap()).contains('$'));
    }
}
