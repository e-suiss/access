#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

use super::*;

const NOW: u64 = 1_800_000_000_000;

fn nonce() -> [u8; 16] {
    crate::random::bytes::<16>().unwrap()
}

fn keys(n: usize) -> (Vec<OperatorKey>, KeySet) {
    let mut text = String::from("generation 1\nthreshold 2\n");
    let mut out = Vec::new();
    for i in 0..n {
        let (k, _) = OperatorKey::generate().unwrap();
        let _ = writeln!(text, "ed25519 k{i} {}", hex(&k.public()));
        out.push(k);
    }
    (out, KeySet::parse(&text).unwrap())
}

fn doc(ops: &[&str]) -> Document {
    Document::new(
        "eu-1",
        ops.iter().map(|o| Op::parse(o).unwrap()).collect(),
        nonce(),
        NOW,
        NOW + MAX_WINDOW_MS,
    )
    .unwrap()
}

// CMP-25, §17.7.3
#[test]
fn cmp_25_two_of_three_verifies_offline() {
    let (k, set) = keys(3);
    let mut d = doc(&["epoch.floor", "leader.unhealthy"]);
    d.approve("k0", &k[0]).unwrap();
    assert_eq!(d.verify(&set, "eu-1", NOW), Err(BreakGlassError::Quorum));
    d.approve("k2", &k[2]).unwrap();
    let back = Document::decode(&d.encode().unwrap()).unwrap();
    assert_eq!(back, d);
    assert_eq!(back.verify(&set, "eu-1", NOW + 1).unwrap(), ["k0", "k2"]);
}

// CMP-25
#[test]
fn cmp_25_repeated_unknown_or_forged_approvals_are_refused() {
    let (k, set) = keys(3);
    let (stranger, _) = OperatorKey::generate().unwrap();
    let mut twice = doc(&["health"]);
    twice.approve("k0", &k[0]).unwrap();
    twice.approve("k0", &k[0]).unwrap();
    assert_eq!(
        twice.verify(&set, "eu-1", NOW),
        Err(BreakGlassError::Approval)
    );
    let mut forged = doc(&["health"]);
    forged.approve("k0", &k[0]).unwrap();
    forged.approve("k1", &stranger).unwrap();
    assert_eq!(
        forged.verify(&set, "eu-1", NOW),
        Err(BreakGlassError::Approval)
    );
    let mut unknown = doc(&["health"]);
    unknown.approve("k0", &k[0]).unwrap();
    unknown.approve("zz", &stranger).unwrap();
    assert_eq!(
        unknown.verify(&set, "eu-1", NOW),
        Err(BreakGlassError::Approval)
    );
    let mut changed = doc(&["health"]);
    changed.approve("k0", &k[0]).unwrap();
    changed.approve("k1", &k[1]).unwrap();
    changed.ops = vec![Op::EpochFloor];
    assert_eq!(
        changed.verify(&set, "eu-1", NOW),
        Err(BreakGlassError::Approval)
    );
}

// §17.7.3, OP-57 m.9
#[test]
fn op_46_window_and_cell_bind_the_document() {
    assert_eq!(
        Document::new(
            "eu-1",
            vec![Op::Health],
            nonce(),
            NOW,
            NOW + MAX_WINDOW_MS + 1
        ),
        Err(BreakGlassError::Window)
    );
    assert_eq!(
        Document::new("eu-1", vec![], nonce(), NOW, NOW + 1),
        Err(BreakGlassError::UnknownOp)
    );
    let (k, set) = keys(3);
    let mut d = doc(&["health"]);
    d.approve("k0", &k[0]).unwrap();
    d.approve("k1", &k[1]).unwrap();
    assert!(d.verify(&set, "eu-1", NOW + MAX_WINDOW_MS - 1).is_ok());
    assert_eq!(
        d.verify(&set, "eu-1", NOW + MAX_WINDOW_MS),
        Err(BreakGlassError::NotNow)
    );
    assert_eq!(
        d.verify(&set, "eu-1", NOW - 1),
        Err(BreakGlassError::NotNow)
    );
    assert_eq!(d.verify(&set, "eu-2", NOW), Err(BreakGlassError::Cell));
}

// G63, SI-22
#[test]
fn g63_operations_are_closed() {
    for op in [
        "config.read",
        "health",
        "epoch.floor",
        "leader.unhealthy",
        "leader.healthy",
        "flag:login.banner:on",
    ] {
        assert_eq!(Op::parse(op).unwrap().name(), op);
    }
    for bad in [
        "grant.issue",
        "policy.set",
        "user.read",
        "flag:Bad:on",
        "flag:x:maybe",
        "flag::on",
    ] {
        assert_eq!(Op::parse(bad), Err(BreakGlassError::UnknownOp), "{bad}");
    }
    assert!(!Op::Health.directs() && !Op::ConfigRead.directs() && Op::EpochFloor.directs());
}

// CMP-25
#[test]
fn cmp_25_key_sets_need_a_real_quorum() {
    let (k, _) = keys(2);
    let line = |i: usize| format!("ed25519 k{i} {}\n", hex(&k[i].public()));
    let two = format!("generation 1\n{}{}", line(0), line(1));
    assert_eq!(KeySet::parse(&two).unwrap().threshold, 2);
    for bad in [
        format!("generation 1\nthreshold 1\n{}{}", line(0), line(1)),
        format!("generation 1\nthreshold 3\n{}{}", line(0), line(1)),
        format!("generation 1\n{}", line(0)),
        format!("{}{}", line(0), line(1)),
        format!("generation 1\n{}{}", line(0), line(0)),
        format!(
            "generation 1\n{}ed25519 other {}\n",
            line(0),
            hex(&k[0].public())
        ),
    ] {
        assert!(KeySet::parse(&bad).is_err(), "{bad}");
    }
    let a = KeySet::parse(&two).unwrap();
    assert!(a.shares_key_with(&a));
    let (_, b) = keys(2);
    assert!(!a.shares_key_with(&b));
}

struct SecurityKey {
    pair: EcdsaKeyPair,
}

impl SecurityKey {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        Self {
            pair: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
                .unwrap(),
        }
    }

    fn public(&self) -> Vec<u8> {
        self.pair.public_key().as_ref().to_vec()
    }

    fn assert(&self, rp: &str, challenge: &str, flags: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut auth = sha256(rp.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend(7_u32.to_be_bytes());
        let client =
            format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"x\"}}")
                .into_bytes();
        let mut message = auth.clone();
        message.extend(sha256(&client));
        let sig = self.pair.sign(&SystemRandom::new(), &message).unwrap();
        (auth, client, sig.as_ref().to_vec())
    }
}

// CMP-25, §17.7.3
#[test]
fn cmp_25_fido2_assertions_verify_offline() {
    let k = [OperatorKey::generate().unwrap().0];
    let a = SecurityKey::new();
    let b = SecurityKey::new();
    let set = KeySet::parse(&format!(
        "generation 4\nthreshold 2\nrp breakglass.eu-1\nes256 a {}\nes256 b {}\ned25519 k0 {}\n",
        hex(&a.public()),
        hex(&b.public()),
        hex(&k[0].public())
    ))
    .unwrap();
    let mut d = doc(&["leader.unhealthy"]);
    let challenge = d.challenge().unwrap();
    let (auth, client, sig) = a.assert("breakglass.eu-1", &challenge, 0x05);
    d.approvals.push(Approval::Fido2 {
        key: "a".into(),
        authenticator_data: auth,
        client_data_json: client,
        sig,
    });
    d.approve("k0", &k[0]).unwrap();
    let back = Document::decode(&d.encode().unwrap()).unwrap();
    assert_eq!(back.verify(&set, "eu-1", NOW).unwrap(), ["a", "k0"]);
    for (rp, ch, flags) in [
        ("other", challenge.as_str(), 0x05),
        ("breakglass.eu-1", "AAAA", 0x05),
        ("breakglass.eu-1", challenge.as_str(), 0x01),
    ] {
        let mut bad = doc(&["leader.unhealthy"]);
        bad.nonce = d.nonce;
        let (auth, client, sig) = b.assert(rp, ch, flags);
        bad.approvals.push(Approval::Fido2 {
            key: "b".into(),
            authenticator_data: auth,
            client_data_json: client,
            sig,
        });
        bad.approve("k0", &k[0]).unwrap();
        assert_eq!(
            bad.verify(&set, "eu-1", NOW),
            Err(BreakGlassError::Approval)
        );
    }
}

// OP-157 m.3 (j)
#[test]
fn op_157_directives_are_signed() {
    let (key, seed) = OperatorKey::generate().unwrap();
    let again = OperatorKey::from_hex(&seed).unwrap();
    assert_eq!(again.public(), key.public());
    let (other, _) = OperatorKey::generate().unwrap();
    let d = Directive {
        cell: "eu-1".into(),
        seq: 3,
        op: Op::EpochFloor,
        at_ms: NOW,
        document: sha256(b"doc"),
    };
    let file = d.sign(&key).unwrap();
    assert_eq!(Directive::verify(&file, &key.public()).unwrap(), d);
    assert_eq!(
        Directive::verify(&file, &other.public()),
        Err(BreakGlassError::Signature)
    );
    let mut tampered = file.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(Directive::verify(&tampered, &key.public()).is_err());
    let read = Directive {
        op: Op::Health,
        ..d
    };
    assert_eq!(read.sign(&key), Err(BreakGlassError::UnknownOp));
    assert!(format!("{key:?}").contains("redacted"));
}

// OP-157 m.3 (j)
#[test]
fn op_157_directives_fold_in_sequence() {
    let at = |seq, op: &str, at_ms| Directive {
        cell: "eu-1".into(),
        seq,
        op: Op::parse(op).unwrap(),
        at_ms,
        document: sha256(b"d"),
    };
    let s = DirectiveState::fold(&[
        at(4, "leader.healthy", 40),
        at(1, "epoch.floor", 90),
        at(3, "leader.unhealthy", 30),
        at(2, "flag:a:on", 20),
        at(5, "epoch.floor", 50),
        at(6, "flag:a:off", 60),
        at(7, "flag:b:on", 70),
    ]);
    assert_eq!(s.epoch_floor_ms, Some(90));
    assert!(!s.leader_unhealthy);
    assert!(!s.flag("a") && s.flag("b") && !s.flag("c"));
    assert_eq!(s.seq, 7);
    assert_eq!(DirectiveState::fold(&[]), DirectiveState::default());
}
