#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::sync::atomic::{AtomicU64, Ordering};

use suiss_crypto::signer::SoftSigner;

use super::*;

const NOW: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;

fn nonce() -> [u8; NONCE_LEN] {
    access_crypto::random::bytes::<NONCE_LEN>().unwrap()
}

fn keys(n: usize) -> Vec<SoftSigner> {
    (0..n)
        .map(|_| SoftSigner::generate_ed25519().unwrap().0)
        .collect()
}

fn roster(keys: &[SoftSigner], threshold: u8) -> Roster {
    Roster {
        threshold,
        members: keys
            .iter()
            .map(|k| match k.public_key() {
                PublicKey::Ed25519(p) => Member::Ed25519(p),
                _ => panic!("ed25519"),
            })
            .collect(),
    }
}

fn approved(mut p: Permit, r: &Roster, keys: &[SoftSigner], members: &[u8]) -> Permit {
    for m in members {
        p.approve_with(r, *m, &keys[usize::from(*m)]).unwrap();
    }
    p
}

fn started(keys: &[SoftSigner]) -> (Roster, Transcript) {
    let r = roster(keys, 2);
    let init = approved(
        Permit::draft(Op::Init(r.clone()), NOW, nonce()).unwrap(),
        &r,
        keys,
        &[0, 1, 2],
    );
    (r, Transcript::genesis(&init, NOW).unwrap())
}

fn activate(until: u64, at: u64) -> Permit {
    Permit::draft(
        Op::Activate {
            policy: policy_digest(&Policy::AUTHORITY),
            until,
        },
        at,
        nonce(),
    )
    .unwrap()
}

// CR-29, FA-6, OP-157 m.3 (x)
#[test]
fn a_permit_with_one_approval_is_refused() {
    let k = keys(3);
    let (r, mut t) = started(&k);
    let one = approved(activate(NOW + HOUR, NOW), &r, &k, &[1]);
    assert_eq!(one.quorate(&r), Err(CeremonyError::QuorumMissing));
    assert_eq!(
        t.seal(&one, NOW).map(|_| ()),
        Err(CeremonyError::QuorumMissing)
    );
    assert_eq!(
        CeremonyError::QuorumMissing.code(),
        "ceremony-quorum-missing"
    );
    let twice = approved(activate(NOW + HOUR, NOW), &r, &k, &[1, 1]);
    assert_eq!(twice.approvals.len(), 1, "one member counts once");
    assert_eq!(twice.quorate(&r), Err(CeremonyError::QuorumMissing));
    let two = approved(activate(NOW + HOUR, NOW), &r, &k, &[0, 2]);
    let s = t.seal(&two, NOW).unwrap();
    assert_eq!(s.len, 2);
    assert!(s.active(&policy_digest(&Policy::AUTHORITY), NOW).is_ok());
}

// CR-29, OP-157 m.3 (x)
#[test]
fn an_approval_by_someone_outside_the_roster_does_not_count() {
    let k = keys(3);
    let (r, _) = started(&k);
    let stranger = keys(1);
    let mut p = activate(NOW + HOUR, NOW);
    assert_eq!(
        p.approve_with(&r, 0, &stranger[0]),
        Err(CeremonyError::Approval)
    );
    assert_eq!(
        p.approve_with(&r, 7, &k[0]),
        Err(CeremonyError::Approval),
        "no member 7"
    );
    let mut forged = approved(activate(NOW + HOUR, NOW), &r, &k, &[0]);
    forged.approvals.push(Approval::Ed25519 {
        member: 1,
        sig: forged.approvals[0].clone().sig_bytes(),
    });
    assert_eq!(forged.quorate(&r), Err(CeremonyError::Approval));
}

impl Approval {
    fn sig_bytes(self) -> Vec<u8> {
        match self {
            Self::Ed25519 { sig, .. } | Self::Fido2 { sig, .. } => sig,
        }
    }
}

// CR-29, OP-157 m.3 (x)
#[test]
fn init_needs_every_member_and_a_sound_roster() {
    let k = keys(3);
    let r = roster(&k, 2);
    let two = approved(
        Permit::draft(Op::Init(r.clone()), NOW, nonce()).unwrap(),
        &r,
        &k,
        &[0, 1],
    );
    assert_eq!(
        Transcript::genesis(&two, NOW).map(|_| ()),
        Err(CeremonyError::QuorumMissing)
    );
    for bad in [roster(&k, 1), roster(&k, 4), roster(&keys(1), 1)] {
        assert_eq!(
            Permit::draft(Op::Init(bad), NOW, nonce()).map(|_| ()),
            Err(CeremonyError::Roster)
        );
    }
    let mut repeated = roster(&k, 2);
    repeated.members[2] = repeated.members[0].clone();
    assert_eq!(repeated.check(), Err(CeremonyError::Roster));
}

// CR-29, OP-157 m.3 (x)
#[test]
fn a_permit_lives_fifteen_minutes_and_once() {
    let k = keys(3);
    let (r, mut t) = started(&k);
    let p = approved(activate(NOW + HOUR, NOW), &r, &k, &[0, 1]);
    assert_eq!(p.not_after, NOW + PERMIT_MAX_MS);
    assert_eq!(
        t.seal(&p, NOW + PERMIT_MAX_MS + 1).map(|_| ()),
        Err(CeremonyError::Expired)
    );
    let mut long = p.clone();
    long.not_after = NOW + PERMIT_MAX_MS + 1;
    assert_eq!(t.seal(&long, NOW).map(|_| ()), Err(CeremonyError::Expired));
    long.not_after = NOW + PERMIT_MAX_MS - 1;
    assert_eq!(t.seal(&long, NOW).map(|_| ()), Err(CeremonyError::Approval));
    t.seal(&p, NOW + PERMIT_MAX_MS).unwrap();
    assert_eq!(
        t.seal(&p, NOW + PERMIT_MAX_MS).map(|_| ()),
        Err(CeremonyError::NonceReused)
    );
    assert_eq!(
        Permit::draft(
            Op::Activate {
                policy: policy_digest(&Policy::AUTHORITY),
                until: NOW + ACTIVATION_MAX_MS + 1,
            },
            NOW,
            nonce(),
        )
        .map(|_| ()),
        Err(CeremonyError::Window)
    );
}

// CR-29, OP-157 m.3 (x)
#[test]
fn a_transcript_reopens_only_on_an_unbroken_chain_from_its_pinned_genesis() {
    let k = keys(3);
    let (r, mut t) = started(&k);
    let genesis = t.state().genesis;
    t.seal(&approved(activate(NOW + HOUR, NOW), &r, &k, &[0, 1]), NOW)
        .unwrap();
    t.seal(
        &approved(
            Permit::draft(Op::Deactivate, NOW + 1, nonce()).unwrap(),
            &r,
            &k,
            &[1, 2],
        ),
        NOW + 1,
    )
    .unwrap();
    t.seal(
        &approved(activate(NOW + 2 * HOUR, NOW + 2), &r, &k, &[0, 2]),
        NOW + 2,
    )
    .unwrap();
    let bytes = t.bytes().to_vec();
    let reopened = Transcript::open(&bytes, &genesis).unwrap();
    assert_eq!(reopened.state(), t.state());
    let a = reopened.state().activation.unwrap();
    assert_eq!((a.until, a.seq), (NOW + 2 * HOUR, 3));

    for i in [0, bytes.len() / 3, bytes.len() / 2, bytes.len() - 1] {
        let mut broken = bytes.clone();
        broken[i] ^= 1;
        assert!(Transcript::open(&broken, &genesis).is_err(), "byte {i}");
    }
    let (_, other) = started(&keys(3));
    assert_eq!(
        Transcript::open(&bytes, &other.state().genesis).map(|_| ()),
        Err(CeremonyError::Chain)
    );
    let one_entry = Transcript::genesis(
        &approved(
            Permit::draft(Op::Init(r.clone()), NOW, nonce()).unwrap(),
            &r,
            &k,
            &[0, 1, 2],
        ),
        NOW,
    )
    .unwrap();
    let mut spliced = one_entry.bytes().to_vec();
    spliced.extend_from_slice(&bytes[first_entry_len(&bytes)..]);
    assert_eq!(
        Transcript::open(&spliced, &one_entry.state().genesis).map(|_| ()),
        Err(CeremonyError::Chain)
    );
    assert!(Transcript::open(&bytes[..bytes.len() - 1], &genesis).is_err());
    assert_eq!(
        Transcript::open(&[], &genesis).map(|_| ()),
        Err(CeremonyError::Chain)
    );
}

fn first_entry_len(bytes: &[u8]) -> usize {
    dcbor::decode_prefix(bytes, Limits::CEILING, &TagAllowlist::none())
        .unwrap()
        .1
}

// CR-29, OP-157 m.3 (x)
#[test]
fn a_permit_file_round_trips() {
    let k = keys(3);
    let (r, _) = started(&k);
    let p = approved(activate(NOW + HOUR, NOW), &r, &k, &[2, 0]);
    let back = Permit::decode(&p.encode().unwrap()).unwrap();
    assert_eq!(back, p);
    assert_eq!(
        back.approvals
            .iter()
            .map(Approval::member)
            .collect::<Vec<_>>(),
        [0, 2]
    );
    assert!(back.quorate(&r).is_ok());
}

fn der(fixed: &[u8]) -> Vec<u8> {
    let int = |x: &[u8]| {
        let x: Vec<u8> = x.iter().copied().skip_while(|b| *b == 0).collect();
        let mut out = Vec::new();
        if x.first().is_some_and(|b| b & 0x80 != 0) {
            out.push(0);
        }
        out.extend(x);
        let mut tlv = vec![0x02, u8::try_from(out.len()).unwrap()];
        tlv.extend(out);
        tlv
    };
    let mut body = int(&fixed[..32]);
    body.extend(int(&fixed[32..]));
    let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
    out.extend(body);
    out
}

fn assertion(key: &SoftSigner, rp_id: &str, flags: u8, p: &Permit) -> (Vec<u8>, Vec<u8>) {
    let mut auth_data = access_crypto::webauthn::sha256(rp_id.as_bytes()).to_vec();
    auth_data.push(flags);
    auth_data.extend_from_slice(&[0, 0, 0, 1]);
    let mut message = auth_data.clone();
    message.extend_from_slice(&access_crypto::webauthn::sha256(&p.signed_bytes().unwrap()));
    (auth_data, der(&key.sign(&message).unwrap()))
}

// CR-29, OP-157 m.3 (x), (bb)
#[test]
fn a_fido2_ceremony_key_approves_with_user_verification() {
    let ed = keys(2);
    let fido = SoftSigner::generate_p256().unwrap().0;
    let PublicKey::P256(sec1) = fido.public_key() else {
        panic!("p-256");
    };
    let mut r = roster(&ed, 2);
    r.members.push(Member::Fido2 {
        sec1,
        rp_id: String::from("ceremony.access.example"),
    });
    assert!(r.check().is_ok());
    let mut p = activate(NOW + HOUR, NOW);
    p.approve_with(&r, 0, &ed[0]).unwrap();
    for (rp, flags) in [
        ("ceremony.access.example", FLAG_UP),
        ("other.example", FLAG_UP | FLAG_UV),
    ] {
        let (auth_data, sig) = assertion(&fido, rp, flags, &p);
        assert_eq!(
            p.approve(
                &r,
                Approval::Fido2 {
                    member: 2,
                    auth_data,
                    sig
                }
            ),
            Err(CeremonyError::Approval),
            "{rp} {flags}"
        );
    }
    let (auth_data, sig) = assertion(&fido, "ceremony.access.example", FLAG_UP | FLAG_UV, &p);
    p.approve(
        &r,
        Approval::Fido2 {
            member: 2,
            auth_data,
            sig,
        },
    )
    .unwrap();
    assert!(p.quorate(&r).is_ok());
}

static CLOCK: AtomicU64 = AtomicU64::new(NOW);

fn clock() -> u64 {
    CLOCK.load(Ordering::SeqCst)
}

struct Soft;

impl Bindings for Soft {
    fn binding(&mut self, _: &Digest) -> Result<Box<dyn Signer + Send>, SignError> {
        Ok(Box::new(SoftSigner::generate_ed25519()?.0))
    }
}

// CR-29, FA-6, OP-157 m.3 (x)
#[test]
fn a_binding_key_is_neither_made_nor_used_outside_an_activation() {
    let k = keys(3);
    let (r, mut t) = started(&k);
    let gate = Gate::new(&Policy::AUTHORITY, clock);
    let mut bindings = Quorate::new(Soft, gate.clone());
    let domain = Digest([3; 32]);
    assert_eq!(gate.adopt(t.state()), Err(CeremonyError::Inactive));
    assert!(matches!(bindings.binding(&domain), Err(SignError::Key)));

    let other_policy = Permit::draft(
        Op::Activate {
            policy: policy_digest(&Policy::REALM),
            until: NOW + HOUR,
        },
        NOW,
        nonce(),
    )
    .unwrap();
    t.seal(&approved(other_policy, &r, &k, &[0, 1]), NOW)
        .unwrap();
    assert_eq!(gate.adopt(t.state()), Err(CeremonyError::Inactive));
    assert!(bindings.binding(&domain).is_err());

    t.seal(&approved(activate(NOW + HOUR, NOW), &r, &k, &[0, 1]), NOW)
        .unwrap();
    gate.adopt(t.state()).unwrap();
    let key = bindings.binding(&domain).unwrap();
    assert!(key.sign(b"excerpt").is_ok());
    CLOCK.store(NOW + HOUR, Ordering::SeqCst);
    assert!(matches!(key.sign(b"excerpt"), Err(SignError::Key)));
    assert!(bindings.binding(&domain).is_err());
    CLOCK.store(NOW, Ordering::SeqCst);
    assert!(key.sign(b"excerpt").is_ok());
    gate.close();
    assert!(key.sign(b"excerpt").is_err());
}
