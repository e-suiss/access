#![allow(clippy::unwrap_used, reason = "test code")]

use core::fmt::Write as _;

use super::*;

fn example(id: &str) -> String {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../conformance/cddl/examples/identity-claims.json"
    ))
    .unwrap();
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()["cbor"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn binding(class: IdentityClass, value: Value) -> String {
    let bytes = dcbor::encode(
        &Value::Array(vec![Value::text(class.name()), value]),
        Limits::CEILING,
    )
    .unwrap();
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

// OP-153 m.3 (b), (c), (o), (q), L2-CLB-1
#[test]
fn every_body_matches_its_cddl_example() {
    let recovery = RecoveryResult {
        party: Id([2; 16]),
        successor: [9; 32],
        attempt: Id([5; 16]),
        path: RecoveryPath::RegisteredCode,
        achieved_aal: 2,
    };
    assert_eq!(
        binding(IdentityClass::RecoveryResult, recovery.to_value()),
        example("recovery-result")
    );
    let domain = DomainVerification {
        organization: Id([6; 16]),
        domain: String::from("acme.example"),
        method: VerificationMethod::DnsTxt,
        verified_at: 1_767_225_000_000,
    };
    assert_eq!(
        binding(IdentityClass::DomainVerification, domain.to_value()),
        example("domain-verification")
    );
    let member = Membership {
        organization: Id([6; 16]),
        member: Id([2; 16]),
        root: true,
        since: 1_767_225_000_000,
    };
    assert_eq!(
        binding(IdentityClass::Membership, member.to_value()),
        example("membership-owner")
    );
    let guardian = Guardianship {
        guardian: Id([2; 16]),
        ward: Id([3; 16]),
        basis: GuardianshipBasis::Parent,
        until: Some(1_893_456_000_000),
    };
    assert_eq!(
        binding(IdentityClass::Guardianship, guardian.to_value()),
        example("guardianship")
    );
    assert_eq!(
        binding(
            IdentityClass::AgeRange,
            Value::text(AgeRange::Age16To17.name())
        ),
        example("age-range")
    );
}

// L2-CLB-1, L2-CLB-2
#[test]
fn the_class_is_inside_the_digest() {
    let body = Membership {
        organization: Id([6; 16]),
        member: Id([2; 16]),
        root: false,
        since: 1,
    }
    .to_value();
    assert_ne!(
        digest(IdentityClass::Membership, &body).unwrap(),
        digest(IdentityClass::Guardianship, &body).unwrap()
    );
    for c in IdentityClass::ALL {
        assert_eq!(IdentityClass::parse(c.name()), Some(c));
        assert!(access_kernel::claim::body::Class::parse(c.name()).is_none());
    }
    assert!(!IdentityClass::AgeRange.has_body());
}
