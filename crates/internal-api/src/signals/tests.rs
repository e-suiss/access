use super::*;

fn vectors() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/cddl/examples/product-seam.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..=i.saturating_add(1)], 16).unwrap())
        .collect()
}

// OP-156 m.3 (r), m.6 (h), L2-CLB-1
#[test]
fn signal_bodies_follow_the_seam_vectors() {
    let v = vectors();
    let mut seen = 0;
    for case in v["cases"].as_array().unwrap() {
        let edn = case["edn"].as_str().unwrap();
        let Some(class) = CLASSES
            .iter()
            .find(|c| edn.starts_with(&format!("[\"{c}\"")))
        else {
            continue;
        };
        seen += 1;
        let valid = case["valid"].as_bool().unwrap();
        let Some(cbor) = case["cbor"].as_str() else {
            assert!(!valid, "{edn}");
            continue;
        };
        let tagged = dcbor::decode(&hex(cbor), Limits::CEILING).unwrap();
        let Value::Array(items) = &tagged else {
            panic!("{edn}");
        };
        let s = Signal::from_value(class, &items[1]).unwrap();
        assert_eq!(s.class(), *class);
        let body = dcbor::encode(&items[1], Limits::CEILING).unwrap();
        assert_eq!(s.to_bytes(), body, "{edn}");
        assert_eq!(
            read(class, Some(&s.digest()), Some(&body)),
            Reading::Read(s.clone())
        );
    }
    assert!(seen >= 7, "{seen}");
}

// CI-2, OP-156 m.3 (r)
#[test]
fn a_risk_level_never_allows_and_an_unreadable_one_is_critical() {
    assert_eq!(RiskLevel::parse("allow"), None);
    assert_eq!(RiskLevel::parse("none"), None);
    assert!(RiskLevel::Low < RiskLevel::Critical);
    assert_eq!(risk_of(&Reading::Unreadable), RiskLevel::Critical);
    let low = Signal::Risk(RiskExternal {
        level: RiskLevel::Low,
        reason_class: String::from("none"),
    });
    assert!(low.assurance().is_empty());
    assert_eq!(
        read(RISK_EXTERNAL, Some(&low.digest()), None),
        Reading::Unreadable
    );
    assert_eq!(
        read(RISK_EXTERNAL, Some(&[0; 32]), Some(&low.to_bytes())),
        Reading::Unreadable
    );
    assert_eq!(
        risk_of(&read(
            RISK_EXTERNAL,
            Some(&low.digest()),
            Some(&low.to_bytes())
        )),
        RiskLevel::Low
    );
}

// IDP-34, OP-156 m.3 (r)
#[test]
fn a_proofing_level_is_the_kernel_loa_dimension() {
    let p = |level| {
        Signal::Proofing(IdentityProofing {
            provider: String::from("idv.example"),
            method: Method::Document,
            level,
            verified_at: 1,
        })
    };
    assert_eq!(p(ProofingLevel::Ial(2)).assurance()["loa_eidas"], 2);
    assert_eq!(p(ProofingLevel::Eidas(3)).assurance()["loa_eidas"], 3);
    let round = p(ProofingLevel::Eidas(2));
    assert_eq!(
        Signal::from_bytes(IDENTITY_PROOFING, &round.to_bytes()).unwrap(),
        round
    );
    assert!(
        Signal::from_value(
            IDENTITY_PROOFING,
            &map(vec![
                ("provider", Value::text("x")),
                ("method", Value::text("selfie")),
                ("ial", Value::Unsigned(2)),
                ("verified_at", Value::Unsigned(1)),
            ])
        )
        .is_err()
    );
}

// §8.10, OP-156 m.3 (r)
#[test]
fn posture_reads_worst_first() {
    let p = |managed, compliant| {
        Posture::of(&Reading::Read(Signal::Posture(PostureMdm {
            managed,
            compliant,
            provider: String::from("acme-mdm"),
            statement: String::from("Disk encrypted"),
        })))
    };
    assert_eq!(p(true, true), Posture::Compliant);
    assert_eq!(p(false, true), Posture::Unmanaged);
    assert_eq!(p(true, false), Posture::Noncompliant);
    assert_eq!(Posture::of(&Reading::Unreadable), Posture::Noncompliant);
    assert!(Posture::Compliant < Posture::Noncompliant);
    assert!(!is_ref("Acme MDM"));
    assert!(is_ref("acme-dlp"));
}
