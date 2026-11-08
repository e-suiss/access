use suiss_crypto::envelope::SoftKek;

use super::*;
use crate::adapters::SealedFactory;

fn factory() -> SealedFactory<SoftKek> {
    SealedFactory::new(SoftKek::new("identity-kek", [5; 32]))
}

// OP-150, CR-21 m.3, T31
#[test]
fn the_cell_key_is_sealed_and_restored() {
    let mut f = factory();
    let key = CellKey::generate("cell-a", &mut f).unwrap();
    let stored = key.stored().unwrap();
    let again = CellKey::restore("cell-a", &stored, &mut f).unwrap();
    assert_eq!(again.vkey(), key.vkey());
    assert_eq!(again.origin(), "cell-a/identity-audit");
    let v = dcbor::decode(&stored, Limits::CEILING).unwrap();
    assert_eq!(v.get("label"), Some(&Value::text(LABEL)));
    let mut other = CellKey::generate("cell-a", &mut f)
        .unwrap()
        .stored()
        .unwrap();
    let w = dcbor::decode(&other, Limits::CEILING).unwrap();
    let swapped = Value::Map(vec![
        (Value::text("label"), Value::text(LABEL)),
        (Value::text("origin"), Value::text("cell-a/identity-audit")),
        (Value::text("key"), v.get("key").unwrap().clone()),
        (Value::text("sealed"), w.get("sealed").unwrap().clone()),
    ]);
    other = dcbor::encode(&swapped, Limits::CEILING).unwrap();
    assert_eq!(
        CellKey::restore("cell-a", &other, &mut f).err(),
        Some(CellError::Stored)
    );
    assert_eq!(
        CellKey::generate("a cell", &mut f).err(),
        Some(CellError::Name)
    );
}

// OP-44, OP-39
#[test]
fn the_cell_key_signs_its_two_chains_only() {
    let mut f = factory();
    let key = CellKey::generate("cell-a", &mut f).unwrap();
    let operational = operational_origin(key.origin()).unwrap();
    assert_eq!(operational, "cell-a/authority-operational");
    let body = |origin: &str| {
        Checkpoint {
            origin: origin.to_owned(),
            size: 1,
            root: [7; 32],
            extensions: vec![String::from("issued_at 1")],
        }
        .to_body()
        .unwrap()
    };
    assert!(key.sign(&body(key.origin())).is_ok());
    assert!(key.sign(&body(&operational)).is_ok());
    assert_eq!(
        key.sign(&body("cell-b/authority-operational")).err(),
        Some(SignerError::Note)
    );
    assert_eq!(operational_origin("cell-a/other"), None);
    assert_eq!(operational_origin("identity-audit"), None);
}

// OP-152 m.7 (d)
#[test]
fn the_cell_key_signs_realm_trees_under_its_own_log_only() {
    let mut f = factory();
    let key = CellKey::generate("cell-a", &mut f).unwrap();
    let realm = realm_origin(key.origin(), &[0xab; 16]);
    assert_eq!(
        realm,
        "cell-a/identity-audit/realm/abababababababababababababababab"
    );
    let body = |origin: &str| {
        Checkpoint {
            origin: origin.to_owned(),
            size: 1,
            root: [7; 32],
            extensions: vec![String::from("issued_at 1")],
        }
        .to_body()
        .unwrap()
    };
    assert!(key.sign(&body(&realm)).is_ok());
    for other in [
        String::from("cell-b/identity-audit/realm/abababababababababababababababab"),
        format!("{}/realm/ABABABABABABABABABABABABABABABAB", key.origin()),
        format!("{}/realm/abab", key.origin()),
        format!("{}/realms/abababababababababababababababab", key.origin()),
        format!("{}/realm/abababababababababababababababab/x", key.origin()),
    ] {
        assert_eq!(
            key.sign(&body(&other)).err(),
            Some(SignerError::Note),
            "{other}"
        );
    }
}
