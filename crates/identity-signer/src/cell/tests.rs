use suiss_crypto::envelope::SoftKek;

use super::*;
use crate::adapters::SealedFactory;

fn factory() -> SealedFactory<SoftKek> {
    SealedFactory::new(SoftKek::new("identity-kek", [5; 32]))
}

// OP-150, CR-21 m.3, T31: the stored key holds only sealed material under the identity KEK and
// loads back to the same key; a tampered public key or a cell name that is no key name is refused
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
