use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::cose::{Algorithm, KeySet};
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};

use super::*;

fn trusted(s: &SoftSigner) -> KeySet {
    let mut k = KeySet::default();
    k.insert(thumbprint(&s.public_key()), s.public_key())
        .unwrap();
    k.allowed.insert(Algorithm::Ed25519);
    k
}

fn signed(s: &SoftSigner, statement: &Statement) -> Vec<u8> {
    sign_sign1(
        s,
        thumbprint(&s.public_key()),
        CONTENT_TYPE,
        &statement.to_bytes().unwrap(),
    )
    .unwrap()
}

// T20, CR-58: the binding key's Genesis statement verifies for its domain only
#[test]
fn the_genesis_statement_verifies_for_its_domain_only() {
    let (binding, _) = SoftSigner::generate_ed25519().unwrap();
    let statement = Statement {
        domain: Digest([7; 32]),
        genesis: Digest([7; 32]),
        issued_at: 1_000,
    };
    let bytes = signed(&binding, &statement);
    assert_eq!(
        verify(&PureBackend, &bytes, &trusted(&binding), &Digest([7; 32])).unwrap(),
        statement
    );
    assert_eq!(
        verify(&PureBackend, &bytes, &trusted(&binding), &Digest([9; 32])),
        Err(GenesisError::Domain)
    );
    let (other, _) = SoftSigner::generate_ed25519().unwrap();
    assert!(matches!(
        verify(&PureBackend, &bytes, &trusted(&other), &Digest([7; 32])),
        Err(GenesisError::Signature(_))
    ));
}

// CR-58: a payload with another shape is not a Genesis statement
#[test]
fn a_malformed_statement_is_rejected() {
    let extra = dcbor::encode(
        &Value::Map(vec![
            (Value::text("domain"), Digest([7; 32]).to_value()),
            (Value::text("genesis"), Digest([7; 32]).to_value()),
            (Value::text("issued_at"), Value::Unsigned(1)),
            (Value::text("x"), Value::Unsigned(1)),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    assert_eq!(Statement::from_bytes(&extra), Err(GenesisError::Malformed));
    assert_eq!(Statement::from_bytes(&[0xa0]), Err(GenesisError::Malformed));
}
