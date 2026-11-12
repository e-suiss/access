use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::aws::AwsLcBackend;
use suiss_crypto::cose::{Algorithm, PublicKey};
use suiss_crypto::signer::{MlDsaSigner, Signer as _, SoftSigner, sign_sign1};

use super::*;

const BODY: &str = "origin\n2\nAAAA\n";

fn pq_witness(name: &str, independent: bool) -> (Witness, MlDsaSigner) {
    let (signer, _) = MlDsaSigner::generate(Algorithm::MlDsa65).unwrap();
    let w = Witness::new(
        name.to_owned(),
        signer.public_key(),
        Algorithm::MlDsa65,
        String::from("Example Witness Ltd"),
        independent,
    );
    (w, signer)
}

fn cosign(name: &str, signer: &MlDsaSigner, body: &str, at: u64) -> PqCosign {
    let kid = thumbprint(&signer.public_key());
    PqCosign {
        name: name.to_owned(),
        timestamp: at,
        sign1: sign_sign1(
            signer,
            kid,
            COSIGN_CONTENT_TYPE,
            &PqCosign::message(body, at),
        )
        .unwrap(),
    }
}

// RB-0, OP-159 m.3 (g), (j)
#[test]
fn only_an_independent_declared_ml_dsa_witness_may_cosign_a_re_anchor() {
    let (classic, _) = SoftSigner::generate_ed25519().unwrap();
    let mut d = Declarations::default();
    d.witnesses.push(Witness::new(
        String::from("w-classic"),
        classic.public_key(),
        Algorithm::Ed25519,
        String::from("Example Witness Ltd"),
        true,
    ));
    let (own, _) = pq_witness("w-own", false);
    d.witnesses.push(own);
    assert_eq!(pq_witnesses(&d, None), Err(ReanchorError::NoPqWitness));
    let (indep, _) = pq_witness("w-pq", true);
    d.witnesses.push(indep.clone());
    assert_eq!(pq_witnesses(&d, None).unwrap(), vec![&indep]);
    assert_eq!(pq_witnesses(&d, Some(&[])), Err(ReanchorError::NoPqWitness));
    assert_eq!(
        pq_witnesses(&d, Some(std::slice::from_ref(&indep)))
            .unwrap()
            .len(),
        1
    );
}

// RA-3, RR-35, HL-34
#[test]
fn a_re_anchor_is_anchored_only_by_a_valid_independent_cosign() {
    let (indep, s) = pq_witness("w-pq", true);
    let (own, o) = pq_witness("w-own", false);
    let ws = [&indep, &own];
    assert_eq!(status(&AwsLcBackend, &ws, (2, BODY), &[]), Status::Pending);
    let theirs = cosign("w-own", &o, BODY, 10);
    assert_eq!(
        status(&AwsLcBackend, &ws, (2, BODY), &[theirs]),
        Status::Pending
    );
    let wrong_body = cosign("w-pq", &s, "origin\n3\nAAAA\n", 10);
    assert_eq!(
        status(&AwsLcBackend, &ws, (2, BODY), &[wrong_body]),
        Status::Pending
    );
    let impostor = cosign("w-pq", &o, BODY, 10);
    assert_eq!(
        status(&AwsLcBackend, &ws, (2, BODY), &[impostor]),
        Status::Pending
    );
    let good = cosign("w-pq", &s, BODY, 10);
    assert_eq!(
        status(&AwsLcBackend, &ws, (2, BODY), &[good]),
        Status::Anchored(PqReanchor::new(2, 10_000, vec![String::from("w-pq")]))
    );
    let d = declared_with(&Declarations::default(), PqReanchor::new(2, 10_000, vec![]));
    assert_eq!(d.pq_reanchor.map(|r| r.size), Some(2));
    let PublicKey::MlDsa(..) = indep.key else {
        panic!("ML-DSA key");
    };
}

// §15.16, RA-6, OP-159 m.3 (f)
#[test]
fn retirement_needs_a_cosigned_re_anchor_of_the_head_within_a_day() {
    assert_eq!(retire_gate(None, 5, 0), Err(ReanchorError::Required));
    let r = PqReanchor::new(5, 1_000, vec![String::from("w-pq")]);
    assert_eq!(retire_gate(Some(&r), 5, 1_000 + CADENCE_MS), Ok(()));
    assert_eq!(
        retire_gate(Some(&r), 6, 2_000),
        Err(ReanchorError::Required)
    );
    assert_eq!(
        retire_gate(Some(&r), 5, 1_001 + CADENCE_MS),
        Err(ReanchorError::Required)
    );
    assert_eq!(ReanchorError::Required.code(), "reanchor-required");
}
