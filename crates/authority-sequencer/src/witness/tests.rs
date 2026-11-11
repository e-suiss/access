#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

fn vkey(name: &str) -> String {
    let (s, _) = suiss_crypto::signer::SoftSigner::generate_ed25519().unwrap();
    let suiss_crypto::cose::PublicKey::Ed25519(k) = suiss_crypto::signer::Signer::public_key(&s)
    else {
        panic!("ed25519");
    };
    Verifier::cosigner(name, k).unwrap().to_vkey()
}

// SI-12, B13, Ek B 6082
#[test]
fn a_witness_of_the_provider_operator_is_not_independent() {
    let v = vkey("w.example");
    let own = Target::new("http://127.0.0.1:1", &v, " suiss ", "Suiss").unwrap();
    assert!(!own.independent);
    let other = Target::new("http://127.0.0.1:1", &v, "Example Witness Ltd", "Suiss").unwrap();
    assert!(other.independent);
    assert!(Target::new("https://w:1", &v, "x", "Suiss").is_err());
    assert!(Target::new("http://w:1", &v, "", "Suiss").is_err());
    let log = suiss_crypto::note::Verifier::ed25519("w.example", [9; 32])
        .map(|v| v.to_vkey())
        .unwrap();
    assert!(Target::new("http://w:1", &log, "x", "Suiss").is_err());
}

// OP-38, SEC23, OP-158 m.3 (c), (e)
#[tokio::test(flavor = "multi_thread")]
async fn waiting_commits_coalesce_into_one_request_and_time_out_pending() {
    let b = Board::default();
    let d = Digest([4; 32]);
    let woke = b.woken();
    b.want(d, 3);
    tokio::time::timeout(Duration::from_secs(5), woke)
        .await
        .unwrap();
    b.want(d, 5);
    b.want(d, 4);
    assert_eq!(b.wanted(&d), Some(5));
    assert_eq!(b.wait(d, 5, Duration::from_millis(20)).await, Err(0));
    let waiter = {
        let b = std::sync::Arc::new(b);
        let w = std::sync::Arc::clone(&b);
        let h = tokio::spawn(async move { w.wait(d, 5, Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        b.set_witnessed(d, 6);
        assert_eq!(b.wanted(&d), None);
        h
    };
    assert_eq!(waiter.await.unwrap(), Ok(6));
}

// TI-RT2, FA-3, OP-158 m.3 (k)
#[test]
fn a_cosignature_older_than_the_log_stops_commits_until_one_agrees() {
    assert_eq!(time_check(), Ok(()));
    assert_eq!(cross_check(11_250, 10), Err(TimeError::AheadOfWitness));
    assert_eq!(time_check(), Err(TimeError::AheadOfWitness));
    assert_eq!(cross_check(11_000, 11), Ok(()));
    assert_eq!(time_check(), Ok(()));
}
