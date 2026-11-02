use suiss_crypto::envelope::SoftKek;
use suiss_crypto::rotation::Policy;

use super::*;
use crate::app::Keyring;

// CR-21 m.3: a sealed realm key loads back under the same KEK and not under another
#[test]
fn sealed_keys_open_only_under_their_kek() {
    let mut factory = SealedFactory::new(SoftKek::new("realm-kek-1", [1; 32]));
    for alg in [JwsAlg::Es256, JwsAlg::Ed25519] {
        let g = factory.generate(alg).unwrap();
        let loaded = factory.load(alg, &g.sealed).unwrap();
        assert_eq!(loaded.public_key(), g.signer.public_key());
        let mut other = SealedFactory::new(SoftKek::new("realm-kek-2", [2; 32]));
        assert!(other.load(alg, &g.sealed).is_err());
    }
}

// CR-23: a restarted signer loads its sealed keys back and signs on with the same key
#[test]
fn a_restart_signs_with_the_same_key() {
    let mut factory = SealedFactory::new(SoftKek::new("realm-kek-1", [1; 32]));
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut now = 0;
    while now <= Policy::REALM.publish_lead_ms + 60_000 {
        let _ = ring.tick(&mut factory, now, now);
        now += 60_000;
    }
    let before = ring.sign("at+jwt", b"{}", now).unwrap();
    let mut restored =
        Keyring::restore(JwsAlg::Es256, Policy::REALM, ring.saved(), &mut factory).unwrap();
    assert_eq!(restored.jwks(), ring.jwks());
    let after = restored.sign("at+jwt", b"{}", now).unwrap();
    assert_eq!(after.kid, before.kid);
}
