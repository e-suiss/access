//! Mutation fuzzing of real attestation objects and authenticator data (CR-10, OP-146 m.4 (g)).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test fixtures"
)]

mod support;

use access_identity_webauthn::domain::ceremony::{
    ClientExtensionResults, RegistrationResponse, RegistrationState, verify_registration,
};
use access_identity_webauthn::domain::ids::UserHandle;
use access_identity_webauthn::domain::policy::RealmPolicy;
use proptest::prelude::*;
use support::*;

fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, RegistrationState) {
    let state = RegistrationState {
        realm: REALM,
        user: UserHandle::from_bytes([1; 64]),
        challenge: [5; 32],
        conditional: false,
        expires_at: NOW + 60,
        prf_salt: None,
    };
    let mut a = Authenticator::new(Key::es256());
    let (cdj, att) = a.register(RP_ID, ORIGIN, &state.challenge);
    (a.credential_id, cdj, att, state)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // CR-10 m.4
    #[test]
    fn mutated_attestation_objects_never_panic(
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8),
        cut in proptest::option::of(any::<usize>()),
    ) {
        let (id, cdj, mut att, state) = fixture();
        for (at, byte) in edits {
            let i = at % att.len();
            att[i] = byte;
        }
        if let Some(c) = cut {
            att.truncate(c % (att.len() + 1));
        }
        let _ = verify_registration(
            &rp(),
            &RealmPolicy::default(),
            &state,
            &RegistrationResponse {
                raw_id: &id,
                client_data_json: &cdj,
                attestation_object: &att,
                transports: &[],
                extensions: ClientExtensionResults::default(),
            },
            None,
            NOW,
        );
    }
}
