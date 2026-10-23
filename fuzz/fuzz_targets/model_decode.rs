//! OP-108 m.4, OP-110 m.1: the model has one canonical form.
#![no_main]

use access_kernel::codec::Canonical;
use access_kernel::intent::IntentEnvelope;
use access_kernel::model::CanonicalAuthority;
use access_kernel::validity::ValidityContract;
use libfuzzer_sys::fuzz_target;

fn round_trip<T: Canonical>(data: &[u8]) {
    if let Ok(v) = T::from_bytes(data) {
        assert_eq!(v.to_bytes().ok().as_deref(), Some(data));
    }
}

fuzz_target!(|data: &[u8]| {
    round_trip::<CanonicalAuthority>(data);
    round_trip::<IntentEnvelope>(data);
    round_trip::<ValidityContract>(data);
});
