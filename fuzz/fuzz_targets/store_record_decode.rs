//! SA-T9, §17.6.12, OP-159 m.3 (cc): an authority record read back from the database decodes,
//! hashes and folds without panicking, and only its canonical encoding decodes.
#![no_main]

use access_kernel::codec::Canonical;
use access_kernel::record::RecordEnvelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(env) = RecordEnvelope::from_bytes(data) else {
        return;
    };
    if let Ok(bytes) = env.to_bytes() {
        assert_eq!(bytes, data);
    }
    if let Ok(core) = env.leaf_core() {
        let _ = core.leaf_hash();
    }
    let _ = env.domain();
    let _ = access_kernel::fold::effects(&env);
});
