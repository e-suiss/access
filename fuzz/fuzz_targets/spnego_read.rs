//! OP-155 m.3 (o), RR-28: the Kerberos gateway's Negotiate token reader, as the parser worker
//! runs it on untrusted input.
#![no_main]

use access_parse::spnego::{Offer, read};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Offer::Kerberos(t)) = read(data) {
        assert!(t.token.len() <= data.len());
        assert!(!t.sname.is_empty() && !t.realm.is_empty());
    }
});
