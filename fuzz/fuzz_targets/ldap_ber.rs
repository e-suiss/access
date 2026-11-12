//! SA-T9, R-4, SAI-2, OP-125, GHSA-qcxq-75wr-5cm8, OP-159 m.3 (cc): the LDAP gateway's BER
//! limits run before any decoding and never panic; a message they pass decodes or is refused,
//! never deeper than 32 levels. The pull client's element reader walks the same bytes one level
//! at a time. Both crates' modules are compiled in as they are.
#![no_main]
#![allow(dead_code, unreachable_pub, reason = "the gateway's and client's modules, compiled in for fuzzing")]

#[path = "../../bins/access-gw-ldap/src/ber.rs"]
mod gateway;
#[path = "../../crates/identity-directory/src/ber.rs"]
mod client;

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;

fn walk(input: &[u8]) {
    let mut stack = vec![(input, 0_usize)];
    while let Some((bytes, depth)) = stack.pop() {
        if depth > gateway::MAX_DEPTH {
            return;
        }
        let mut r = client::Reader::new(bytes);
        while !r.is_empty() {
            let Ok(t) = r.element() else {
                break;
            };
            if t.tag & 0x20 != 0 {
                stack.push((t.content, depth.saturating_add(1)));
            } else if t.tag == 0x02 {
                let _ = client::integer(t.content);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = client::frame_len(data);
    if let Ok(Some(total)) = gateway::frame_len(data) {
        assert!(total <= gateway::MAX_MESSAGE);
    }
    walk(data);
    if gateway::check(data).is_ok() {
        let mut one = BytesMut::from(data);
        let mut codec =
            ldap3_proto::LdapCodec::new(Some(gateway::MAX_MESSAGE), Some(gateway::MAX_DEPTH));
        let _ = codec.decode(&mut one);
    }
});
