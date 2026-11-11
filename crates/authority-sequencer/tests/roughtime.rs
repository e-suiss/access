//! TI-RT2, FA-3, OP-158 m.3 (k): Roughtime as the third time source, from a local Roughtime
//! twin over UDP, next to the process clock and the real PostgreSQL server's clock.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::{SystemTime, UNIX_EPOCH};

use access_authority_sequencer::adapters::SourcesClock;
use access_authority_sequencer::ports::Clock as _;
use access_authority_sequencer::witness::{RoughtimeServer, read_roughtime, roughtime};
use access_store::testing::fresh;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::roughtime::responder::Responder;
use suiss_crypto::signer::{Signer as _, SoftSigner};

fn wall_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A Roughtime server on a local UDP port answering `offset` seconds off the wall clock.
fn twin(offset: i64) -> RoughtimeServer {
    let (long, _) = SoftSigner::generate_ed25519().unwrap();
    let (online, _) = SoftSigner::generate_ed25519().unwrap();
    let PublicKey::Ed25519(key) = long.public_key() else {
        panic!("ed25519");
    };
    let now = wall_s();
    let responder = Responder::new(&long, Box::new(online), now - 86_400, now + 86_400).unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let mut buf = vec![0_u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let midpoint = wall_s().checked_add_signed(offset).unwrap();
            if let Ok(answer) = responder.respond(&buf[..n], midpoint, 1) {
                let _ = socket.send_to(&answer, from);
            }
        }
    });
    RoughtimeServer { addr, key }
}

// TI-RT2, FA-3, OP-158 m.3 (k)
#[tokio::test(flavor = "multi_thread")]
async fn roughtime_is_a_third_source_and_one_deviating_source_does_not_stop_commits() {
    let db = fresh().await.unwrap();
    let mut clock = SourcesClock::new(db.app.clone());

    let honest = twin(0);
    let reading = read_roughtime(&honest).await.unwrap();
    assert!(reading.at.abs_diff(wall_s() * 1000) < 3_000);
    assert_eq!(reading.radius, 1_000);
    roughtime().sample(&[honest]).await;
    assert!(roughtime().current().is_some());
    clock.now().await.unwrap();
    assert_eq!(clock.deviating(), 0);

    // one of three sources an hour off: the other two agree, the commit goes on
    let liar = twin(3_600);
    roughtime().sample(&[liar]).await;
    clock.now().await.unwrap();
    assert_eq!(clock.deviating(), 1);

    // an answer under another key is no reading at all
    let mut forged = twin(0);
    forged.key = twin(0).key;
    assert!(read_roughtime(&forged).await.is_err());
}
