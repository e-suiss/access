use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use std::sync::Mutex;

use super::*;

const fn ring(pos: u64, idx: u32, id: u8) -> Ring {
    Ring {
        domain: [7; 32],
        at: Cursor { pos, idx },
        id: [id; 32],
    }
}

#[derive(Default)]
struct Rang(Mutex<Vec<Ring>>);

impl Bell for Rang {
    fn ring(&self, ring: Ring) {
        self.0.lock().unwrap().push(ring);
    }
}

// OP-156 m.3 (j)
#[test]
fn the_payload_is_domain_pos_and_idx_only() {
    let r = ring(42, 3, 9);
    let p = r.payload();
    assert_eq!(
        Ring::read(&p).unwrap(),
        ([7; 32], Cursor { pos: 42, idx: 3 })
    );
    let v = dcbor::decode(&p, Limits::CEILING).unwrap();
    let Value::Map(entries) = v else { panic!() };
    let keys: Vec<_> = entries.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(
        keys,
        vec![
            Value::text("idx"),
            Value::text("pos"),
            Value::text("domain")
        ]
    );
    assert_eq!(r.msg_id(), "09".repeat(32));
    assert!(Ring::read(b"\xa0").is_err());
    let extra = dcbor::encode(
        &Value::Map(vec![
            (Value::text("domain"), Value::Bytes(vec![0; 32])),
            (Value::text("pos"), Value::Unsigned(1)),
            (Value::text("idx"), Value::Unsigned(0)),
            (Value::text("body"), Value::Unsigned(0)),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    assert!(Ring::read(&extra).is_err());
}

// TI-6, OP-156 m.3 (j)
#[test]
fn no_ring_leaves_before_the_durability_fence() {
    let bell = Rang::default();
    let mut gate = Gate::new(Fence::at(4));
    assert!(!gate.release(ring(5, 0, 1), &bell));
    assert!(bell.0.lock().unwrap().is_empty());
    gate.fence().advance(5).unwrap();
    assert!(gate.release(ring(5, 0, 1), &bell));
    assert!(!gate.release(ring(6, 0, 2), &bell));
    assert_eq!(*bell.0.lock().unwrap(), vec![ring(5, 0, 1)]);
    let mut empty = Gate::default();
    assert!(!empty.release(ring(0, 0, 3), &bell));
    empty.fence().advance(0).unwrap();
    assert!(empty.release(ring(0, 0, 3), &bell));
}

#[test]
fn rings_spread_over_few_partitions() {
    let t = Topic::ACCESS;
    let mut d = [0_u8; 32];
    d[0] = 13;
    assert_eq!(t.subject(&d), "access.doorbell.5");
    assert_eq!(t.all(), "access.doorbell.*");
    assert!(proto::matches(&t.all(), &t.subject(&[255; 32])));
}

#[test]
fn acknowledgements_and_errors_read() {
    assert_eq!(
        pub_ack(br#"{"stream":"ACCESS_DOORBELL","seq":4,"duplicate":true}"#).unwrap(),
        Ack {
            stream: String::from("ACCESS_DOORBELL"),
            seq: 4,
            duplicate: true
        }
    );
    let e = pub_ack(br#"{"error":{"code":503,"err_code":10039,"description":"no stream"}}"#)
        .unwrap_err();
    assert_eq!(e.code, 10039);
    assert!(pub_ack(b"nope").is_err());
    assert!(pub_ack(br#"{"type":"x"}"#).is_err());
}

#[cfg(feature = "testing")]
mod twin {
    use std::time::Duration;

    use super::super::client::{self, Listener, Publisher, Report};
    use super::super::testing::{Pki, Twin};
    use super::*;

    // OP-156 m.3 (j), T26
    #[tokio::test(flavor = "multi_thread")]
    async fn a_ring_is_stored_once_per_event_id_and_reaches_listeners() {
        let pki = Pki::new().unwrap();
        let twin = Twin::start(pki.server.clone()).await.unwrap();
        let cfg = pki.client(&twin.addr(), "t1").unwrap();
        let mut listener = Listener::connect(&cfg).await.unwrap();
        let mut p = Publisher::connect(&cfg).await.unwrap();
        let first = p.ring(&ring(3, 1, 1)).await.unwrap();
        assert_eq!(
            (first.stream.as_str(), first.seq, first.duplicate),
            ("ACCESS_DOORBELL", 1, false)
        );
        let again = p.ring(&ring(3, 1, 1)).await.unwrap();
        assert!(again.duplicate);
        let stored = twin.stored("ACCESS_DOORBELL");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].msg_id.as_deref(), Some("01".repeat(32).as_str()));
        assert_eq!(stored[0].subject, Topic::ACCESS.subject(&[7; 32]));
        let heard = tokio::time::timeout(Duration::from_secs(5), listener.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(heard, ([7; 32], Cursor { pos: 3, idx: 1 }));
        let p2 = Publisher::connect(&pki.client(&twin.addr(), "t2").unwrap()).await;
        assert!(p2.is_ok(), "an existing stream is reused");
    }

    // OP-156 m.3 (j): mutual TLS only
    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_without_the_operators_certificate_is_refused() {
        let pki = Pki::new().unwrap();
        let other = Pki::new().unwrap();
        let twin = Twin::start(pki.server.clone()).await.unwrap();
        let mut cfg = other.client(&twin.addr(), "t3").unwrap();
        assert!(Publisher::connect(&cfg).await.is_err());
        cfg.tls = client::tls(
            pki.ca_pem.as_bytes(),
            other.cert_pem.as_bytes(),
            other.key_pem.as_bytes(),
        )
        .unwrap();
        assert!(Publisher::connect(&cfg).await.is_err());
        assert!(client::tls(b"", pki.cert_pem.as_bytes(), pki.key_pem.as_bytes()).is_err());
    }

    // OP-23: losing NATS is only delay
    #[tokio::test(flavor = "multi_thread")]
    async fn publish_survives_a_server_that_is_down_and_coalesces() {
        let pki = Pki::new().unwrap();
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = free.local_addr().unwrap().to_string();
        drop(free);
        let cfg = pki.client(&addr, "t4").unwrap();
        let (bell, rx) = client::queue(16);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let reports = std::sync::Arc::new(Mutex::new(Vec::new()));
        let seen = reports.clone();
        let task = tokio::spawn(client::publish(cfg, rx, stopped, move |r| {
            seen.lock().unwrap().push(matches!(r, Report::Rang(_)));
        }));
        bell.ring(ring(1, 0, 1));
        tokio::time::timeout(Duration::from_secs(10), async {
            while reports.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(*reports.lock().unwrap(), vec![false]);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();

        let twin = Twin::start(pki.server.clone()).await.unwrap();
        let cfg = pki.client(&twin.addr(), "t5").unwrap();
        let (bell, rx) = client::queue(16);
        for i in 0..5 {
            bell.ring(ring(10 + i, 0, u8::try_from(i).unwrap()));
        }
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(client::publish(cfg, rx, stopped, |_| {}));
        tokio::time::timeout(Duration::from_secs(10), async {
            while twin.stored("ACCESS_DOORBELL").is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let stored = twin.stored("ACCESS_DOORBELL");
        assert_eq!(stored.len(), 1, "queued rings of one domain coalesce");
        assert_eq!(Ring::read(&stored[0].payload).unwrap().1.pos, 14);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    /// The same flow against a real `nats-server` 2.15 with `JetStream` and `tls { verify: true }`
    /// (CI job `nats`): `ACCESS_TEST_NATS_ADDR` and the PEM files `scripts/ci/nats-env.sh`
    /// writes.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs nats-server; CI job nats (scripts/ci/nats-env.sh)"]
    async fn nats_server_stores_a_ring_once_and_delivers_it() {
        let var = |k: &str| std::env::var(k).unwrap();
        let read = |k: &str| std::fs::read(var(k)).unwrap();
        let cfg = client::Config {
            addr: var("ACCESS_TEST_NATS_ADDR"),
            server_name: rustls_pki_types::ServerName::try_from("localhost")
                .unwrap()
                .to_owned(),
            tls: client::tls(
                &read("ACCESS_TEST_NATS_CA"),
                &read("ACCESS_TEST_NATS_CERT"),
                &read("ACCESS_TEST_NATS_KEY"),
            )
            .unwrap(),
            topic: Topic::ACCESS,
            inbox: String::from("ci"),
            name: String::from("doorbell-ci"),
        };
        let mut listener = Listener::connect(&cfg).await.unwrap();
        let mut p = Publisher::connect(&cfg).await.unwrap();
        let first = p.ring(&ring(9, 2, 0xab)).await.unwrap();
        assert!(!first.duplicate);
        let again = p.ring(&ring(9, 2, 0xab)).await.unwrap();
        assert!(again.duplicate);
        assert_eq!(again.seq, first.seq);
        let heard = tokio::time::timeout(Duration::from_secs(5), listener.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(heard, ([7; 32], Cursor { pos: 9, idx: 2 }));
    }
}
