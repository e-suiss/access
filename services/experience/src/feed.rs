//! The stream's feeds (OP-153 m.3 (v), m.8 (d), OP-156 m.8 (d)): Access's SSF poll endpoint
//! (RFC 8936), whose stream this service polls as its receiver, and Access's NATS doorbell,
//! whose rings this service hears over mTLS. Each event or ring moves the beacon. A signal is
//! only a hint to read again: neither SET bodies nor rings are trusted or forwarded, so a
//! forged or replayed one can at most cause a read, never show anything (XI-3). Without either
//! feed the beacon stays still and the stream sends keep-alives only; with the doorbell down the
//! SSF poll still moves it.

use std::future::Future;
use std::time::Duration;

use access_sdk::transport::Answer;
use serde_json::{Value, json};
use tokio::sync::watch;

use suiss_ledger::doorbell::client;

use crate::adapters::Beacon;

/// Most events asked for per poll.
pub const MAX_EVENTS: u32 = 25;

/// How long to wait after an empty or failed poll.
pub const IDLE: Duration = Duration::from_secs(2);

/// Most acknowledgements carried by one poll (RFC 8936 §2.4).
pub const MAX_ACKS: usize = 100;

/// Access's SSF poll route for this service's stream, as its receiver.
pub trait Poll: Send + Sync {
    /// `POST` the poll body; a transport failure is [`Answer::Unanswered`].
    fn poll(&self, body: Vec<u8>) -> impl Future<Output = Answer> + Send;
}

/// What one poll answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polled {
    /// The `jti` of each SET received.
    pub jtis: Vec<String>,
    /// Whether more wait.
    pub more: bool,
}

/// The poll body acknowledging `acks` (RFC 8936 §2.4).
#[must_use]
pub fn request(acks: &[String]) -> Vec<u8> {
    json!({
        "ack": acks.iter().take(MAX_ACKS).collect::<Vec<_>>(),
        "maxEvents": MAX_EVENTS,
        "returnImmediately": true,
    })
    .to_string()
    .into_bytes()
}

/// The `jti`s and `moreAvailable` of a `200` poll answer; `None` for anything else.
#[must_use]
pub fn answer(a: &Answer) -> Option<Polled> {
    let Answer::Response(r) = a else {
        return None;
    };
    if r.status != 200 {
        return None;
    }
    let v: Value = serde_json::from_slice(&r.body).ok()?;
    let sets = v.get("sets")?.as_object()?;
    Some(Polled {
        jtis: sets.keys().take(MAX_ACKS).cloned().collect(),
        more: v.get("moreAvailable").and_then(Value::as_bool) == Some(true),
    })
}

/// One step: polls with `acks`, moves `beacon` past `count` when events came, and answers what
/// to acknowledge next, the new count, and whether to poll again at once.
pub async fn step<P: Poll>(
    poll: &P,
    beacon: &Beacon,
    acks: &[String],
    count: u64,
) -> (Vec<String>, u64, bool) {
    match answer(&poll.poll(request(acks)).await) {
        Some(p) if !p.jtis.is_empty() => {
            let n = u64::try_from(p.jtis.len()).unwrap_or(u64::MAX);
            let count = count.saturating_add(n);
            beacon.advance(n);
            (p.jtis, count, p.more)
        }
        Some(p) => (Vec::new(), count, p.more),
        None => (acks.to_vec(), count, false),
    }
}

/// Polls until `stop` turns true. A failed poll keeps its acknowledgements for the next one.
pub async fn run<P: Poll>(poll: P, beacon: Beacon, mut stop: watch::Receiver<bool>) {
    let mut acks = Vec::new();
    let mut count = 0;
    loop {
        if *stop.borrow() {
            return;
        }
        let (next, seen, more) = step(&poll, &beacon, &acks, count).await;
        acks = next;
        count = seen;
        if !more {
            tokio::select! {
                () = tokio::time::sleep(IDLE) => {}
                _ = stop.changed() => return,
            }
        }
    }
}

/// Moves `beacon` on every ring of Access's doorbell until `stop` turns true; while NATS is down
/// it connects again and the other feed carries on (OP-156 m.8 (d), OP-23).
pub async fn doorbell(cfg: client::Config, beacon: Beacon, stop: watch::Receiver<bool>) {
    client::listen(
        cfg,
        stop,
        move |_, _| beacon.advance(1),
        |e| tracing::warn!(event = "doorbell.unavailable", error = %e, "doorbell unavailable; the stream keeps polling (OP-23)"),
    )
    .await;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::unused_async_trait_impl,
        reason = "test code; the request-path lints (OP-3) do not apply"
    )]

    use std::sync::Mutex;

    use access_sdk::transport::{Fault, Response};

    use super::*;
    use crate::ports::Signals as _;

    struct Script(Mutex<Vec<Answer>>, Mutex<Vec<Value>>);

    impl Poll for Script {
        async fn poll(&self, body: Vec<u8>) -> Answer {
            self.1
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&body).unwrap());
            let mut answers = self.0.lock().unwrap();
            if answers.is_empty() {
                Answer::Unanswered(Fault::Unreachable)
            } else {
                answers.remove(0)
            }
        }
    }

    fn sets(jtis: &[&str], more: bool) -> Answer {
        let sets: serde_json::Map<String, Value> = jtis
            .iter()
            .map(|j| ((*j).to_owned(), Value::from("eyJ.x.y")))
            .collect();
        Answer::Response(Response::new(
            200,
            json!({ "sets": sets, "moreAvailable": more })
                .to_string()
                .into_bytes(),
        ))
    }

    // OP-153 m.3 (v), m.8 (d), XI-3
    #[tokio::test]
    async fn events_move_the_beacon_and_are_acknowledged() {
        let script = Script(
            Mutex::new(vec![
                sets(&["a", "b"], true),
                Answer::Unanswered(Fault::Timeout),
                sets(&[], false),
                Answer::Response(Response::new(401, Vec::new())),
            ]),
            Mutex::new(Vec::new()),
        );
        let beacon = Beacon::default();
        let mut rx = beacon.watch();
        let (acks, count, more) = step(&script, &beacon, &[], 0).await;
        assert_eq!(
            (acks.clone(), count, more),
            (vec!["a".into(), "b".into()], 2, true)
        );
        assert!(rx.has_changed().unwrap());
        assert_eq!(*rx.borrow_and_update(), 2);
        let (acks, count, more) = step(&script, &beacon, &acks, count).await;
        assert_eq!(
            acks,
            vec!["a".to_owned(), "b".to_owned()],
            "kept after a failure"
        );
        assert!(!more);
        let (acks, count, _) = step(&script, &beacon, &acks, count).await;
        assert_eq!(acks, Vec::<String>::new());
        let (_, count, _) = step(&script, &beacon, &acks, count).await;
        assert_eq!(count, 2);
        assert!(!rx.has_changed().unwrap(), "no event, no signal");
        let sent = script.1.lock().unwrap();
        assert_eq!(sent[0]["ack"], json!([]));
        assert_eq!(sent[1]["ack"], json!(["a", "b"]));
        assert_eq!(sent[2]["ack"], json!(["a", "b"]));
        assert_eq!(sent[3]["ack"], json!([]));
        assert_eq!(sent[0]["maxEvents"], MAX_EVENTS);
    }

    // OP-156 m.8 (d), XI-3
    #[tokio::test(flavor = "multi_thread")]
    async fn a_doorbell_ring_moves_the_beacon() {
        use suiss_ledger::doorbell::testing::{Pki, Twin};
        use suiss_ledger::doorbell::{Bell as _, Ring};
        use suiss_ledger::fence::Cursor;

        let pki = Pki::new().unwrap();
        let twin = Twin::start(pki.server.clone()).await.unwrap();
        let cfg = pki.client(&twin.addr(), "experience").unwrap();
        let beacon = Beacon::default();
        let mut rx = beacon.watch();
        let (stop, stopped) = watch::channel(false);
        let listening = tokio::spawn(doorbell(cfg.clone(), beacon.clone(), stopped.clone()));
        let (queue, rings) = client::queue(8);
        let publishing = tokio::spawn(client::publish(cfg, rings, stopped, |_| {}));
        let ring = Ring {
            domain: [5; 32],
            at: Cursor { pos: 3, idx: 0 },
            id: [6; 32],
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                queue.ring(ring);
                if tokio::time::timeout(Duration::from_millis(200), rx.changed())
                    .await
                    .is_ok()
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(*rx.borrow_and_update() >= 1);
        stop.send(true).unwrap();
        listening.await.unwrap();
        publishing.await.unwrap();
    }

    #[tokio::test]
    async fn the_loop_stops_when_asked() {
        let (stop, stopped) = watch::channel(false);
        let script = Script(Mutex::new(vec![sets(&[], false)]), Mutex::new(Vec::new()));
        let task = tokio::spawn(run(script, Beacon::default(), stopped));
        stop.send(true).unwrap();
        task.await.unwrap();
    }
}
