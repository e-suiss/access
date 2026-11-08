//! The stream's feed from Access's SSF poll endpoint (RFC 8936, OP-153 m.3 (v), m.8 (d)): this
//! service polls the stream its receiver credential names, acknowledges what it took and, for
//! every batch that brought at least one event, moves the beacon. A signal is only a hint to
//! read again: the SET bodies are neither trusted nor forwarded, so a forged or replayed event
//! can at most cause a read, never show anything (XI-3). Without a configured stream the beacon
//! stays still and the stream sends keep-alives only.

use std::future::Future;
use std::time::Duration;

use access_sdk::transport::Answer;
use serde_json::{Value, json};
use tokio::sync::watch;

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
            beacon.notify(count);
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

    #[tokio::test]
    async fn the_loop_stops_when_asked() {
        let (stop, stopped) = watch::channel(false);
        let script = Script(Mutex::new(vec![sets(&[], false)]), Mutex::new(Vec::new()));
        let task = tokio::spawn(run(script, Beacon::default(), stopped));
        stop.send(true).unwrap();
        task.await.unwrap();
    }
}
