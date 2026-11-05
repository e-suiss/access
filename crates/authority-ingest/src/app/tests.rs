use std::collections::BTreeSet;
use std::sync::Mutex;

use access_internal_api::claims::Quarantine;
use access_kernel::claim::Channel;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

use super::*;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

#[derive(Default)]
struct Seen(Mutex<BTreeSet<(u32, [u8; 32])>>);

impl Submissions for Seen {
    fn first(
        &self,
        _domain: Digest,
        day: u32,
        hash: [u8; 32],
        _carrier: &'static str,
    ) -> impl std::future::Future<Output = Result<bool, Unavailable>> + Send {
        std::future::ready(Ok(self.0.lock().is_ok_and(|mut s| s.insert((day, hash)))))
    }
}

struct Fixed(u64);

impl Clock for Fixed {
    fn now(&self) -> impl std::future::Future<Output = Result<u64, Unavailable>> + Send {
        std::future::ready(Ok(self.0))
    }
}

#[derive(Default)]
struct Recorded(Mutex<Vec<bool>>);

impl Ledger for Recorded {
    fn record(
        &self,
        _submission: ClaimSubmission,
        resubmitted: bool,
    ) -> impl std::future::Future<Output = Result<ClaimVerdict, Unavailable>> + Send {
        if let Ok(mut r) = self.0.lock() {
            r.push(resubmitted);
        }
        std::future::ready(Ok(ClaimVerdict::Quarantined {
            claim: Id([1; 16]),
            position: 9,
            reason: Quarantine::SourceNotAccepted,
        }))
    }
}

fn submission(carrier: Carrier, body: Option<Vec<u8>>) -> ClaimSubmission {
    ClaimSubmission {
        domain: Digest([1; 32]),
        carrier,
        claim: vec![0xa0],
        body,
        evidence: None,
    }
}

// CMP-8, §9.13 rule 3, OP-150 m.6 (f): a submission is recorded and answered; the day's table
// marks a resubmission, and nothing is dropped silently
#[test]
fn a_submission_reaches_the_ledger_once_marked() {
    let ingest = Ingest::new(Recorded::default(), Seen::default(), Fixed(86_400_000));
    let s = submission(Carrier::Unsigned(Channel::Pep([2; 32])), None);
    let first = block_on(ingest.ingest(s.clone())).unwrap();
    assert!(matches!(first, ClaimVerdict::Quarantined { .. }));
    block_on(ingest.ingest(s)).unwrap();
    assert_eq!(
        ingest
            .ledger
            .0
            .lock()
            .map(|r| r.clone())
            .unwrap_or_default(),
        vec![false, true]
    );
}

// §9.13 rule 3, §10.1.2: an oversized Claim or a mapped carrier without its context is refused
// with a reason and never recorded
#[test]
fn malformed_submissions_are_refused_before_the_ledger() {
    let ingest = Ingest::new(Recorded::default(), Seen::default(), Fixed(1));
    let big = ClaimSubmission {
        claim: vec![0; domain::MAX_CLAIM + 1],
        ..submission(Carrier::Cose, None)
    };
    assert_eq!(
        block_on(ingest.ingest(big)).unwrap(),
        ClaimVerdict::Rejected {
            code: String::from("claim-size")
        }
    );
    assert_eq!(
        block_on(ingest.ingest(submission(Carrier::Oidc, None))).unwrap(),
        ClaimVerdict::Rejected {
            code: String::from("claim-carrier-context")
        }
    );
    let ctx = domain::context_bytes(&Id([6; 16]));
    assert!(precheck(&submission(Carrier::Set, Some(ctx))).is_ok());
    assert!(ingest.ledger.0.lock().is_ok_and(|r| r.is_empty()));
}
