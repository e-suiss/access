//! Gossip (§9.16, U9, HL-7, OP-158 m.3 (d)): fetch every declared witness's latest cosigned
//! checkpoint of a domain, keep those whose cosignature verifies under that witness's key,
//! and report two with the same size and different roots as equivocation. The evidence is
//! the two notes themselves: each carries the log's signature and a witness's cosignature.

use std::fmt::Write as _;

use suiss_crypto::note::{Checkpoint, Verifier, base64_encode, verify_note};
use suiss_crypto::sig::PureBackend;
use suiss_ledger::checkpoint::witness::equivocates;

/// The outcome of one round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// Every witness answered and none contradicts another.
    Consistent,
    /// A witness did not answer or its answer did not verify: nothing can be claimed.
    Unreachable,
    /// Two cosigned checkpoints contradict each other.
    Equivocation,
}

/// What a round printed.
pub(crate) struct Report {
    pub(crate) status: Status,
    pub(crate) text: String,
}

/// Compares the witnesses named by `pairs` (`url`, `vkey`, …) for `domain`.
pub(crate) async fn run(domain: &str, pairs: &[&str]) -> Result<Report, String> {
    let mut seen: Vec<(String, Checkpoint, String)> = Vec::new();
    let mut text = String::new();
    let mut status = Status::Consistent;
    for pair in pairs.chunks(2) {
        let [url, vkey] = pair else {
            return Err("pairs of url and vkey".into());
        };
        let cosigner = Verifier::parse(vkey).map_err(|e| format!("vkey: {e}"))?;
        if !cosigner.is_cosigner() {
            return Err(format!("not a cosigner key: {vkey}"));
        }
        let answer = crate::http::get(url, &format!("/checkpoint/{domain}")).await;
        let verified = match answer {
            Ok((200, note)) => verify_note(&PureBackend, &note, &[cosigner])
                .ok()
                .and_then(|(n, _)| Checkpoint::parse(&n.body).ok())
                .map(|cp| (cp, note)),
            _ => None,
        };
        let Some((cp, note)) = verified else {
            let _ = writeln!(text, "unreachable {url}");
            status = Status::Unreachable;
            continue;
        };
        let _ = writeln!(
            text,
            "witness {url} size {} root {}",
            cp.size,
            base64_encode(&cp.root)
        );
        seen.push(((*url).to_owned(), cp, note));
    }
    for (i, (ua, a, na)) in seen.iter().enumerate() {
        for (ub, b, nb) in seen.iter().skip(i.saturating_add(1)) {
            if equivocates(a, b) {
                status = Status::Equivocation;
                let _ = write!(
                    text,
                    "equivocation size {}\n-- {ua}\n{na}-- {ub}\n{nb}",
                    a.size
                );
            }
        }
    }
    if status == Status::Consistent {
        text.push_str("consistent\n");
    }
    Ok(Report { status, text })
}
