//! Gossip (§9.16, U9, HL-7, OP-158 m.3 (d)): pull every declared witness's latest
//! `gossip-entry` of a domain, keep those whose cosignature verifies under that witness's key
//! over the note it carries, and report two with the same size and different roots as an
//! `equivocation-proof`. The configuration names the domain and the witnesses:
//!
//! ```text
//! domain <domain, base64url>
//! witness <url> <vkey>
//! ```

use std::fmt::Write as _;

use suiss_crypto::note::{Checkpoint, Verifier, base64_encode, verify_note};
use suiss_crypto::sig::PureBackend;
use suiss_ledger::checkpoint::witness::{EquivocationProof, GossipEntry, equivocates};

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

fn parse(text: &str) -> Result<(String, Vec<(String, Verifier)>), String> {
    let (mut domain, mut witnesses) = (None, Vec::new());
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            [] => {}
            ["domain", d] => domain = Some((*d).to_owned()),
            ["witness", url, vkey] => {
                crate::http::split(url)?;
                let v = Verifier::parse(vkey).map_err(|e| format!("vkey: {e}"))?;
                if !v.is_cosigner() {
                    return Err(format!("not a cosigner key: {vkey}"));
                }
                witnesses.push(((*url).to_owned(), v));
            }
            _ => return Err(format!("unknown line: {line}")),
        }
    }
    let domain = domain.ok_or("missing `domain`")?;
    if witnesses.is_empty() {
        return Err("no `witness` lines".into());
    }
    Ok((domain, witnesses))
}

fn verified(entry: &GossipEntry, v: &Verifier) -> Option<Checkpoint> {
    let note = entry.note.as_deref()?;
    let (n, accepted) = verify_note(&PureBackend, note, std::slice::from_ref(v)).ok()?;
    let cp = Checkpoint::parse(&n.body).ok()?;
    let ok = (cp.size, cp.root) == (entry.size, entry.root)
        && accepted
            .iter()
            .any(|a| a.timestamp == Some(entry.cosignature.timestamp));
    ok.then_some(cp)
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// One round over the configuration `text`, at `now` Unix milliseconds.
pub(crate) async fn run(text: &str, now: u64) -> Result<Report, String> {
    let (domain, witnesses) = parse(text)?;
    let mut seen: Vec<(String, Checkpoint, GossipEntry)> = Vec::new();
    let mut out = String::new();
    let mut status = Status::Consistent;
    for (url, v) in &witnesses {
        let entry = match crate::http::get(url, &format!("/gossip/{domain}")).await {
            Ok((200, body)) => GossipEntry::from_bytes(&body).ok(),
            _ => None,
        };
        let Some((cp, entry)) = entry.and_then(|e| verified(&e, v).map(|cp| (cp, e))) else {
            let _ = writeln!(out, "unreachable {url}");
            status = Status::Unreachable;
            continue;
        };
        let _ = writeln!(
            out,
            "witness {url} size {} root {}",
            cp.size,
            base64_encode(&cp.root)
        );
        seen.push((url.clone(), cp, entry));
    }
    for (i, (ua, a, ea)) in seen.iter().enumerate() {
        for (ub, b, eb) in seen.iter().skip(i.saturating_add(1)) {
            if !equivocates(a, b) {
                continue;
            }
            status = Status::Equivocation;
            let proof = EquivocationProof {
                domain: ea.domain,
                size: a.size,
                first: ea.clone(),
                second: eb.clone(),
                found_at: now,
            };
            let _ = writeln!(out, "equivocation size {} between {ua} and {ub}", a.size);
            if let Ok(bytes) = proof.to_bytes() {
                let _ = writeln!(out, "proof {}", hex(&bytes));
            }
        }
    }
    if status == Status::Consistent {
        out.push_str("consistent\n");
    }
    Ok(Report { status, text: out })
}
