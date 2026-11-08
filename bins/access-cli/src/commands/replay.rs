//! `access-cli replay`: re-evaluates a recorded decision with the Kernel and says whether it
//! matches (§17.1.1, P41, INV-21: a decision is a pure function of its input). The bundle names
//! the canonical evaluation input as of the record's `StateBasis` and the recorded decision, both
//! hex CBOR as the conformance vectors carry them. The Kernel's answer is compared byte for byte.

use std::fmt::Write as _;
use std::path::PathBuf;

use access_kernel::binding::{self, MAX_FUEL};
use clap::Args;
use serde_json::Value;

use super::{note, out};
use crate::exit::{self, Code};

/// `replay` arguments.
#[derive(Debug, Args)]
pub(crate) struct ReplayArgs {
    /// A JSON bundle: `{"input": <hex>, "decision": <hex>, "fuel": <n>}`.
    #[arg(long, value_name = "PATH")]
    pub(crate) bundle: PathBuf,
}

/// The verdict of a replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The Kernel decides the same bytes.
    Match,
    /// The Kernel decides other bytes.
    Mismatch {
        /// The Kernel's decision, hex.
        got: String,
    },
    /// The Kernel rejects the input.
    Rejected(String),
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i.checked_add(2)?)?, 16).ok())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Replays one bundle.
pub(crate) fn replay(bundle: &Value) -> Result<Verdict, &'static str> {
    let field = |n: &str| bundle.get(n).and_then(Value::as_str).and_then(hex);
    let input = field("input").ok_or("input")?;
    let recorded = field("decision").ok_or("decision")?;
    let fuel = bundle
        .get("fuel")
        .and_then(Value::as_u64)
        .unwrap_or(MAX_FUEL)
        .min(MAX_FUEL);
    Ok(match binding::evaluate(&input, fuel) {
        Ok(got) if got == recorded => Verdict::Match,
        Ok(got) => Verdict::Mismatch { got: to_hex(&got) },
        Err(e) => Verdict::Rejected(e.to_string()),
    })
}

/// Runs `replay`.
pub(crate) fn run(args: &ReplayArgs) -> Code {
    let Some(bundle) = std::fs::read(&args.bundle)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    else {
        note(&format!(
            "access-cli: {}: not a JSON bundle",
            args.bundle.display()
        ));
        return exit::CONFIG;
    };
    match replay(&bundle) {
        Ok(Verdict::Match) => out("match\n"),
        Ok(Verdict::Mismatch { got }) => {
            let _ = out(&format!("mismatch\nkernel: {got}\n"));
            exit::DIFFERS
        }
        Ok(Verdict::Rejected(e)) => {
            let _ = out(&format!("mismatch\nkernel rejected the input: {e}\n"));
            exit::DIFFERS
        }
        Err(field) => {
            note(&format!("access-cli: the bundle's `{field}` is not hex"));
            exit::CONFIG
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    fn decision_vector() -> Value {
        let text = include_str!("../../../../conformance/vectors/core/1/decision.json");
        let v: Value = serde_json::from_str(text).unwrap();
        let case = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c.get("decision").is_some())
            .unwrap()
            .clone();
        let mut b = serde_json::Map::new();
        b.insert("input".into(), case["input"].clone());
        b.insert("decision".into(), case["decision"].clone());
        b.insert(
            "fuel".into(),
            case.get("fuel")
                .or_else(|| v.get("fuel"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        Value::Object(b)
    }

    // INV-21, P41
    #[test]
    fn a_recorded_decision_replays_to_a_match_and_a_tampered_one_does_not() {
        let b = decision_vector();
        assert_eq!(replay(&b).unwrap(), Verdict::Match);
        let mut t = b.clone();
        let d = t["decision"].as_str().unwrap().to_owned();
        let flipped = format!(
            "{}{}",
            &d[..d.len() - 2],
            if d.ends_with("00") { "01" } else { "00" }
        );
        t["decision"] = Value::String(flipped);
        assert!(matches!(replay(&t).unwrap(), Verdict::Mismatch { .. }));
        let mut bad = b;
        bad["input"] = Value::String(String::from("zz"));
        assert_eq!(replay(&bad), Err("input"));
    }
}
