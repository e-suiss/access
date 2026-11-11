//! `access-cli domain recover` (§13.6, §16.6 FR-0…FR-6, SEC20–SEC22, OP-158 m.3 (m)).
//!
//! - FR-1: the records come from the provider-external replica (`--replica`) or an honest
//!   provider's export (`--export`); their roots are recomputed here, nothing is taken on trust.
//! - FR-2: each declared witness's latest cosigned head is read from the witness itself and
//!   checked against its key; one that does not answer leaves the quorum incomplete.
//! - FR-3: the plan is N, its checkpoint, R*, the arm, the declared lost suffix and the fork.
//!   The recovering provider records the heads and evaluates `domain_recover` itself; this plan
//!   is what the root's AIS cites.
//! - PR-2 (`--discover`): the revocations the lost suffix may hold, from the old provider's
//!   partial export and the Decision Receipts at hand. Each is a suggestion: redoing it is a
//!   separate revoke Exercise, never made here (XI-19).
//!
//! The recovery keys are never read: they stay on the root Parties' devices or offline (SEC20).

use std::path::PathBuf;

use access_authority_core::app::forced::{
    Arm, Plan, WitnessHead, fetch_witness_heads, plan, prefix_roots,
};
use access_authority_core::domain::export::{Coverage, Streamed, read_stream};
use access_authority_sequencer::witness::Target;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::record::RecordKind;
use clap::Args;
use serde_json::{Value, json};

use super::super::{note, out};
use crate::exit::{self, Code};

/// `domain recover` arguments.
#[derive(Debug, Args)]
pub(crate) struct RecoverArgs {
    /// The `DomainID`, unpadded base64url.
    #[arg(long, value_name = "DOMAIN")]
    pub(crate) domain: String,
    /// A declared witness, `http://host:port=<vkey>`; repeat for each. All of them are asked.
    #[arg(long = "witness", value_name = "URL=VKEY", required = true)]
    pub(crate) witnesses: Vec<String>,
    /// The records: a full-disclosure export package from Genesis.
    #[arg(long, value_name = "PATH")]
    pub(crate) export: PathBuf,
    /// The records came from the domain's provider-external replica, so they bound R*.
    #[arg(long)]
    pub(crate) replica: bool,
    /// Also list the revocations the lost suffix may hold (PR-2).
    #[arg(long)]
    pub(crate) discover: bool,
    /// For `--discover`: the old provider's partial export past N.
    #[arg(long = "partial-export", value_name = "PATH")]
    pub(crate) partial: Option<PathBuf>,
    /// For `--discover`: a Decision Receipt JSON `{"position", "action", "exercise"}`; repeat.
    #[arg(long = "receipt", value_name = "PATH")]
    pub(crate) receipts: Vec<PathBuf>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn targets(list: &[String]) -> Result<Vec<Target>, String> {
    list.iter()
        .map(|w| {
            let (url, vkey) = w
                .split_once('=')
                .ok_or_else(|| format!("--witness {w}: not URL=VKEY"))?;
            Target::new(url, vkey, "declared", "recovering").map_err(|e| e.to_string())
        })
        .collect()
}

fn package(path: &PathBuf) -> Result<Streamed, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    read_stream(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// FR-1: the roots of every prefix of a full-disclosure package from Genesis.
pub(crate) fn roots_of(p: &Streamed) -> Result<Vec<[u8; 32]>, String> {
    if p.coverage != Coverage::Full || p.range.0 != 0 {
        return Err(String::from(
            "the records must be a full export from Genesis",
        ));
    }
    let leaves = p
        .records
        .iter()
        .map(|d| d.leaf_hash().map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let roots = prefix_roots(&leaves).map_err(|e| e.to_string())?;
    if roots.last() != Some(&p.root) {
        return Err(String::from(
            "the records do not reproduce the package's root",
        ));
    }
    Ok(roots)
}

fn head_view(h: Option<&WitnessHead>, t: &Target) -> Value {
    match h {
        Some(h) => json!({
            "witness": t.url,
            "size": h.head().size.to_string(),
            "root": b64url_encode(&h.head().root.0),
            "at": h.at().to_string(),
        }),
        None => json!({ "witness": t.url, "answered": false }),
    }
}

/// The plan as the root's AIS cites it.
pub(crate) fn plan_view(p: &Plan) -> Value {
    let cp = |c: &access_kernel::recovery::CheckpointRef| json!({ "size": c.size.to_string(), "root": b64url_encode(&c.root.0) });
    json!({
        "n": p.n.to_string(),
        "cited_checkpoint": cp(&p.cited),
        "replica_head": p.replica_head.as_ref().map(cp),
        "lost_suffix": p.lost_suffix.map(|l| json!({ "from": l.from.to_string(), "to": l.to.to_string() })),
        "fork": p.fork.iter().map(cp).collect::<Vec<_>>(),
        "arm": match p.arm { Arm::Replica => "i", Arm::Lossy => "ii" },
    })
}

fn revokes(action: &str) -> bool {
    action.ends_with("revoke") || action == "instance_terminate" || action == "party_depart"
}

/// PR-2: what the lost suffix past `n` may have revoked, from a partial export and receipts.
pub(crate) fn discover(n: u64, partial: Option<&Streamed>, receipts: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    for d in partial.map(|p| p.records.as_slice()).unwrap_or_default() {
        if d.header.pos < n || d.header.kind != RecordKind::Decision {
            continue;
        }
        let action = d
            .opened
            .get("intent")
            .and_then(|f| f.value.get("action"))
            .and_then(|a| a.get("name"))
            .and_then(|v| match v {
                suiss_crypto::dcbor::Value::Text(t) => Some(t.clone()),
                _ => None,
            });
        if action.as_deref().is_none_or(revokes) {
            out.push(json!({
                "source": "partial-export",
                "position": d.header.pos.to_string(),
                "action": action,
            }));
        }
    }
    for r in receipts {
        let pos = r
            .get("position")
            .and_then(Value::as_str)
            .and_then(|p| p.parse::<u64>().ok());
        let action = r.get("action").and_then(Value::as_str);
        if let (Some(pos), Some(action)) = (pos, action)
            && pos >= n
            && revokes(action)
        {
            out.push(json!({
                "source": "receipt",
                "position": pos.to_string(),
                "action": action,
                "exercise": r.get("exercise"),
            }));
        }
    }
    out
}

async fn report(args: &RecoverArgs) -> Result<Value, String> {
    let domain = b64url_decode(&args.domain)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .map(Digest)
        .ok_or("--domain: not a DomainID")?;
    let targets = targets(&args.witnesses)?;
    let records = package(&args.export)?;
    let roots = roots_of(&records)?;
    let heads = fetch_witness_heads(&targets, &domain).await;
    let p = plan(&heads, &roots, args.replica, now_ms()).map_err(|e| e.to_string())?;
    let mut v = plan_view(&p);
    if let Some(o) = v.as_object_mut() {
        o.insert(String::from("domain"), json!(args.domain));
        o.insert(
            String::from("witness_heads"),
            Value::Array(
                heads
                    .iter()
                    .zip(&targets)
                    .map(|(h, t)| head_view(h.as_ref(), t))
                    .collect(),
            ),
        );
        o.insert(
            String::from("quorum"),
            json!(if heads.iter().all(Option::is_some) {
                "complete"
            } else {
                "incomplete"
            }),
        );
    }
    if args.discover {
        let partial = args.partial.as_ref().map(package).transpose()?;
        let receipts = args
            .receipts
            .iter()
            .map(|r| {
                std::fs::read(r)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                    .ok_or_else(|| format!("{}: not a receipt", r.display()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let found = discover(p.n, partial.as_ref(), &receipts);
        if let Some(o) = v.as_object_mut() {
            o.insert(String::from("lost"), Value::Array(found));
            o.insert(
                String::from("redo"),
                json!("Each lost revocation is made again as its own revoke Exercise; nothing here changes the domain."),
            );
        }
    }
    Ok(v)
}

/// Runs `domain recover`.
pub(crate) async fn run(args: &RecoverArgs) -> Code {
    match report(args).await {
        Ok(v) => out(&format!(
            "{}\n",
            serde_json::to_string_pretty(&v).unwrap_or_default()
        )),
        Err(e) => {
            note(&format!("access-cli: domain recover: {e}"));
            exit::FAILED
        }
    }
}

#[cfg(test)]
mod tests;
