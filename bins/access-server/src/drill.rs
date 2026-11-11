//! The restore drill (OP-57, §17.10.3, OP-158 m.3 (r)): `access-server drill baseline` records
//! what a restore must bring back, and `access-server drill restore <baseline.json>` runs the
//! nine items, in order, on the restored environment. The report's digest is written to the
//! identity audit log as `drill.restore`, so the cell's signed audit checkpoint covers it.
//!
//! Items that need the backup tool's own evidence (the RTO timings, `pgbackrest verify`) take
//! it as input and are `not-run` without it; nothing is assumed to pass.

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::cell::{Witnessed, replay};
use access_kernel::digest::Digest;
use access_store::Pool;
use access_store::identity::TenantTx;
use access_store::scope::DomainId;
use serde::{Deserialize, Serialize};

/// One domain's head and witnessed size as the baseline saw it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainMark {
    /// Head position.
    pub(crate) pos: u64,
    /// Size of the newest independently witnessed checkpoint; 0 when none.
    pub(crate) witnessed: u64,
}

/// What a restore of this cell must bring back.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Baseline {
    /// When it was taken, Unix milliseconds: the PITR target unless the input names another.
    pub(crate) at_ms: u64,
    /// Every live realm's JWKS `kid`s, by slug.
    pub(crate) kids: BTreeMap<String, BTreeSet<String>>,
    /// Every domain's head, by base64url domain id.
    pub(crate) domains: BTreeMap<String, DomainMark>,
    /// The PITR target, when it is not `at_ms`.
    #[serde(default)]
    pub(crate) target_ms: Option<u64>,
    /// Measured restore times (item 5): with and without tuned parallelism, milliseconds.
    #[serde(default)]
    pub(crate) rto_ms: Option<(u64, u64)>,
    /// Whether the backup tool verified the repository (item 6), e.g. `pgbackrest verify`.
    #[serde(default)]
    pub(crate) repo_verified: Option<bool>,
}

/// How one item ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Status {
    /// It held.
    Pass,
    /// It did not; the environment is not opened to traffic.
    Fail,
    /// Its evidence was not given or the deployment lacks the part.
    NotRun,
}

/// One item of the report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Item {
    /// 1 to 9, the order of §17.10.3.
    pub(crate) n: u8,
    /// What it checks.
    pub(crate) name: &'static str,
    /// How it ended.
    pub(crate) status: Status,
    /// What was found.
    pub(crate) detail: String,
}

/// The drill's report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Report {
    /// The nine items in order.
    pub(crate) items: Vec<Item>,
    /// Whether none failed.
    pub(crate) passed: bool,
    /// SHA-256 of the items' JSON, base64url, as the audit row names it.
    pub(crate) digest: String,
}

/// The pools and keys the drill reads.
pub(crate) struct Env<'a, R> {
    pub(crate) app: &'a Pool,
    pub(crate) router: &'a Pool,
    pub(crate) sequencer: &'a Pool,
    pub(crate) migrator: Option<&'a Pool>,
    pub(crate) realm_keys: &'a R,
    pub(crate) event_key: &'a (dyn Fn(&Digest) -> bool + Sync),
    pub(crate) cold: Option<&'a access_identity_export::adapters::cold_file::FileCold>,
    pub(crate) breakglass: Option<&'a (dyn Fn() -> Result<usize, String> + Sync)>,
}

fn b64(d: &Digest) -> String {
    access_kernel::json::b64url_encode(&d.0)
}

/// Every live realm and the domains bound to it.
async fn domains(app: &Pool, router: &Pool) -> Result<Vec<Digest>, String> {
    let mut out = BTreeSet::new();
    for r in access_store::tenancy::routes(router)
        .await
        .map_err(|e| e.to_string())?
    {
        let mut t = TenantTx::begin(app, r.tenant, r.realm)
            .await
            .map_err(|e| e.to_string())?;
        for (d, _) in access_store::realm_binding::domains(&mut t, r.realm)
            .await
            .map_err(|e| e.to_string())?
        {
            out.insert(Digest(*d.as_bytes()));
        }
        t.commit().await.map_err(|e| e.to_string())?;
    }
    Ok(out.into_iter().collect())
}

fn kids_of(jwks: &str) -> BTreeSet<String> {
    serde_json::from_str::<serde_json::Value>(jwks)
        .ok()
        .and_then(|v| v.get("keys").and_then(|k| k.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|k| k.get("kid").and_then(|k| k.as_str()).map(String::from))
        .collect()
}

async fn kids<R: access_identity_admin::ports::RealmKeys>(
    router: &Pool,
    keys: &R,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut out = BTreeMap::new();
    for r in access_store::tenancy::routes(router)
        .await
        .map_err(|e| e.to_string())?
    {
        let jwks = keys
            .jwks(r.realm)
            .await
            .map_err(|_| format!("realm {}: the JWKS does not load", r.slug))?;
        out.insert(r.slug, kids_of(&jwks));
    }
    Ok(out)
}

/// The baseline of this cell now (OP-57): taken before the backup a drill restores.
///
/// # Errors
/// What could not be read.
pub(crate) async fn baseline<R: access_identity_admin::ports::RealmKeys>(
    env: &Env<'_, R>,
    at_ms: u64,
) -> Result<Baseline, String> {
    let mut marks = BTreeMap::new();
    for d in domains(env.app, env.router).await? {
        let id = DomainId::from_bytes(d.0);
        let head = access_store::authority::read_head(env.sequencer, &id)
            .await
            .map_err(|e| e.to_string())?;
        let witnessed = access_store::witness::latest_witnessed(env.app, &id, None)
            .await
            .map_err(|e| e.to_string())?
            .map_or(0, |c| c.size);
        marks.insert(
            b64(&d),
            DomainMark {
                pos: head.pos,
                witnessed,
            },
        );
    }
    Ok(Baseline {
        at_ms,
        kids: kids(env.router, env.realm_keys).await?,
        domains: marks,
        ..Baseline::default()
    })
}

fn item(n: u8, name: &'static str, r: Result<Option<String>, String>) -> Item {
    let (status, detail) = match r {
        Ok(Some(d)) => (Status::Pass, d),
        Ok(None) => (Status::NotRun, String::from("no evidence given")),
        Err(d) => (Status::Fail, d),
    };
    Item {
        n,
        name,
        status,
        detail,
    }
}

async fn pitr(
    env: &Env<'_, impl Sync>,
    base: &Baseline,
    all: &[Digest],
) -> Result<Option<String>, String> {
    let target = base.target_ms.unwrap_or(base.at_ms);
    let mut newest = 0;
    for d in all {
        let head = access_store::authority::read_head(env.sequencer, &DomainId::from_bytes(d.0))
            .await
            .map_err(|e| e.to_string())?;
        newest = newest.max(head.recorded_at);
    }
    if newest > target {
        return Err(format!(
            "a record of {newest} is after the recovery target {target}"
        ));
    }
    Ok(Some(format!(
        "newest record {newest} at or before {target}"
    )))
}

async fn domain_log(
    env: &Env<'_, impl Sync>,
    base: &Baseline,
    d: Digest,
) -> Result<String, String> {
    let id = DomainId::from_bytes(d.0);
    let img = access_store::cells::image(env.sequencer, &id)
        .await
        .map_err(|e| e.to_string())?;
    let witnessed = access_store::witness::latest_witnessed(env.app, &id, None)
        .await
        .map_err(|e| e.to_string())?
        .map(|c| Witnessed {
            size: c.size,
            root: c.root,
        });
    let replayed = replay(d, &img, witnessed).map_err(|e| format!("{}: {e}", b64(&d)))?;
    if let Some(w) = witnessed
        && replayed.witnessed_root != Some(w.root)
    {
        return Err(format!(
            "{}: the witnessed checkpoint {} differs",
            b64(&d),
            w.size
        ));
    }
    // OP-57, FA-10: a log behind what the witnesses saw is not opened; its suffix comes from the
    // replica, or the domain is recovered
    let size = img.head.head.pos.saturating_add(1);
    if let Some(mark) = base.domains.get(&b64(&d))
        && mark.witnessed > size
    {
        return Err(format!(
            "{}: restored to {size} records, behind the witnessed {}; complete it from the replica or recover the domain",
            b64(&d),
            mark.witnessed
        ));
    }
    Ok(format!("{}: {size} records replay", b64(&d)))
}

/// Runs the nine items in order (§17.10.3).
///
/// # Errors
/// Only when the report cannot be recorded; a failed item is a failed report, not an error.
#[expect(clippy::too_many_lines, reason = "the nine items in their order")]
pub(crate) async fn restore<R: access_identity_admin::ports::RealmKeys>(
    env: &Env<'_, R>,
    base: &Baseline,
) -> Result<Report, String> {
    let all = domains(env.app, env.router).await;
    let mut items = Vec::with_capacity(9);
    let listed = all.clone().unwrap_or_default();
    items.push(item(
        1,
        "point-in-time recovery to the target",
        match &all {
            Ok(d) => pitr(env, base, d).await,
            Err(e) => Err(e.clone()),
        },
    ));
    let now_kids = kids(env.router, env.realm_keys).await;
    items.push(item(2, "signing keys restored together", {
        let missing: Vec<String> = listed
            .iter()
            .filter(|d| !(env.event_key)(d))
            .map(b64)
            .collect();
        match (&now_kids, missing.is_empty()) {
            (Err(e), _) => Err(e.clone()),
            (Ok(_), false) => Err(format!("no event key for {}", missing.join(", "))),
            (Ok(k), true) => Ok(Some(format!(
                "{} realms' key sets and {} domains' keys load",
                k.len(),
                listed.len()
            ))),
        }
    }));
    items.push(item(
        3,
        "JWKS serves the same kids",
        match &now_kids {
            Err(e) => Err(e.clone()),
            Ok(k) if *k == base.kids => Ok(Some(format!("{} realms match", k.len()))),
            Ok(k) => Err(format!(
                "realms differ: {:?}",
                k.iter()
                    .filter(|(slug, set)| base.kids.get(*slug) != Some(*set))
                    .map(|(slug, _)| slug.as_str())
                    .chain(
                        base.kids
                            .keys()
                            .filter(|s| !k.contains_key(*s))
                            .map(String::as_str)
                    )
                    .collect::<Vec<_>>()
            )),
        },
    ));
    items.push(item(
        4,
        "the schema version fits this binary",
        match env.migrator {
            None => Ok(None),
            Some(m) => match access_store::connect::applied_newest(m).await {
                Ok(Some(v)) if access_store::MIGRATOR.iter().any(|x| x.version == v) => Ok(Some(
                    format!("newest applied migration {v} is this binary's"),
                )),
                Ok(Some(v)) => Err(format!("migration {v} is unknown to this binary")),
                Ok(None) => Err(String::from("no migration applied")),
                Err(e) => Err(e.to_string()),
            },
        },
    ));
    items.push(item(
        5,
        "restore time measured, tuned and untuned",
        Ok(base
            .rto_ms
            .map(|(t, u)| format!("tuned {t} ms, untuned {u} ms"))),
    ));
    items.push(item(
        6,
        "repository integrity verified",
        match base.repo_verified {
            None => Ok(None),
            Some(true) => Ok(Some(String::from(
                "the backup tool verified the repository",
            ))),
            Some(false) => Err(String::from(
                "the backup tool did not verify the repository",
            )),
        },
    ));
    items.push(item(
        7,
        "deletion facts applied again",
        match crate::reshred::gate(env.app, env.cold).await {
            Ok(()) => Ok(Some(String::from(
                "no restore generation waits for a re-shred",
            ))),
            Err(e) => Err(e),
        },
    ));
    let mut logs = Vec::new();
    let mut failed = None;
    for d in &listed {
        match domain_log(env, base, *d).await {
            Ok(l) => logs.push(l),
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    items.push(item(
        8,
        "authority logs replay to their witnessed checkpoints",
        match (&all, failed) {
            (Err(e), _) => Err(e.clone()),
            (Ok(_), Some(e)) => Err(e),
            (Ok(_), None) => Ok(Some(logs.join("; "))),
        },
    ));
    items.push(item(
        9,
        "the break-glass path works",
        match env.breakglass {
            None => Ok(None),
            Some(read) => read().map(|n| Some(format!("{n} directives read"))),
        },
    ));
    let body = serde_json::to_vec(&items).map_err(|e| e.to_string())?;
    let digest = access_kernel::json::b64url_encode(&suiss_crypto::digest::sha256(&body));
    let passed = items.iter().all(|i| i.status != Status::Fail);
    let target = format!("report:{digest}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    access_store::operational::record_operational(
        env.app,
        &access_store::operational::OperationalEvent {
            occurred_at_ms: now,
            tenant: None,
            domain: None,
            event_type: "drill.restore",
            actor: "drill",
            target: &target,
            reason: if passed { "passed" } else { "failed" },
            correlation: "drill",
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(Report {
        items,
        passed,
        digest,
    })
}
