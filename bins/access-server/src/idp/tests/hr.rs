//! The HR-sourced lifecycle on the real commit path (OP-156 m.3 (q), OP-153 m.3 (gg), IDP-35,
//! TN-95, TN-109, AG-41, INV-16): an HR source registered by `idp.hr.source_register` has its
//! own issuer Party; an `idp.hr.import` writes its records in the decision's transaction or
//! nothing at all; the HR job states them as the source's HR Claims through Claim Ingest, which
//! quarantines them until the domain accepts the source for `subject-selection`; a start date
//! activates the staged account with a passkey setup invitation through Relay, and an end date
//! suspends it, ends its sessions and suspends the agents it sponsored.

#![allow(
    clippy::too_many_lines,
    reason = "test code: one person's HR life read in order"
)]

use std::sync::atomic::{AtomicU64, Ordering};

use access_authority_ingest::app::Ingest;
use access_identity_account::app::hr::{self as records, CLASSES, hr_line};
use access_identity_admin::app::hr::{HrJob, Vaults};
use access_identity_admin::app::rest::{Op, compile};
use access_identity_admin::domain::Invalid;
use access_identity_admin::domain::hr::HrChange;
use access_internal_api::idp::Verdict;
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::b64url_encode;

use super::*;
use crate::ingest::PgSubmissions;

const DAY: u64 = 86_400_000;

/// Claim Ingest's clock, moved by the test the way days pass.
pub(super) struct Moving(pub(super) Arc<AtomicU64>);

impl access_authority_ingest::ports::Clock for Moving {
    fn now(&self) -> impl Future<Output = Result<u64, Unavailable>> + Send {
        std::future::ready(Ok(self.0.load(Ordering::SeqCst)))
    }
}

pub(super) struct TestVaults<'a>(pub(super) &'a Opened);

impl Vaults for TestVaults<'_> {
    fn vault(&self, realm: RealmId) -> Option<access_identity_account::app::vault::Vault> {
        self.0.vault(realm)
    }
}

fn meta_intent(payload: &Payload) -> IntentEnvelope {
    IntentEnvelope {
        provenance: std::collections::BTreeMap::new(),
        action: meta::core_action(payload.action()),
        resources: vec![access_kernel::model::ResourceRef {
            namespace: String::from("access.party"),
            path: vec![String::from("p")],
            incarnation: 0,
        }],
        params: std::collections::BTreeMap::new(),
        opaque: std::collections::BTreeMap::from([(
            String::from(meta::PAYLOAD_PARAM),
            payload.digest().unwrap(),
        )]),
        recipient: None,
        purpose: None,
        context: access_kernel::intent::ContextRefs::default(),
        validity: Window {
            from: NOW,
            until: NOW + HOUR,
        },
    }
}

pub(super) async fn establish(w: &World, d: Digest, nonce: u8, content: Value) -> Verdict {
    let payload = Payload::AcceptanceEstablish(content);
    let intent = meta_intent(&payload);
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    let digest = intent_digest(&intent).unwrap();
    let ais = sign(&statement(d, &[nonce; 16], digest, basis), ROOT_KEY);
    w.plane
        .commit(
            access_authority_core::domain::Request {
                domain: d,
                mode: access_kernel::combinator::Mode::Commit,
                nonce: vec![nonce; 16],
                intent,
                payload: Some(payload),
                basis,
                capacity: Capacity::Own,
                proofs: Vec::new(),
                exercise: None,
                consistency: None,
            },
            ais,
            (String::from(PEP), None),
        )
        .await
        .unwrap()
}

/// The domain's `subject-selection` Acceptance of the HR source's issuer (TN-95, INV-16).
pub(super) fn selection(issuer: [u8; 16]) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), Id(issuer).to_value()),
        (
            Value::text("use"),
            Value::text(access_kernel::claim::SUBJECT_SELECTION),
        ),
        (
            Value::text("classes"),
            Value::Array({
                let mut classes = CLASSES.to_vec();
                classes.sort_unstable_by_key(|c| (c.len(), *c));
                classes.into_iter().map(Value::text).collect()
            }),
        ),
        (
            Value::text("subject"),
            access_kernel::model::SubjectSelector::Public.to_value(),
        ),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

pub(super) fn import_body(content: &str, records: u64) -> serde_json::Value {
    serde_json::json!({
        "file": b64url_encode(&records::file_digest(content)),
        "records": records,
        "content": content,
    })
}

pub(super) async fn import(
    w: &World,
    at: (TenantId, RealmId),
    d: Digest,
    content: &str,
    nonce: u8,
) {
    let n = u64::try_from(records::parse_jsonl(content).unwrap().len()).unwrap();
    let change =
        HrChange::import("workday", records::Format::Jsonl, &import_body(content, n)).unwrap();
    written(
        &exercise(
            w,
            &proposal(at, Change::Hr(change), nonce, idp_anchor(d), 1),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
}

pub(super) async fn status_of(
    w: &World,
    (t, r): (TenantId, RealmId),
    subject: [u8; 16],
) -> (String, i64) {
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let row = tx.subject(subject, false).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    (row.status, row.session_epoch)
}

/// Whether `subject`'s newest `class` Claim from the source is a live membership entry of the
/// domain: the Claim was admitted, not quarantined.
async fn admitted(
    w: &World,
    (t, r, d): (TenantId, RealmId, Digest),
    (subject, party): ([u8; 16], Id),
    class: &str,
) -> bool {
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let claim = access_store::issuer::last_in_line(
        &mut tx,
        &subject,
        &DomainId::from_bytes(d.0),
        &hr_line("workday", class),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let Some(claim) = claim else {
        return false;
    };
    let rows = access_store::authority::state_of(
        &w.db.app,
        &DomainId::from_bytes(d.0),
        &[access_kernel::claim::member_key(class, &party, &Id(claim))],
    )
    .await
    .unwrap();
    rows.iter().any(|row| row.value.is_some())
}

/// Every identity outbox kind of the test's database once `want` is among them. The outbox
/// watermark is cluster-wide, so another test's open transaction delays an event, never loses
/// it.
pub(super) async fn kinds(w: &World, want: &str) -> Vec<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let mut out = Vec::new();
        let mut at = access_store::identity::Cursor::default();
        loop {
            let page = access_store::identity::poll(&w.db.reader, at, 500)
                .await
                .unwrap();
            let Some(last) = page.last() else {
                break;
            };
            at = access_store::identity::Cursor {
                xid: last.xid,
                id: last.id,
            };
            out.extend(page.into_iter().map(|e| e.kind));
        }
        if out.iter().any(|k| k == want) {
            return out;
        }
        assert!(std::time::Instant::now() < deadline, "{want}: {out:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// IDP-35, TN-95, INV-16, OP-156 m.3 (q), (gg), Ek B 5148, 5150, 5151, 5179
#[tokio::test]
async fn an_hr_source_selects_only_when_accepted_and_its_dates_start_and_end_the_account() {
    let w = World::new().await;
    let (t, r, d) = w.realm_with("hr-life", Some(0)).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let register = HrChange::register_source(&serde_json::json!({"name": "workday"})).unwrap();
    written(
        &exercise(
            &w,
            &proposal((t, r), Change::Hr(register.clone()), 0x51, idp_anchor(d), 1),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    // OP-73
    assert!(matches!(
        w.admin()
            .prepare(&proposal(
                (t, r),
                Change::Hr(register),
                0x52,
                idp_anchor(d),
                1
            ))
            .await,
        Err(AdminError::Invalid(Invalid::HrSourceExists))
    ));
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let source = tx.hr_source("workday").await.unwrap().unwrap();
    tx.commit().await.unwrap();
    assert_ne!(source.issuer, ROOT.0);

    // OP-156 m.3 (q)
    let csv = "employee_id,email,salary\nE1,ada@acme.example,1\nE2,bob@acme.example,2\n";
    assert_eq!(
        compile(
            Op::ImportHrCsv,
            Some("workday"),
            &import_body(csv, 2),
            &w.ids
        ),
        Err(Invalid::HrRecords)
    );
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    assert_eq!(tx.hr_people("workday").await.unwrap(), 0);
    tx.commit().await.unwrap();

    let first = concat!(
        r#"{"employee_id":"E1","email":"ada@acme.example","department":"R&D","#,
        r#""title":"Engineer","start_date":"1970-01-02"}"#,
    );
    import(&w, (t, r), d, first, 0x53).await;
    let vault = w.keys.vault(r).unwrap();
    let mut tx = access_identity_account::adapters::pg::PgTx(
        TenantTx::begin(&w.db.app, t, r).await.unwrap(),
        Some(vault.clone()),
    );
    let ada = access_identity_account::ports::AccountTx::subject_by_identifier(
        &mut tx,
        "ada@acme.example",
    )
    .await
    .unwrap()
    .unwrap();
    tx.0.commit().await.unwrap();
    // OP-156 m.3 (q)
    let (status, epoch) = status_of(&w, (t, r), ada).await;
    assert_eq!(status, "staged");
    assert!(
        !access_identity_account::domain::status::AccountStatus::parse(&status)
            .unwrap()
            .can_authenticate()
    );
    import(&w, (t, r), d, first, 0x54).await;

    let clock = Arc::new(AtomicU64::new(NOW));
    let ingest = Ingest::new(
        w.plane.domains.clone(),
        PgSubmissions(w.db.app.clone()),
        Moving(Arc::clone(&clock)),
    );
    let vaults = TestVaults(&w.keys);
    let job = HrJob {
        app: &w.db.app,
        reader: &w.db.reader,
        ingest: &ingest,
        vaults: &vaults,
        ids: &w.ids,
    };
    for day in 0..6_u32 {
        access_store::claims::open_claim_ingest_day(&w.db.archive, day)
            .await
            .unwrap();
    }
    let ran = job.run_once(NOW).await.unwrap();
    assert_eq!((ran.claims, ran.applied), (0, 0));
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut tx, &ada, &ALICE.0)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    // INV-16, TN-95
    let ran = job.run_once(NOW).await.unwrap();
    assert_eq!(ran.claims, 3);
    assert!(!admitted(&w, (t, r, d), (ada, ALICE), "hr_department").await);

    // §13.7.1, INV-16
    let v = establish(&w, d, 0x72, selection(source.issuer)).await;
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");

    // TN-109
    let mover = concat!(
        r#"{"employee_id":"E1","email":"ada@acme.example","department":"Finance","#,
        r#""title":"Engineer","start_date":"1970-01-02"}"#,
    );
    import(&w, (t, r), d, mover, 0x55).await;
    job.run_once(NOW).await.unwrap();
    // INV-16
    assert!(admitted(&w, (t, r, d), (ada, ALICE), "hr_title").await);
    assert!(admitted(&w, (t, r, d), (ada, ALICE), "hr_start").await);
    assert!(!admitted(&w, (t, r, d), (ada, ALICE), "hr_department").await);
    let cooling = |w: &World| {
        let w = w.db.app.clone();
        async move {
            let mut tx = TenantTx::begin(&w, t, r).await.unwrap();
            let vault = TestVaults(&Opened::default()).vault(r).unwrap();
            let person =
                records::person(&vault, (t.as_bytes(), r.as_bytes()), "workday", "E1").unwrap();
            let v = tx.hr_record_versions("workday", &person).await.unwrap();
            tx.commit().await.unwrap();
            v.last().unwrap().claims.clone()
        }
    };
    assert_eq!(cooling(&w).await, None, "the new department waits");

    let start = NOW + records::COOLING_MS;
    clock.store(start, Ordering::SeqCst);
    let ran = job.run_once(start).await.unwrap();
    assert_eq!((ran.due, ran.applied), (1, 1));
    assert_eq!(cooling(&w).await.as_deref(), Some("issued"));
    assert_eq!(status_of(&w, (t, r), ada).await.0, "active");
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let invites = tx.hr_invites(ada).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        invites,
        vec![(true, start, start + records::INVITE_TTL_MS)],
        "one-use, 7 days"
    );
    let queued = kinds(&w, "relay.message.passkey_setup_invite.v1").await;
    assert!(queued.iter().any(|k| k == "event.hr.record_due"));
    assert_eq!(job.run_once(start).await.unwrap().applied, 0);

    // AG-41
    let agent = [0x7a; 16];
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    tx.insert_agent(&access_store::agents::NewAgent {
        party: agent,
        operator: ALICE.0,
        kind: "cloud",
        display_name: "Helper",
        description: None,
        exercise: &[0x7b; 32],
    })
    .await
    .unwrap();
    tx.open_sponsorship(agent, ada, &[0x7c; 32]).await.unwrap();
    tx.commit().await.unwrap();

    let leaver = concat!(
        r#"{"employee_id":"E1","email":"ada@acme.example","department":"Finance","#,
        r#""title":"Engineer","start_date":"1970-01-02","end_date":"1970-01-05"}"#,
    );
    import(&w, (t, r), d, leaver, 0x56).await;
    let end = 4 * DAY;
    clock.store(end, Ordering::SeqCst);
    let ran = job.run_once(end).await.unwrap();
    assert_eq!(ran.applied, 1);
    let (status, after) = status_of(&w, (t, r), ada).await;
    assert_eq!(status, "suspended");
    assert!(after > epoch, "{after} > {epoch}");
    kinds(&w, "signal.session_revoked").await;
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    assert_eq!(tx.agent(agent).await.unwrap().unwrap().status, "suspended");
    tx.commit().await.unwrap();

    let retire = HrChange::retire_source("workday", &serde_json::json!({})).unwrap();
    written(
        &exercise(
            &w,
            &proposal((t, r), Change::Hr(retire), 0x57, idp_anchor(d), 1),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let change =
        HrChange::import("workday", records::Format::Jsonl, &import_body(first, 1)).unwrap();
    assert!(matches!(
        w.admin()
            .prepare(&proposal(
                (t, r),
                Change::Hr(change),
                0x58,
                idp_anchor(d),
                1
            ))
            .await,
        Err(AdminError::Invalid(Invalid::NoHrSource))
    ));
}
