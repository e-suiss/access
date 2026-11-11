//! The local deployment's Stage 12 fixtures on the real path (OP-157 m.6 (i), OP-153 m.3 (gg)):
//! the bootstrap makes a support operator in its organization with a registered case system and
//! the test user's open case, a marked break-glass account with its two pre-issued Grants, and
//! an access review whose manager sees the sample agent's Grant; a second run changes nothing.

use access_identity_account::app::SUBJECT_PREFIX;

use super::*;
use crate::bootstrap::agent::SampleAgentPlan;
use crate::bootstrap::governance::{BreakglassPlan, ReviewPlan, SupportOperatorPlan};

pub(super) fn fixtures_plan() -> Plan {
    Plan {
        sample_agent: Some(SampleAgentPlan {
            realm: String::from("acme"),
            display_name: String::from("Local sample agent"),
        }),
        support_operator: Some(SupportOperatorPlan {
            realm: String::from("acme"),
            display_name: String::from("Mehmet Y."),
            organisation: String::from("Acme Support"),
            identifier: String::from("support@acme.example"),
            password: Secret::new(String::from("operator horse battery staple")),
            case_system: String::from("local-desk"),
            case: String::from("4411"),
        }),
        breakglass_account: Some(BreakglassPlan {
            realm: String::from("acme"),
            identifier: String::from("oncall@acme.example"),
            organisation: String::from("Acme Security"),
        }),
        review_schedule: Some(ReviewPlan {
            realm: String::from("acme"),
            name: String::from("local-review"),
            period_days: 90,
        }),
        ..approve_plan(None)
    }
}

// OP-157 m.6 (i), m.3 (e), (f), (h), (w), m.10, TN-5, TN-73, CMP-8, OP-69, OP-153 m.3 (gg)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bootstrap_makes_the_stage_twelve_fixtures_once_through_their_exercises() {
    let (w, signer) = World::open("bootstrap-fixtures", true).await;
    let signer = signer.unwrap();
    schedule(&signer);
    schedule(&signer);
    // OP-146 m.5 (f)
    crate::jobs::open_now(&w.db.app, &w.db.archive, "bootstrap-fixtures").await;
    let first = serde_json::to_value(w.run(&fixtures_plan()).await).unwrap();
    let support = &first["support_operator"];
    assert_eq!(support["created"], true, "{first}");
    assert_eq!(support["acceptance"], "accepted", "{support}");
    assert!(support["case_until"].as_u64().is_some(), "{support}");
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let operator = ids
        .decode(SUBJECT_PREFIX, support["subject"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        idp::subject_party(&mut t, &operator).await.unwrap(),
        Some(id_of(support["party"].as_str().unwrap()).0)
    );
    // OP-157 m.3 (e)
    let systems = t.case_systems().await.unwrap();
    let system = systems.iter().find(|c| c.name == "local-desk").unwrap();
    assert!(system.live);
    assert_eq!(
        b64url_encode(&system.issuer),
        support["case_issuer"].as_str().unwrap()
    );
    // TN-5, OP-157 m.6 (f)
    let org = t
        .org_by_party(id_of(support["organisation_party"].as_str().unwrap()).0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(org.display_name, "Acme Support");
    assert!(
        t.memberships(org.id)
            .await
            .unwrap()
            .iter()
            .any(|m| m.subject == operator)
    );
    assert!(
        t.orgs_of(operator)
            .await
            .unwrap()
            .iter()
            .any(|(o, _)| !o.ended)
    );

    // OP-157 m.3 (h), m.10
    let breakglass = &first["breakglass_account"];
    assert_eq!(breakglass["created"], true, "{first}");
    let account = ids
        .decode(SUBJECT_PREFIX, breakglass["subject"].as_str().unwrap())
        .unwrap();
    let marked = t.breakglass_accounts().await.unwrap();
    assert!(
        marked.iter().any(|a| a.subject == account
            && b64url_encode(&a.org) == breakglass["organisation_party"].as_str().unwrap()),
        "{marked:?}"
    );
    let grants = breakglass["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 2, "{breakglass}");
    let holders: BTreeSet<&str> = grants
        .iter()
        .map(|g| g["holding"]["holder"].as_str().unwrap())
        .collect();
    assert!(holders.contains(breakglass["party"].as_str().unwrap()));
    assert!(holders.contains(first["test_user"]["party"].as_str().unwrap()));

    // OP-157 m.3 (w), IDP-39 (3)
    let review = &first["review_schedule"];
    assert_eq!(review["created"], true, "{first}");
    assert!(review["items"].as_u64().unwrap() >= 1, "{review}");
    assert_eq!(review["manager"], first["test_user"]["party"]);
    assert!(
        t.review_schedules()
            .await
            .unwrap()
            .iter()
            .any(|r| r.name == "local-review" && r.live && r.period_days == 90)
    );
    t.commit().await.unwrap();

    // OP-69
    schedule(&signer);
    let second = serde_json::to_value(w.run(&fixtures_plan()).await).unwrap();
    for section in ["support_operator", "breakglass_account", "review_schedule"] {
        assert_eq!(second[section]["created"], false, "{section}: {second}");
    }
    assert_eq!(second["support_operator"]["party"], support["party"]);
    assert_eq!(
        second["support_operator"]["case_until"],
        support["case_until"]
    );
    assert_eq!(second["breakglass_account"]["grants"], breakglass["grants"]);
    assert_eq!(second["review_schedule"]["items"], review["items"]);
}
