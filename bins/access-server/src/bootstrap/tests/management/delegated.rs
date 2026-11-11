//! Delegated administration through the real router and the sequencer (§2.2.1, §12.5.2, TN-114,
//! INV-10, C28, X20, OP-157 m.3 (t)): meta-action role Grants open with the realm's staged flag,
//! an admin never gives more than it holds, closing the flag does not reach back, and a role
//! version moves only by an explicit `grant.amend`.

use access_http::adp::payload::{authority_set_to_json, canonical_authority_to_json};
use access_internal_api::idp::IdpAction;
use access_kernel::meta::{self as kmeta, ExerciseBasis, HoldingRef, kind};
use access_kernel::model::{ActionSet, AuthoritySet, Id, ResourceSelector, Structural};

use super::writes::{Written, basis_json, canonical, exercise_of, role};
use super::*;

/// An admin set over the meta-actions `names` on the objects of `namespace`.
fn admin_on(namespace: &str, names: &[&str]) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: names.iter().map(|n| kmeta::core_action(n)).collect(),
            prefix: std::collections::BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: namespace.to_owned(),
            prefix: Vec::new(),
            kind: None,
            attrs: std::collections::BTreeMap::new(),
        }),
        params: std::collections::BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

impl Console {
    async fn flag(&self, enabled: bool) -> Written {
        self.put_setting(
            "delegated-admin",
            "putDelegatedAdmin",
            serde_json::json!({ "enabled": enabled }),
        )
        .await
    }

    /// The founder's `grant_issue` of `set` to itself from `from`, delegable when `depth` > 0.
    async fn issue_admin(&self, from: serde_json::Value, set: AuthoritySet, depth: u64) -> Written {
        let mut authority = canonical(set);
        authority.delegation.depth = depth;
        let issue = serde_json::json!({ "grant_issue": {
            "basis": from,
            "holder": { "party": b64url_encode(&self.root.0) },
            "authority": canonical_authority_to_json(&authority).unwrap(),
        } });
        self.meta_write("grant_issue", issue, self.meta_anchor())
            .await
    }

    /// The founder's holding of the Grant the committed `w` issued.
    async fn holding_of(&self, w: &Written) -> HoldingRef {
        let grant: Id = kmeta::object_id(&exercise_of(w), kind::GRANT, 0);
        assert!(self.w.domains.derive().await.is_empty());
        let holdings = self.search("holdings", serde_json::json!({})).await;
        let since = holdings["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["grant"] == b64url_encode(&grant.0))
            .and_then(|h| h["since"].as_u64())
            .unwrap();
        HoldingRef {
            grant,
            holder: self.root,
            since,
        }
    }

    fn meta_anchor_json(&self) -> serde_json::Value {
        serde_json::json!({ "anchor": b64url_encode(&kmeta::meta_anchor(&self.domain).0) })
    }
}

/// The decision shows a restriction; the blocker's subcode is for the root's own view
/// (§9.14.2): [`delegated::OFF`] is pinned in the authority-core test.
fn refused_as_off(w: &Written) {
    assert_eq!(w.body["decision"], false, "{}", w.body);
    assert_eq!(
        w.body["context"]["blockers"][0]["class"], "restricted",
        "{}",
        w.body
    );
}

// TN-114, §12.5.2, §2.2.1, X20, OP-157 m.3 (t), Ek B 5492, 5592, 5453
#[tokio::test]
async fn a_new_admin_grant_waits_for_the_realm_flag_and_closing_does_not_reach_back() {
    let c = console("v8-flag", true).await;
    let revoke = admin_on("access.grant", &["grant_revoke"]);
    let anchor = c.meta_anchor_json();
    let off = c.issue_admin(anchor.clone(), revoke.clone(), 0).await;
    refused_as_off(&off);

    let opened = c.flag(true).await;
    assert_eq!(opened.status, StatusCode::OK, "{}", opened.body);
    let issued = c.issue_admin(anchor.clone(), revoke, 0).await;
    assert_eq!(issued.body["decision"], true, "{}", issued.body);
    let held = c.holding_of(&issued).await;

    let closed = c.flag(false).await;
    assert_eq!(closed.status, StatusCode::OK, "{}", closed.body);
    refused_as_off(
        &c.issue_admin(anchor, admin_on("access.grant", &["grant_amend"]), 0)
            .await,
    );

    // OP-157 m.3 (t)
    let target = c.issue_to_founder().await;
    let revoke = serde_json::json!({ "grant_revoke": { "grant": b64url_encode(&target.0) } });
    let done = c
        .meta_write("grant_revoke", revoke, ExerciseBasis::Holding(held))
        .await;
    assert_eq!(done.body["decision"], true, "{}", done.body);
}

// INV-10, TN-114, §12.5.2, Ek B 5492, 5592
#[tokio::test]
async fn an_admin_never_gives_a_meta_action_above_its_own_set() {
    let c = console("v8-inv10", true).await;
    assert_eq!(c.flag(true).await.status, StatusCode::OK);
    let anchor = c.meta_anchor_json();
    let parent = c
        .issue_admin(anchor, admin_on("access.domain", &["grant_issue"]), 1)
        .await;
    assert_eq!(parent.body["decision"], true, "{}", parent.body);
    let held = c.holding_of(&parent).await;
    let basis = ExerciseBasis::Holding(held);

    let child = |set: AuthoritySet| {
        let mut authority = canonical(set);
        authority.constraints.validity.until -= 3_600_000;
        serde_json::json!({ "grant_issue": {
            "basis": basis_json(basis),
            "holder": { "party": b64url_encode(&c.root.0) },
            "authority": canonical_authority_to_json(&authority).unwrap(),
        } })
    };
    let wider = c
        .meta_write(
            "grant_issue",
            child(admin_on("access.domain", &["grant_issue", "policy_set"])),
            basis,
        )
        .await;
    assert_eq!(wider.body["decision"], false, "{}", wider.body);
    let within = c
        .meta_write(
            "grant_issue",
            child(admin_on("access.domain", &["grant_issue"])),
            basis,
        )
        .await;
    assert_eq!(within.body["decision"], true, "{}", within.body);
}

// TN-114, C28, X20, OP-157 m.3 (t), Ek B 5655
#[tokio::test]
async fn a_new_role_version_moves_no_grant_by_itself() {
    let c = console("v8-no-auto", true).await;
    let v1 = role(&[IdpAction::AccountSuspend, IdpAction::AccountReactivate]);
    let v2 = role(&[IdpAction::AccountSuspend]);
    let define = |set: &AuthoritySet| {
        serde_json::json!({ "authority_set_define": {
            "name": "helpdesk",
            "authority": authority_set_to_json(set).unwrap(),
        } })
    };
    for set in [&v1, &v2] {
        let w = c
            .meta_write("authority_set_define", define(set), c.meta_anchor())
            .await;
        assert_eq!(w.body["decision"], true, "{}", w.body);
    }
    let idp = kmeta::object_id(&c.domain, kind::ANCHOR, IDP_ANCHOR);
    let issue = serde_json::json!({ "grant_issue": {
        "basis": { "anchor": b64url_encode(&idp.0) },
        "holder": { "party": b64url_encode(&c.root.0) },
        "authority": canonical_authority_to_json(&canonical(v1.clone())).unwrap(),
        "named": {
            "name": "helpdesk",
            "version": 1,
            "digest": b64url_encode(&kmeta::authority_set_digest(&v1).0),
        },
    } });
    let w = c.meta_write("grant_issue", issue, c.idp_anchor()).await;
    assert_eq!(w.body["decision"], true, "{}", w.body);
    let grant: Id = kmeta::object_id(&exercise_of(&w), kind::GRANT, 0);
    assert!(c.w.domains.derive().await.is_empty());

    let view = c
        .search(
            "admin-grant",
            serde_json::json!({ "grant": b64url_encode(&grant.0) }),
        )
        .await;
    let held = &view["results"][0];
    assert_eq!(held["role"]["name"], "helpdesk", "{view}");
    assert_eq!(
        held["role"]["version"], 1,
        "a new version moves no one: {view}"
    );
}
