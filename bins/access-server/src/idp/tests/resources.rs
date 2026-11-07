//! The realm resources the management API adds, through commit against real PostgreSQL and the
//! authority plane (OP-151 m.2 M1): groups and their one membership issuer, account
//! suspension, upstream registrations, the sign-in and session policies and secret rotation.

use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_admin::app::rest::{Kind, Op, compile};
use access_identity_admin::domain::Invalid;
use serde_json::json;

use super::*;

async fn ready(slug: &str) -> (World, (TenantId, RealmId), Digest) {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm(slug).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    (w, (tenant, realm), d)
}

async fn run(
    w: &World,
    at: (TenantId, RealmId),
    d: Digest,
    change: Change,
    nonce: u8,
) -> Result<Applied, AdminError> {
    exercise(w, &proposal(at, change, nonce, idp_anchor(d), 1), ROOT_KEY).await
}

/// Why the realm refuses `change` before anything is signed or committed.
async fn refused(
    w: &World,
    at: (TenantId, RealmId),
    d: Digest,
    change: Change,
    nonce: u8,
) -> Invalid {
    match w
        .admin()
        .prepare(&proposal(at, change, nonce, idp_anchor(d), 1))
        .await
    {
        Err(AdminError::Invalid(i)) => i,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("prepared"),
    }
}

// TN-117: a group has one membership issuer; members change through idp.group.members_* only
// when the administration issues them, and the issuer never changes
#[tokio::test]
async fn a_group_keeps_its_one_membership_issuer() {
    let (w, at, d) = ready("groups").await;
    let up = compile(
        Op::PutUpstream,
        Some("google"),
        &json!({"issuer": "https://accounts.google.com", "client_id": "c",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                "ssf": {"issuer": "https://accounts.google.com",
                        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                        "aud": "https://groups.id.test",
                        "events": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"]}}),
        &w.ids,
    )
    .unwrap();
    written(&run(&w, at, d, up, 1).await.unwrap());
    // OP-151 m.7 (g): the registration declared the provider as an inbound transmitter
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let transmitters = t.transmitters().await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(transmitters.len(), 1);
    assert_eq!(transmitters[0].issuer, "https://accounts.google.com");
    let staff = |issuer: &str| {
        compile(
            Op::PutGroup,
            Some("staff"),
            &json!({"display_name": "Staff", "membership_issuer": issuer}),
            &w.ids,
        )
        .unwrap()
    };
    written(&run(&w, at, d, staff("upstream:google"), 2).await.unwrap());
    let resolved = w.admin().resolve(at.0, at.1, staff("admin")).await.unwrap();
    assert!(
        matches!(resolved, Change::GroupUpdate(_)),
        "a PUT on an existing group updates"
    );
    assert_eq!(
        refused(&w, at, d, resolved, 3).await,
        Invalid::MembershipIssuer
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let subject = t.insert_subject("active", "kek-1", &[1; 40]).await.unwrap();
    t.commit().await.unwrap();
    let account = w.ids.encode(SUBJECT_PREFIX, subject).unwrap();
    let add = compile(
        Op::AddGroupMembers,
        Some("staff"),
        &json!({"account_ids": [account]}),
        &w.ids,
    )
    .unwrap();
    assert_eq!(
        refused(&w, at, d, add, 4).await,
        Invalid::UpstreamMembership
    );
    let crew = compile(
        Op::PutGroup,
        Some("crew"),
        &json!({"display_name": "Crew"}),
        &w.ids,
    )
    .unwrap();
    written(&run(&w, at, d, crew, 5).await.unwrap());
    let add = compile(
        Op::AddGroupMembers,
        Some("crew"),
        &json!({"account_ids": [account]}),
        &w.ids,
    )
    .unwrap();
    written(&run(&w, at, d, add, 6).await.unwrap());
    let groups = w
        .admin()
        .read(at.0, at.1, Kind::Groups, None, None, 10)
        .await
        .unwrap();
    assert_eq!(groups.items.len(), 2);
    assert_eq!(groups.items[0].0["membership_issuer"], "admin");
}

// §12.3.1, TN-49: a suspension ends the account's sessions and is reversed only by a
// reactivation; a second suspension finds nothing to leave
#[tokio::test]
async fn an_account_is_suspended_and_reactivated_through_commit() {
    let (w, at, d) = ready("suspend").await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let subject = t.insert_subject("active", "kek-1", &[1; 40]).await.unwrap();
    t.commit().await.unwrap();
    let account = w.ids.encode(SUBJECT_PREFIX, subject).unwrap();
    let suspend = compile(Op::SuspendAccount, Some(&account), &json!({}), &w.ids).unwrap();
    written(&run(&w, at, d, suspend.clone(), 1).await.unwrap());
    let view = w
        .admin()
        .read(at.0, at.1, Kind::Accounts, Some(&account), None, 1)
        .await
        .unwrap();
    assert_eq!(view.items[0].0["status"], "suspended");
    assert_eq!(refused(&w, at, d, suspend, 2).await, Invalid::AccountState);
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let epoch = t
        .subject(subject, false)
        .await
        .unwrap()
        .unwrap()
        .session_epoch;
    t.commit().await.unwrap();
    assert_eq!(epoch, 1, "the suspension raised the session epoch");
    let back = compile(Op::ReactivateAccount, Some(&account), &json!({}), &w.ids).unwrap();
    written(&run(&w, at, d, back, 3).await.unwrap());
}

// TN-129, TN-132, OP-151 m.3 (f): the policies are written by their own Exercises and read
// back in the settings view; an unbound console session is refused
#[tokio::test]
async fn the_realm_policies_change_through_commit() {
    let (w, at, d) = ready("policies").await;
    let fresh = w
        .admin()
        .read(at.0, at.1, Kind::Settings, None, None, 1)
        .await
        .unwrap();
    assert_eq!(fresh.items[0].0["session_policy"]["binding"], "asn");
    let signin = compile(
        Op::PutSigninPolicy,
        None,
        &json!({"methods": ["passkey"], "mfa_required": true}),
        &w.ids,
    )
    .unwrap();
    written(&run(&w, at, d, signin, 1).await.unwrap());
    let session = compile(
        Op::PutSessionPolicy,
        None,
        &json!({"absolute_ms": 3_600_000, "idle_ms": 300_000, "binding": "ip"}),
        &w.ids,
    )
    .unwrap();
    written(&run(&w, at, d, session, 2).await.unwrap());
    let view = w
        .admin()
        .read(at.0, at.1, Kind::Settings, None, None, 1)
        .await
        .unwrap();
    let (s, version) = &view.items[0];
    assert_eq!(s["signin_policy"]["methods"], json!(["passkey"]));
    assert_eq!(s["signin_policy"]["mfa_required"], true);
    assert_eq!(s["session_policy"]["binding"], "ip");
    assert!(*version > 0);
    let open = compile(
        Op::PutSessionPolicy,
        None,
        &json!({"absolute_ms": 3_600_000, "idle_ms": 300_000, "binding": "none"}),
        &w.ids,
    )
    .unwrap();
    assert_eq!(refused(&w, at, d, open, 3).await, Invalid::SessionPolicy);
}

// CR-38: a rotation issues a new secret shown once; a client without a secret has none to
// rotate
#[tokio::test]
async fn a_client_secret_rotates_with_a_new_one_shown_once() {
    let (w, at, d) = ready("rotate").await;
    let mut c = new_client(&w).await;
    c.auth = AuthMethod::ClientSecretBasic;
    let first = run(&w, at, d, Change::ClientRegister(c.clone()), 1)
        .await
        .unwrap();
    let Applied::Written {
        secret: Some(old), ..
    } = first
    else {
        panic!("a secret client gets a secret")
    };
    let rotated = run(&w, at, d, Change::ClientSecretRotate(c.id.clone()), 2)
        .await
        .unwrap();
    let Applied::Written {
        secret: Some(new), ..
    } = rotated
    else {
        panic!("a rotation shows the new secret")
    };
    assert_ne!(old.expose(), new.expose());
    let public = new_client(&w).await;
    written(
        &run(&w, at, d, Change::ClientRegister(public.clone()), 3)
            .await
            .unwrap(),
    );
    assert_eq!(
        refused(&w, at, d, Change::ClientSecretRotate(public.id), 4).await,
        Invalid::NoSecret
    );
    let view = w
        .admin()
        .read(at.0, at.1, Kind::Clients, Some(c.id.as_str()), None, 1)
        .await
        .unwrap();
    let text = view.items[0].0.to_string();
    assert!(
        !text.contains(new.expose()) && !text.contains("secret_hash"),
        "{text}"
    );
}
