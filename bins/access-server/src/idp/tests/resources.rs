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
    let session = t
        .insert_session(&access_store::sessions::NewSession {
            cookie_hash: &[3; 32],
            subject,
            session_epoch: 0,
            keep_signed_in: false,
            created_ms: 1,
            auth_time_ms: 1,
            idle_ms: i64::MAX / 4,
            expires_ms: i64::MAX / 2,
            assurance: b"[]",
        })
        .await
        .unwrap();
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
    // TN-49, TN-41, OP-150 L2, OP-151 m.3 (i): a decided suspension does what any status move
    // does in its transaction: the session ends, the session-revoked and account-disabled
    // signals, the realm issuer's account_status Claim and the webhook events are queued
    let ended = t.session_by_id(session).await.unwrap().unwrap();
    let kinds = t.outbox_kinds().await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(epoch, 1, "the suspension raised the session epoch");
    assert!(ended.ended_ms.is_some());
    for kind in [
        "signal.session_revoked",
        "signal.account_disabled",
        "claim.account_status",
        "event.session.revoked",
        "event.account.suspended",
    ] {
        assert_eq!(
            kinds.iter().filter(|k| *k == kind).count(),
            1,
            "{kind} in {kinds:?}"
        );
    }
    let back = compile(Op::ReactivateAccount, Some(&account), &json!({}), &w.ids).unwrap();
    written(&run(&w, at, d, back, 3).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let kinds = t.outbox_kinds().await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| *k == "claim.account_status")
            .count(),
        2
    );
    assert!(kinds.iter().any(|k| k == "event.account.reactivated"));
}

// TN-129, TN-132, OP-151 m.3 (f): the policies are written by their own Exercises and read
// back in the settings view; an unbound console session is refused
#[tokio::test]
async fn the_realm_policies_change_through_commit() {
    let (w, at, d) = ready("policies").await;
    // TN-129, OP-151 m.3 (f), m.11 (d): the console binds to the prefix by default and to the
    // full address once the realm's session policy says `ip`
    let network = crate::console::sessions::RealmBinding {
        app: w.db.app.clone(),
        directory: access_identity_oauth::adapters::PgDirectory::new(w.db.router.clone()),
    };
    let binding = || async {
        access_http::console::ports::Network::policy(&network, "policies")
            .await
            .unwrap()
            .full_ip
    };
    assert!(!binding().await);
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
    assert!(
        binding().await,
        "the console reads the realm's full-address binding"
    );
    assert!(
        access_http::console::ports::Network::policy(&network, "nowhere")
            .await
            .is_err()
    );
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
    // CR-38, OP-151 m.11 (g): the old secret stays acceptable, as a digest, for the overlap
    let mut t = access_store::identity::TenantTx::begin(&w.db.app, at.0, at.1)
        .await
        .unwrap();
    let previous = access_store::idp::realm::previous_secret(&mut t, c.id.as_str())
        .await
        .unwrap();
    t.commit().await.unwrap();
    assert_eq!(
        previous,
        Some(access_crypto::oauth::secret_digest(old.expose().as_bytes()))
    );
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

// OP-151 m.3 (o), m.14 (f): tightening the protection mode is idp.realm.protection_mode (CT1),
// loosening it idp.realm.protection_mode_loosen (CT2); an intent drawn for the wrong one is
// refused; the settings view reads the mode back
#[tokio::test]
async fn the_protection_mode_action_follows_its_tier() {
    use access_internal_api::idp::IdpAction;
    let (w, at, d) = ready("protection").await;
    let tighten = compile(
        Op::PutProtectionMode,
        None,
        &json!({"suspicious_ip": "enforce", "sl2": "stepup", "denied_asns": [64500]}),
        &w.ids,
    )
    .unwrap();
    let tighten = w.admin().resolve(at.0, at.1, tighten).await.unwrap();
    assert_eq!(tighten.action(), IdpAction::RealmProtectionMode);
    written(&run(&w, at, d, tighten, 1).await.unwrap());
    let view = w
        .admin()
        .read(at.0, at.1, Kind::Settings, None, None, 1)
        .await
        .unwrap();
    assert_eq!(
        view.items[0].0["protection_mode"]["suspicious_ip"],
        "enforce"
    );
    assert_eq!(view.items[0].0["protection_mode"]["brute_force"], "enforce");
    let loosen = compile(
        Op::PutProtectionMode,
        None,
        &json!({"sl2": "shadow"}),
        &w.ids,
    )
    .unwrap();
    let mislabelled = loosen.clone();
    let loosen = w.admin().resolve(at.0, at.1, loosen).await.unwrap();
    assert_eq!(loosen.action(), IdpAction::RealmProtectionModeLoosen);
    assert!(matches!(
        w.admin()
            .prepare(&proposal(at, mislabelled, 2, idp_anchor(d), 1))
            .await,
        Err(AdminError::Conflict)
    ));
    written(&run(&w, at, d, loosen, 3).await.unwrap());
    // TI-9: brute-force protection has no monitor mode
    assert_eq!(
        compile(
            Op::PutProtectionMode,
            None,
            &json!({"brute_force": "monitor", "sl2": "shadow"}),
            &w.ids,
        ),
        Err(Invalid::ProtectionMode)
    );
}

// TN-110, EI-25, MD-8: a commit that was never drafted is checked against the realm's state on
// the first application of its decision: a client id already registered is the write's problem
// (400), not a storage failure (503), and nothing is bound; a retry of a written decision is
// still answered without a check. A write the database refuses for the state it found is a
// conflict (409)
#[tokio::test]
async fn a_commit_is_checked_against_the_state_on_first_application() {
    let (w, at, d) = ready("first-application").await;
    let c = new_client(&w).await;
    let register = proposal(at, Change::ClientRegister(c.clone()), 1, idp_anchor(d), 1);
    let ais = {
        let prepared = w.admin().prepare(&register).await.unwrap();
        sign(
            &statement(
                prepared.domain,
                &register.nonce,
                prepared.digest,
                register.basis,
            ),
            ROOT_KEY,
        )
    };
    written(&w.admin().apply(&register, ais.clone()).await.unwrap());

    let again = proposal(at, Change::ClientRegister(c), 2, idp_anchor(d), 1);
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let g = access_store::idp::governance(&mut t)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    let intent = again.change.intent(&g.slug, again.validity).unwrap();
    let digest = access_kernel::intent::intent_digest(&intent).unwrap();
    let undrafted = sign(&statement(d, &again.nonce, digest, again.basis), ROOT_KEY);
    let refused = w.admin().apply(&again, undrafted).await.unwrap_err();
    assert!(
        matches!(refused, AdminError::Invalid(Invalid::ClientExists)),
        "{refused:?}"
    );
    assert_eq!(refused.problem().0, 400);
    assert!(matches!(
        w.admin().apply(&register, ais).await.unwrap(),
        Applied::AlreadyWritten { .. }
    ));

    // TN-16, INV-32: a second realm on a taken slug is refused by the database's unique index
    let tenant = access_store::tenancy::create_tenant(&w.db.app, "pool-default")
        .await
        .unwrap();
    let taken = w
        .admin()
        .create_realm(&NewRealm {
            tenant,
            slug: "first-application",
            style: IssuerStyle::Subdomain,
            placement: "pool-default",
            root: Root::Sole(ROOT),
            ct3_delay_s: None,
            schemas: Vec::new(),
            acceptances: Vec::new(),
            issuer_predicate_input: Vec::new(),
            provisioned_by: None,
        })
        .await;
    let Err(conflict) = taken else {
        panic!("a taken slug opened a second realm");
    };
    assert!(matches!(conflict, AdminError::Conflict), "{conflict:?}");
    assert_eq!(conflict.problem().0, 409);
}

// §4.4, OP-151 m.14 (f): an account becomes a canary through idp.account.canary (CT2), once
#[tokio::test]
async fn an_account_becomes_a_canary_through_commit() {
    let (w, at, d) = ready("canary").await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let subject = t.insert_subject("active", "kek-1", &[1; 40]).await.unwrap();
    t.commit().await.unwrap();
    let account = w.ids.encode(SUBJECT_PREFIX, subject).unwrap();
    let canary = compile(Op::MarkCanary, Some(&account), &json!({}), &w.ids).unwrap();
    assert_eq!(canary, Change::AccountCanary(subject));
    written(&run(&w, at, d, canary.clone(), 1).await.unwrap());
    assert!(matches!(
        run(&w, at, d, canary, 2).await,
        Err(AdminError::Conflict)
    ));
}

// §13.4 G54, §12.3.1, TN-49, OP-150 m.11 (f): a write signed by an Instance of a Party whose
// account in the realm is suspended, locked or deactivated is refused before a decision, with
// or without a session naming that account; while the account is active, and for a Party bound
// to no account of the realm (the operator's root), the write goes on
#[tokio::test]
async fn a_party_whose_account_cannot_act_changes_nothing() {
    let (w, at, d) = ready("standing").await;
    let client = Change::ClientRegister(new_client(&w).await);
    written(&run(&w, at, d, client, 1).await.unwrap());

    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let subject = t.insert_subject("active", "kek-1", &[1; 40]).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &subject, &ROOT.0)
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    let client = Change::ClientRegister(new_client(&w).await);
    written(&run(&w, at, d, client, 2).await.unwrap());

    let mut nonce = 3;
    for (from, to) in [
        ("active", "suspended"),
        ("suspended", "active"),
        ("active", "locked"),
        ("locked", "deactivated"),
    ] {
        let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
        assert!(t.set_subject_status(subject, from, to).await.unwrap());
        t.commit().await.unwrap();
        for session in [None, Some(subject)] {
            let client = Change::ClientRegister(new_client(&w).await);
            let mut p = proposal(at, client, nonce, idp_anchor(d), 1);
            p.subject = session;
            nonce += 1;
            let answer = exercise(&w, &p, ROOT_KEY).await;
            if to == "active" {
                written(&answer.unwrap());
            } else {
                assert!(
                    matches!(&answer, Err(AdminError::Refused(code)) if code == "actor-binding"),
                    "{to}: {answer:?}"
                );
            }
        }
    }
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(
        t.set_subject_status(subject, "deactivated", "active")
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    let client = Change::ClientRegister(new_client(&w).await);
    written(&run(&w, at, d, client, nonce).await.unwrap());
}

// OP-150 m.11 (b), TN-61: account deletion, realm rehoming and reset intents are declared and
// never compiled into a change here
#[test]
fn reserved_operations_compile_to_nothing() {
    let ids = access_crypto::opaque_id::IdKey::new(access_crypto::Secret::new([7; 32]));
    let account = ids.encode(SUBJECT_PREFIX, [1; 16]).unwrap();
    for op in [Op::DeleteAccount, Op::ResetIntent] {
        assert_eq!(
            compile(op, Some(&account), &json!({}), &ids),
            Err(Invalid::Reserved)
        );
    }
    assert_eq!(
        compile(Op::RehomeRealm, None, &json!({}), &ids),
        Err(Invalid::Reserved)
    );
}
