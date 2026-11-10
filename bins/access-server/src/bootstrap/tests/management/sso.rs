//! Organization enterprise SSO on the real server path (OP-155 m.3 (i), OP-153 m.3 (gg), TN-94,
//! TN-95, TN-134, IDP-28): enforcement's preview, sweep and sign-in refusal through the admin
//! surface, the sequencer and the hosted login router; the one-use setup link through the
//! hosted portal; SCIM authority over invitations; the SSO catalog's authority-mapping templates.

#![allow(clippy::too_many_lines, reason = "test code; each test reads in order")]

use access_identity_account::domain::invitation::{code_hash, token_hash};
use access_kernel::json::b64url_encode;
use access_store::orgs::{NewInvitation, Source};

use super::super::recovery::{PW, Page, Recording, account, hosted, session, vault_of};
use super::scim::{scim_router, user};
use super::*;

const ORG: [u8; 16] = [0x5a; 16];

const OWNER: [u8; 16] = [0x77; 16];

/// Organization Contoso, founded by its own owner account: the realm administrator driving the
/// console is not a member, so enforcement does not end the console's own session.
async fn org(c: &Console) -> [u8; 16] {
    let owner = account(c, "owner@contoso.example", false).await;
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &owner, &OWNER)
            .await
            .unwrap()
    );
    let id = t.insert_org(ORG, "Contoso", &[7; 32]).await.unwrap();
    t.insert_membership(id, owner, Source::Founder, true, None)
        .await
        .unwrap();
    t.commit().await.unwrap();
    id
}

async fn invite(c: &Console, org: [u8; 16], email: &str, token: &str) -> [u8; 16] {
    let v = vault_of(c);
    let index = v
        .index_of(c.route.tenant.as_bytes(), c.route.realm.as_bytes(), email)
        .unwrap();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let id = t
        .insert_invitation(&NewInvitation {
            org,
            token_hash: &token_hash(token),
            code_hash: &code_hash("ABCDEFGH"),
            invitee_index: &index,
            invitee_domain: email.rsplit_once('@').unwrap().1,
            inviter: OWNER,
            role: ("member", 1),
            exercise: None,
            ttl_s: 86_400,
        })
        .await
        .unwrap();
    t.commit().await.unwrap();
    id
}

async fn invitation_open(c: &Console, org: [u8; 16], id: [u8; 16]) -> bool {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let open = t.open_invitations(org).await.unwrap().contains(&id);
    t.commit().await.unwrap();
    open
}

async fn sign_in(app: &axum::Router, identifier: &str) -> (StatusCode, serde_json::Value) {
    let mut p = Page::default();
    let flow = p.call(app, &Method::POST, "/v1/login/flows", None).await;
    assert_eq!(flow.status, StatusCode::CREATED, "{}", flow.json);
    let action = |g: &serde_json::Value| {
        let a = g["action"].as_str().unwrap();
        a.strip_prefix("/realms/acme").unwrap_or(a).to_owned()
    };
    let id = p
        .call(
            app,
            &Method::POST,
            &action(&flow.json),
            Some(serde_json::json!({"method": "identifier", "fields": {"identifier": identifier}})),
        )
        .await;
    let done = p
        .call(
            app,
            &Method::POST,
            &action(&id.json),
            Some(serde_json::json!({"method": "password", "fields": {"password": PW}})),
        )
        .await;
    (done.status, done.json)
}

// TN-94, C10, X20, SI-4, OP-155 m.3 (i), (gg), Ek B 4872
#[tokio::test]
async fn enforcing_sso_previews_sweeps_and_refuses_local_sign_in_until_lifted() {
    let c = console("sso-enforce", false).await;
    let app = hosted(&c, Recording::default());
    let org = org(&c).await;
    let party = b64url_encode(&ORG);
    let mia = account(&c, "mia@contoso.example", true).await;
    let bot = account(&c, "build-bot@contoso.example", true).await;
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    t.insert_membership(org, mia, Source::Invite, false, None)
        .await
        .unwrap();
    t.insert_membership(org, bot, Source::Invite, false, None)
        .await
        .unwrap();
    t.insert_ldap_credential([0x31; 16], bot, "ci", "$argon2id$placeholder")
        .await
        .unwrap();
    t.commit().await.unwrap();
    let cookie = session(&c, mia).await;
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let live = t
        .session_by_cookie(&access_identity_session::domain::session::cookie_digest(
            &<[u8; 32]>::try_from(b64url_decode(&cookie).unwrap()).unwrap(),
        ))
        .await
        .unwrap()
        .unwrap();
    let (clients, _) = access_store::idp::realm::clients(&mut t, "", 1)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let epoch = t.subject(mia, false).await.unwrap().unwrap().session_epoch;
    let grant = t
        .insert_grant(&access_store::oauth::NewGrant {
            sid: [0x41; 16],
            client: clients.client_uuid,
            subject: mia,
            session: live.id,
            session_epoch: epoch,
            dpop_jkt: None,
            details: b"{}",
            created_ms: i64::try_from(now()).unwrap(),
            expires_ms: i64::try_from(now() + 86_400_000).unwrap(),
        })
        .await
        .unwrap();
    t.commit().await.unwrap();
    let pending = invite(&c, org, "new@contoso.example", "pending-token").await;
    assert_eq!(sign_in(&app, "mia@contoso.example").await.0, StatusCode::OK);

    // X20, TN-94
    let preview = c
        .admin_get(&format!(
            "/admin/v1/realms/acme/organizations/{party}/sso-enforcement/preview"
        ))
        .await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.body);
    assert_eq!(preview.body["enforced"], false);
    assert_eq!(preview.body["members"].as_array().unwrap().len(), 3);
    assert_eq!(preview.body["pending_invitations"], 1);
    let services = preview.body["service_accounts"].as_array().unwrap();
    assert_eq!(services.len(), 1);
    let bot_row = preview.body["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["service_account"] == true)
        .unwrap();
    assert_eq!(bot_row["api_keys"], 1);
    assert_eq!(&bot_row["account_id"], &services[0]);
    assert!(preview.body["totals"]["refresh_families"].as_u64().unwrap() >= 1);

    // C10
    let target = format!("/admin/v1/realms/acme/organizations/{party}/sso-enforcement");
    let no_fate = c
        .rest_write(
            &Method::POST,
            &target,
            ("enforceOrganizationSso", Some(&party)),
            serde_json::json!({}),
            None,
        )
        .await;
    assert_eq!(no_fate.status, StatusCode::BAD_REQUEST, "{}", no_fate.body);
    let w = c
        .rest_write(
            &Method::POST,
            &target,
            ("enforceOrganizationSso", Some(&party)),
            serde_json::json!({ "invitations": "cancel" }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);

    // TN-94: the sweep
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    assert!(t.subject(mia, false).await.unwrap().unwrap().session_epoch > epoch);
    assert!(t.live_sessions(mia).await.unwrap().is_empty());
    assert!(t.grant(grant).await.unwrap().unwrap().revoked_ms.is_some());
    assert_eq!(t.ldap_credentials(bot).await.unwrap().len(), 0);
    t.commit().await.unwrap();
    assert!(!invitation_open(&c, org, pending).await);

    // TN-94: password sign-in is refused while SSO is enforced
    let (status, refused) = sign_in(&app, "mia@contoso.example").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(refused.to_string().contains("sso-required"), "{refused}");
    let again = c
        .rest_write(
            &Method::POST,
            &target,
            ("enforceOrganizationSso", Some(&party)),
            serde_json::json!({ "invitations": "redirect_to_sso" }),
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    let after = c
        .admin_get(&format!(
            "/admin/v1/realms/acme/organizations/{party}/sso-enforcement/preview"
        ))
        .await;
    assert_eq!(after.body["enforced"], true);
    assert_eq!(after.body["invitations"], "cancel");

    // SI-4: lifting widens again
    let lift = c
        .rest_write(
            &Method::POST,
            &format!("{target}/lift"),
            ("liftOrganizationSso", Some(&party)),
            serde_json::json!({}),
            None,
        )
        .await;
    assert_eq!(lift.status, StatusCode::OK, "{}", lift.body);
    assert_eq!(sign_in(&app, "mia@contoso.example").await.0, StatusCode::OK);
    c.w.domains.release().await;
}

// TN-134, OP-155 m.3 (i), (gg), Ek B 4874, 4914, 4933
#[tokio::test]
async fn a_setup_link_opens_once_for_one_browser_drafts_only_and_expires() {
    let c = console("sso-setup", false).await;
    let app = hosted(&c, Recording::default());
    let org = org(&c).await;
    let party = b64url_encode(&ORG);
    let bad = c
        .rest_write(
            &Method::POST,
            &format!("/admin/v1/realms/acme/organizations/{party}/setup-links"),
            ("createOrganizationSetupLink", Some(&party)),
            serde_json::json!({ "email": "not an address" }),
            None,
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.body);
    let w = c
        .rest_write(
            &Method::POST,
            &format!("/admin/v1/realms/acme/organizations/{party}/setup-links"),
            ("createOrganizationSetupLink", Some(&party)),
            serde_json::json!({ "email": "it@contoso.example" }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    let link = w.body["setup_link"].as_str().unwrap();
    let token = link.rsplit_once("/sso-setup/").unwrap().1.to_owned();
    assert_eq!(token.len(), 43);
    let path = format!("/v1/sso-setup/{token}");

    // TN-134: a read spends nothing
    let mut admin = Page::default();
    let read = admin.call(&app, &Method::GET, &path, None).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.json);
    assert_eq!(read.json["organization"]["display_name"], "Contoso");
    assert_eq!(read.json["opened"], false);
    let wizards = read.json["wizards"].as_array().unwrap();
    assert_eq!(wizards.len(), 9);
    assert!(wizards.iter().any(|w| w["provider"] == "entra"));
    assert!(
        read.json["values"]["acs_url"]
            .as_str()
            .unwrap()
            .contains("/v1/login/upstream/org-5a5a5a5a5a5a/saml/acs")
    );
    let mut scanner = Page::default();
    assert_eq!(
        scanner.call(&app, &Method::GET, &path, None).await.status,
        StatusCode::OK
    );

    // TN-134: the first step binds the link to this browser and only drafts
    let unknown = admin
        .call(
            &app,
            &Method::POST,
            &path,
            Some(
                serde_json::json!({"step": "connection", "provider": "nobody", "protocol": "saml",
                "entity_id": "x", "metadata_url": "https://idp.example/m"}),
            ),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    let drafted = admin
        .call(
            &app,
            &Method::POST,
            &path,
            Some(
                serde_json::json!({"step": "connection", "provider": "okta", "protocol": "saml",
                "entity_id": "http://www.okta.com/exk1",
                "metadata_url": "https://contoso.okta.com/app/exk1/sso/saml/metadata"}),
            ),
        )
        .await;
    assert_eq!(drafted.status, StatusCode::CREATED, "{}", drafted.json);
    assert!(admin.jar.contains_key("__Host-access-sso-setup"));
    let other = scanner.call(&app, &Method::GET, &path, None).await;
    assert_eq!(other.status, StatusCode::GONE, "{}", other.json);
    let stolen = scanner
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"step": "finish"})),
        )
        .await;
    assert_eq!(stolen.status, StatusCode::GONE);
    let test = admin
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"step": "test"})),
        )
        .await;
    assert_eq!(test.status, StatusCode::CONFLICT, "{}", test.json);
    let view = c
        .admin_get(&format!("/admin/v1/realms/acme/organizations/{party}"))
        .await;
    let drafts = view.body["connection_drafts"].as_array().unwrap();
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0]["protocol"], "saml");
    assert_eq!(drafts[0]["provider"], "okta");
    assert_eq!(drafts[0]["through_setup_link"], true);
    let finished = admin
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"step": "finish"})),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{}", finished.json);
    assert_eq!(
        admin.call(&app, &Method::GET, &path, None).await.status,
        StatusCode::GONE
    );

    // TN-134: 72 hours
    let old = "expired-setup-link-token-0000000000000000000";
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    t.insert_setup_link_ago(
        org,
        &suiss_crypto::digest::sha256(old.as_bytes()),
        &[9; 32],
        73 * 3_600,
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let mut late = Page::default();
    let gone = late
        .call(&app, &Method::GET, &format!("/v1/sso-setup/{old}"), None)
        .await;
    assert_eq!(gone.status, StatusCode::GONE, "{}", gone.json);
    assert_eq!(gone.json["text"], "sso_setup.link_expired");
    c.w.domains.release().await;
}

// TN-95, INV-16, OP-155 m.3 (i), (gg), Ek B 4873
#[tokio::test]
async fn while_a_scim_source_is_bound_invitations_close_and_deprovisioning_cancels_them() {
    let c = console("sso-scim", true).await;
    let app = hosted(&c, Recording::default());
    let org = org(&c).await;
    let party = b64url_encode(&ORG);
    let ada_invite = invite(&c, org, "ada@contoso.example", "ada-token").await;
    let bob = account(&c, "bob@contoso.example", false).await;
    invite(&c, org, "bob@contoso.example", "bob-token").await;

    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/scim-clients",
            ("registerScimClient", None),
            serde_json::json!({ "name": "hr", "organization": party }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    let secret = w.body["client_secret"].as_str().unwrap().to_owned();

    // TN-95: no new invitation
    let refused = c
        .rest_write(
            &Method::POST,
            &format!("/admin/v1/realms/acme/organizations/{party}/invitations"),
            ("createInvitation", Some(&party)),
            serde_json::json!({ "email": "eve@contoso.example", "inviter_name": "Root",
                                "role": "member", "role_version": 1 }),
            None,
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert!(
        refused
            .body
            .to_string()
            .contains("invitations-closed-by-scim"),
        "{}",
        refused.body
    );

    // TN-95: a pending invitation becomes an access request
    let mut me = Page::default();
    me.jar.insert(
        String::from("__Host-access-session"),
        session(&c, bob).await,
    );
    let accepted = me
        .call(
            &app,
            &Method::POST,
            "/v1/invitations/bob-token",
            Some(serde_json::json!({ "confirm": true })),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED, "{}", accepted.json);
    assert_eq!(accepted.json["status"], "requested");
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    assert!(t.access_requested(org, bob).await.unwrap());
    assert!(
        !t.memberships(org)
            .await
            .unwrap()
            .iter()
            .any(|m| m.subject == bob)
    );
    t.commit().await.unwrap();

    // TN-95: SCIM deprovisioning cancels the person's pending invitation
    let s = scim_router(&c);
    let (st, _, created) = s
        .call(
            Method::POST,
            "/Users",
            &secret,
            Some(user("ada@contoso.example", "e-ada")),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    assert!(invitation_open(&c, org, ada_invite).await);
    let id = created["id"].as_str().unwrap();
    let (st, _, _) = s
        .call(Method::DELETE, &format!("/Users/{id}"), &secret, None, &[])
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert!(!invitation_open(&c, org, ada_invite).await);

    // TN-95: retiring the client reopens invitations
    let retired = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/scim-clients/hr/retire",
            ("retireScimClient", Some("hr")),
            serde_json::json!({}),
            None,
        )
        .await;
    assert_eq!(retired.status, StatusCode::OK, "{}", retired.body);
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    assert_eq!(t.scim_sources(org).await.unwrap().len(), 0);
    t.commit().await.unwrap();
    c.w.domains.release().await;
}

async fn action_at(c: &Console, written: &serde_json::Value) -> String {
    let position: i64 = written["position"].as_str().unwrap().parse().unwrap();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let action = t.idp_decision_action(position).await.unwrap().unwrap();
    t.commit().await.unwrap();
    action
}

// IDP-28, L6, OP-155 m.3 (i), m.7 (a), Ek B 4913
#[tokio::test]
async fn a_catalog_template_that_maps_authority_is_the_reserved_sp_mapping() {
    let c = console("sso-catalog", false).await;
    let body = |name: &str, template: &str| {
        serde_json::json!({
            "name": name,
            "template": template,
            "entity_id": format!("https://{name}.sp.test/metadata"),
            "acs": [{ "url": format!("https://{name}.sp.test/acs"), "index": 0,
                      "binding": "post", "default": true }],
            "attributes": [{ "name": "email", "source": "email" }],
        })
    };
    let notion = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/saml-sps",
            ("registerSamlSp", None),
            body("notion", "notion"),
            None,
        )
        .await;
    assert_eq!(notion.status, StatusCode::CREATED, "{}", notion.body);
    assert_eq!(action_at(&c, &notion.body).await, "idp.saml.sp_register");
    let unknown = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/saml-sps",
            ("registerSamlSp", None),
            body("nobody", "not-in-the-catalog"),
            None,
        )
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST, "{}", unknown.body);
    let mut aws = body("aws", "aws");
    aws["attributes"] = serde_json::json!([
        { "name": "https://aws.amazon.com/SAML/Attributes/Role", "source": "email" },
        { "name": "https://aws.amazon.com/SAML/Attributes/RoleSessionName", "source": "email" },
    ]);
    let mapped = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/saml-sps",
            ("registerSamlSp", None),
            aws,
            None,
        )
        .await;
    assert_eq!(mapped.status, StatusCode::CREATED, "{}", mapped.body);
    assert_eq!(action_at(&c, &mapped.body).await, "idp.saml.sp_mapping");
    c.w.domains.release().await;
}
