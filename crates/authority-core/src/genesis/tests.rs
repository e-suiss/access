#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_internal_api::idp::{GenesisOrder, IdpAction, NAMESPACES};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{Root, kind, object_id};
use access_kernel::model::{Id, ResourceRef, Window};
use access_kernel::tier::{Tier, of};

use super::*;

struct Fixed;

impl Salts for Fixed {
    fn salt(&mut self) -> Result<[u8; 32], CoreError> {
        Ok([4; 32])
    }
}

fn values(order: &GenesisOrder) -> BTreeMap<String, Value> {
    realm(order, &mut Fixed)
        .unwrap()
        .into_iter()
        .map(|(k, o)| (k, o.value))
        .collect()
}

fn order(root: Root) -> GenesisOrder {
    GenesisOrder {
        tenant: [1; 16],
        slug: String::from("acme"),
        root,
        ct3_delay_s: None,
        causal_binding: false,
        schemas: Vec::new(),
        issuer: None,
        acceptances: Vec::new(),
        issuer_predicate_input: Vec::new(),
    }
}

// TN-111, L0-META-7, OP-141 m.35 (d)
#[test]
fn a_realm_genesis_roots_idp_and_accepts_its_catalogs() {
    // INV-2, INV-29, E34, MD-14
    let d = Digest([7; 32]);
    let founder = Id([2; 16]);
    let effects = meta::genesis_effects(&d, &values(&order(Root::Sole(founder)))).unwrap();
    let keys: BTreeSet<Vec<u8>> = effects.iter().map(|(k, _)| k.clone()).collect();
    assert!(keys.contains(&meta::key(kind::ANCHOR, &meta::meta_anchor(&d))));
    assert!(keys.contains(&meta::key(
        kind::ANCHOR,
        &object_id(&d, kind::ANCHOR, IDP_ANCHOR)
    )));
    for ns in NAMESPACES {
        assert!(
            keys.contains(&access_kernel::schema::schemas_key(ns)),
            "{ns}"
        );
    }
    assert!(!values(&order(Root::Sole(founder))).contains_key("policy"));
}

// §12.5.1
#[test]
fn a_joint_root_and_a_time_lock_are_carried() {
    // TN-111, OP-141 m.34 (d)
    let root = Root::Joint {
        parties: BTreeSet::from([Id([3; 16]), Id([2; 16])]),
        k: 2,
    };
    let mut o = order(root);
    o.ct3_delay_s = Some(0);
    let v = values(&o);
    assert!(meta::genesis_effects(&Digest([7; 32]), &v).is_ok());
    assert!(v.contains_key("policy"));
}

fn intent(action: IdpAction) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: action.action_ref(),
        resources: vec![ResourceRef {
            namespace: String::from("idp"),
            path: vec![String::from("acme"), String::from("realm")],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window { from: 0, until: 1 },
    }
}

// OP-141 m.34 (a), m.35 (g)
// IDP-5, IDI-4
#[test]
#[expect(clippy::too_many_lines, reason = "one row per idp action and its tier")]
fn idp_actions_carry_their_consequence_tiers() {
    // IDP-5, IDI-4, TN-95, TN-117, §13.7.1
    let tier = |a: IdpAction| of(&intent(a), None, false, Some(&a.schema()));
    assert_eq!(tier(IdpAction::RealmRpId), Tier::Ct3);
    assert_eq!(tier(IdpAction::RealmRehome), Tier::Ct3);
    assert_eq!(tier(IdpAction::UpstreamRegister), Tier::Ct3);
    assert_eq!(tier(IdpAction::UpstreamMapping), Tier::Ct3);
    // OP-157 m.3 (t), m.19 (d)
    assert_eq!(tier(IdpAction::MapperSet), Tier::Ct3);
    assert_eq!(tier(IdpAction::ClientRegister), Tier::Ct2);
    assert_eq!(tier(IdpAction::ClientUpdate), Tier::Ct2);
    assert_eq!(tier(IdpAction::CimdPolicy), Tier::Ct2);
    assert_eq!(tier(IdpAction::RealmJoseAlg), Tier::Ct2);
    assert_eq!(tier(IdpAction::ClientRetire), Tier::Ct1);
    assert_eq!(tier(IdpAction::RealmArgon2), Tier::Ct1);
    // TN-118, TN-106, §13.2, §13.7.1, OP-73
    assert_eq!(tier(IdpAction::RealmKeyPolicy), Tier::Ct3);
    assert_eq!(tier(IdpAction::RealmKeyRotate), Tier::Ct3);
    assert_eq!(tier(IdpAction::AccountDelete), Tier::Ct3);
    assert_eq!(tier(IdpAction::RealmBranding), Tier::Ct2);
    assert_eq!(tier(IdpAction::RealmKeyDrop), Tier::Ct1);
    // TN-117, TN-129, TN-132, CR-38, §12.3.1, OP-151 m.2 M1
    for (a, t) in [
        (IdpAction::GroupCreate, Tier::Ct2),
        (IdpAction::GroupUpdate, Tier::Ct2),
        (IdpAction::GroupMembersAdd, Tier::Ct2),
        (IdpAction::GroupMembersRemove, Tier::Ct1),
        (IdpAction::GroupRetire, Tier::Ct1),
        (IdpAction::AccountSuspend, Tier::Ct1),
        (IdpAction::AccountReactivate, Tier::Ct2),
        (IdpAction::ClientSecretRotate, Tier::Ct2),
        (IdpAction::UpstreamUpdate, Tier::Ct3),
        (IdpAction::UpstreamRetire, Tier::Ct1),
        (IdpAction::RealmSigninPolicy, Tier::Ct2),
        (IdpAction::RealmSessionPolicy, Tier::Ct2),
        // OP-151 m.14 (f)
        (IdpAction::RealmProtectionMode, Tier::Ct1),
        (IdpAction::RealmProtectionModeLoosen, Tier::Ct2),
        (IdpAction::AccountCanary, Tier::Ct2),
        // OP-153 m.18 (e), m.19 (d), m.20 (g), m.22 (g), m.25 (b)
        (IdpAction::AccountBind, Tier::Ct2),
        (IdpAction::AccountImport, Tier::Ct2),
        (IdpAction::AccountMigrationExport, Tier::Ct3),
        (IdpAction::AccountGuardianshipRecord, Tier::Ct2),
        (IdpAction::RealmCspMode, Tier::Ct1),
        (IdpAction::RealmCspModeLoosen, Tier::Ct2),
        // OP-154 m.3 (a)
        (IdpAction::AgentRegister, Tier::Ct2),
        (IdpAction::AgentUpdate, Tier::Ct1),
        (IdpAction::AgentSponsorAssign, Tier::Ct2),
        (IdpAction::AgentSponsorRemove, Tier::Ct1),
        (IdpAction::AgentRetire, Tier::Ct1),
        (IdpAction::AgentTemplateDefine, Tier::Ct2),
        (IdpAction::VaultResourceEnable, Tier::Ct2),
        (IdpAction::VaultResourceDisable, Tier::Ct1),
        (IdpAction::VaultResourceRegister, Tier::Ct3),
        (IdpAction::VaultReleaseModeOpen, Tier::Ct2),
        (IdpAction::VaultReleaseModeClose, Tier::Ct1),
        (IdpAction::ClientResourceRegister, Tier::Ct2),
        (IdpAction::ClientDcrPolicy, Tier::Ct2),
        (IdpAction::ClientDcrPolicyTighten, Tier::Ct1),
        (IdpAction::ClientCrossAppConnection, Tier::Ct2),
        (IdpAction::ClientCrossAppConnectionRetire, Tier::Ct1),
        (IdpAction::RealmDeviceCode, Tier::Ct2),
        (IdpAction::RealmDeviceCodeClose, Tier::Ct1),
        // OP-155 m.3 (a)
        (IdpAction::SamlSpRegister, Tier::Ct2),
        (IdpAction::SamlSpMapping, Tier::Ct3),
        (IdpAction::SamlSpUpdate, Tier::Ct2),
        (IdpAction::SamlSpRetire, Tier::Ct1),
        (IdpAction::SamlCertPolicy, Tier::Ct2),
        (IdpAction::SamlCertEmergency, Tier::Ct3),
        (IdpAction::ScimClientRegister, Tier::Ct2),
        (IdpAction::ScimTokenRotate, Tier::Ct2),
        (IdpAction::ScimClientRetire, Tier::Ct1),
        (IdpAction::ScimOutboundRegister, Tier::Ct2),
        (IdpAction::ScimOutboundRetire, Tier::Ct1),
        (IdpAction::GatewayRegister, Tier::Ct2),
        (IdpAction::GatewayRetire, Tier::Ct1),
        (IdpAction::GatewayKeytabPolicy, Tier::Ct2),
        (IdpAction::GatewayKeytabEmergency, Tier::Ct3),
        (IdpAction::GatewayRadiusClientRegister, Tier::Ct2),
        (IdpAction::FederationEnable, Tier::Ct2),
        (IdpAction::FederationDisable, Tier::Ct1),
        (IdpAction::FederationTrustAnchorAdd, Tier::Ct3),
        (IdpAction::FederationTrustAnchorRemove, Tier::Ct1),
        (IdpAction::FederationTaEnable, Tier::Ct2),
        (IdpAction::FederationRegistrationOpen, Tier::Ct2),
        (IdpAction::FederationRegistrationClose, Tier::Ct1),
        (IdpAction::VcVerifierEnable, Tier::Ct2),
        (IdpAction::VcVerifierDisable, Tier::Ct1),
        (IdpAction::VcTrustedList, Tier::Ct3),
        (IdpAction::VcIssuerEnable, Tier::Ct2),
        (IdpAction::VcIssuerDisable, Tier::Ct1),
        (IdpAction::ClientProfile, Tier::Ct1),
        (IdpAction::ClientProfileLoosen, Tier::Ct2),
        (IdpAction::ClientAuthMethodLegacy, Tier::Ct2),
        (IdpAction::ClientAlgRs256, Tier::Ct2),
        (IdpAction::ClientEncryption, Tier::Ct1),
        (IdpAction::ClientSamlBearer, Tier::Ct2),
        (IdpAction::ClientLegacyBearer, Tier::Ct2),
        (IdpAction::RealmCiba, Tier::Ct2),
        (IdpAction::RealmCibaClose, Tier::Ct1),
        (IdpAction::RealmCertificateLogin, Tier::Ct2),
        (IdpAction::RealmMtlsAliases, Tier::Ct2),
        (IdpAction::RealmHrd, Tier::Ct2),
        (IdpAction::RealmHrdClose, Tier::Ct1),
        (IdpAction::RealmFrontchannelLogout, Tier::Ct2),
        (IdpAction::OrgSsoEnforce, Tier::Ct1),
        (IdpAction::OrgSsoEnforceLift, Tier::Ct2),
        (IdpAction::UpstreamAssuranceMap, Tier::Ct3),
        // OP-156 m.3 (a)
        (IdpAction::DomainRegister, Tier::Ct2),
        (IdpAction::DomainRetire, Tier::Ct1),
        (IdpAction::DomainIssuerBind, Tier::Ct3),
        (IdpAction::ProxyRegister, Tier::Ct2),
        (IdpAction::ProxyUpdate, Tier::Ct2),
        (IdpAction::ProxyRetire, Tier::Ct1),
        (IdpAction::ProxyPlainHeaders, Tier::Ct2),
        (IdpAction::ProxyPlainHeadersClose, Tier::Ct1),
        (IdpAction::ProxyMcpPin, Tier::Ct2),
        (IdpAction::SshCaEnable, Tier::Ct2),
        (IdpAction::SshCaDisable, Tier::Ct1),
        (IdpAction::SshCaRotate, Tier::Ct2),
        (IdpAction::SshCaEmergency, Tier::Ct3),
        (IdpAction::SshHostGroupRegister, Tier::Ct2),
        (IdpAction::SshHostGroupRetire, Tier::Ct1),
        (IdpAction::LinuxHostRegister, Tier::Ct2),
        (IdpAction::LinuxHostRetire, Tier::Ct1),
        (IdpAction::LinuxOfflinePolicy, Tier::Ct2),
        (IdpAction::LinuxBreakGlassPolicy, Tier::Ct3),
        (IdpAction::HrSourceRegister, Tier::Ct2),
        (IdpAction::HrSourceRetire, Tier::Ct1),
        (IdpAction::HrImport, Tier::Ct2),
        (IdpAction::HrConnectorRegister, Tier::Ct2),
        (IdpAction::HrConnectorRetire, Tier::Ct1),
        (IdpAction::ExportSinkRegister, Tier::Ct2),
        (IdpAction::ExportSinkUpdate, Tier::Ct2),
        (IdpAction::ExportSinkRetire, Tier::Ct1),
        (IdpAction::SignalSourceRegister, Tier::Ct2),
        (IdpAction::SignalSourceRetire, Tier::Ct1),
        (IdpAction::RealmPush, Tier::Ct2),
        (IdpAction::RealmPushClose, Tier::Ct1),
        (IdpAction::RealmSmsOtp, Tier::Ct2),
        (IdpAction::RealmSmsOtpClose, Tier::Ct1),
        (IdpAction::RealmSpc, Tier::Ct2),
        (IdpAction::RealmCoordinator, Tier::Ct2),
        (IdpAction::RealmIys, Tier::Ct2),
        (IdpAction::RealmIysClose, Tier::Ct1),
        (IdpAction::RealmSecurityNotices, Tier::Ct2),
        (IdpAction::RealmSecurityNoticesClose, Tier::Ct1),
        (IdpAction::RelayResend, Tier::Ct1),
        // OP-157 m.3 (a)
        (IdpAction::AccountSigninMethodChange, Tier::Ct3),
        (IdpAction::AccountMfaChange, Tier::Ct3),
        (IdpAction::AccountPhoneChange, Tier::Ct3),
        (IdpAction::AccountPayment, Tier::Ct3),
        (IdpAction::AccountRoleElevate, Tier::Ct3),
        (IdpAction::AccountInvite, Tier::Ct3),
        (IdpAction::AccountApiKeyCreate, Tier::Ct3),
        (IdpAction::AccountTokenLongLived, Tier::Ct3),
        (IdpAction::AccountArtifactUpload, Tier::Ct1),
        (IdpAction::AccountArtifactRead, Tier::Ct2),
        (IdpAction::SupportCaseSystemRegister, Tier::Ct2),
        (IdpAction::SupportCaseSystemRetire, Tier::Ct1),
        (IdpAction::SupportArtifactPolicy, Tier::Ct2),
        (IdpAction::SupportArtifactPolicyClose, Tier::Ct1),
        (IdpAction::ReviewSchedule, Tier::Ct2),
        (IdpAction::ReviewScheduleClose, Tier::Ct1),
        (IdpAction::OrgMemberBreakglass, Tier::Ct2),
        (IdpAction::OrgMemberBreakglassClear, Tier::Ct1),
        (IdpAction::RealmDelegatedAdmin, Tier::Ct2),
        (IdpAction::RealmDelegatedAdminClose, Tier::Ct1),
        (IdpAction::RealmApprovalInline, Tier::Ct2),
        (IdpAction::RealmApprovalInlineClose, Tier::Ct1),
        (IdpAction::RealmApprovalBatch, Tier::Ct2),
        (IdpAction::RealmApprovalBatchClose, Tier::Ct1),
    ] {
        assert_eq!(tier(a), t, "{}", a.label());
    }
    for a in IdpAction::ALL {
        assert_eq!(IdpAction::from_label(&a.label()), Some(a));
    }
}

fn catalog(publisher: Id, namespace: &str) -> access_kernel::schema::Spp {
    access_kernel::schema::Spp {
        publisher,
        namespace: String::from(namespace),
        catalog_version: 1,
        actions: vec![access_kernel::schema::ActionSchema {
            reversibility: None,
            name: String::from("approve"),
            major: 1,
            effect: access_kernel::schema::EffectClass::Reversible,
            reserved: false,
            consumption_bearing: false,
            params: BTreeMap::new(),
            resource_types: BTreeSet::new(),
            render: None,
        }],
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

// OP-141 m.35 (c), OP-149 m.10, SEC8
#[test]
fn a_genesis_publishes_the_founders_further_catalogs() {
    let d = Digest([7; 32]);
    let founder = Id([2; 16]);
    let mut o = order(Root::Sole(founder));
    o.schemas = vec![catalog(founder, "work")];
    let effects = meta::genesis_effects(&d, &values(&o)).unwrap();
    let keys: BTreeSet<Vec<u8>> = effects.iter().map(|(k, _)| k.clone()).collect();
    assert!(keys.contains(&access_kernel::schema::schemas_key("work")));
    assert!(keys.contains(&access_kernel::schema::schemas_key("idp.client")));
    for bad in [
        catalog(Id([3; 16]), "work"),
        catalog(founder, "idp.client"),
        catalog(founder, "access"),
    ] {
        o.schemas = vec![bad];
        assert!(matches!(
            realm(&o, &mut Fixed),
            Err(CoreError::Protocol("genesis-schema"))
        ));
    }
    o.schemas = vec![catalog(founder, "work"), catalog(founder, "work")];
    assert!(realm(&o, &mut Fixed).is_err());
}

// §10.1.4 rule 3, E18, OP-142, INV-12, G45, PI-13 (§9.13.2)
#[test]
fn the_realm_issuer_is_accepted_for_actor_binding_only() {
    let d = Digest([7; 32]);
    let issuer = Id([9; 16]);
    let mut o = order(Root::Sole(Id([2; 16])));
    let without = meta::genesis_effects(&d, &values(&o)).unwrap();
    assert!(
        !without
            .iter()
            .any(|(k, _)| *k == meta::key(kind::ACCEPTANCES, &issuer))
    );
    o.issuer = Some(issuer);
    let effects = meta::genesis_effects(&d, &values(&o)).unwrap();
    let gates: Vec<access_kernel::claim::Gate> = effects
        .iter()
        .filter_map(|(_, v)| v.as_ref())
        .filter_map(|v| access_kernel::meta::ContentState::from_value(v).ok())
        .filter_map(|c| access_kernel::claim::Gate::of(&c.content).ok())
        .filter(|g| g.issuer == Some(issuer))
        .collect();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].use_, access_kernel::claim::ACTOR_BINDING);
    assert_eq!(
        gates[0].classes,
        REALM_ISSUER_CLASSES.map(String::from).to_vec()
    );
}

// MD-5a, TN-1, INV-37
#[test]
fn the_idp_anchor_covers_its_realm_only() {
    let o = order(Root::Sole(Id([2; 16])));
    let Value::Array(anchors) = values(&o).remove("anchors").unwrap() else {
        panic!("anchors");
    };
    let scope = anchors
        .iter()
        .find_map(|a| match a {
            Value::Map(m) => m
                .iter()
                .find(|(k, _)| *k == Value::text("scope"))
                .map(|(_, v)| v.clone()),
            _ => None,
        })
        .unwrap();
    let Value::Map(scope) = scope else {
        panic!("scope");
    };
    let resource = ResourceSelector::from_value(&scope[0].1).unwrap();
    let ResourceSelector::Structural(s) = resource else {
        panic!("{resource:?}");
    };
    assert_eq!(
        (s.namespace.as_str(), s.prefix),
        ("idp", vec![String::from("acme")])
    );
    let mut bad = order(Root::Sole(Id([2; 16])));
    bad.slug = String::new();
    assert!(matches!(
        realm(&bad, &mut Fixed),
        Err(CoreError::Protocol("genesis-slug"))
    ));
}
