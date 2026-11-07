//! OP-149 m.1, m.4, m.7: the event contracts under `sdks/openapi/events` are complete, every
//! committed example meets them, and what the code builds meets them too.

#![allow(
    unreachable_pub,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use access_identity_account::domain::signal::{
    ChangeType, CredentialType, Initiator, RiskLevel, Signal, SignalKind,
};
use access_identity_events::domain::catalog::{
    ClientChange, IdentityEvent, IdentityKind, NAMES, PlatformProduct, authority_ready, urn,
};
use access_identity_events::domain::mapping::{
    Profile, counterpart, counterpart_body, forms, signal_uri,
};
use access_identity_events::domain::set::{
    Envelope, cloud_event, derived_id, set_claims, set_tenant, standard_claims,
};
use access_identity_events::domain::stream::{
    Channel, parse_poll, parse_stream, poll_response, ssf_configuration, stream_json,
};
use access_internal_api::events::{Detail, Event, Kind, ReasonClass, Source, Subject};
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use serde_json::Value as Json;
use support::{assert_cloud_event, assert_set, assert_valid, contracts, load};

// OP-149 m.1, m.7: one schema and one example per catalog event, and the URN prefix
#[test]
fn every_event_has_a_schema_and_an_example() {
    for name in NAMES {
        let schema = load(&format!("{name}.schema.json"));
        assert_eq!(
            schema["$id"],
            format!("urn:suiss:access:schema:event:{name}:1")
        );
        let example = load(&format!("examples/{name}.json"));
        assert_eq!(example["type"], urn(name));
        assert!(urn(name).starts_with("urn:suiss:access:event:"));
    }
    let listed = std::fs::read_dir(contracts())
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|f| f.ends_with(".schema.json"))
        .count();
    assert_eq!(listed, NAMES.len() + 7 + SignalKind::ALL.len());
}

// OP-149 m.4, m.7: every committed example meets its schema
#[test]
fn every_example_is_valid() {
    for name in NAMES {
        assert_cloud_event(&load(&format!("examples/{name}.json")));
    }
    for (example, schema) in [
        ("ssf-configuration", "ssf-configuration"),
        ("stream-request", "stream-request"),
        ("stream", "stream"),
        ("poll-request", "poll-request"),
        ("poll-response", "poll-response"),
    ] {
        assert_valid(
            &format!("{schema}.schema.json"),
            &load(&format!("examples/{example}.json")),
        );
    }
    assert!(
        parse_stream(&std::fs::read(contracts().join("examples/stream-request.json")).unwrap())
            .is_ok()
    );
    assert!(
        parse_poll(&std::fs::read(contracts().join("examples/poll-request.json")).unwrap()).is_ok()
    );
}

// OP-149 m.7, m.17 (d): the schemas refuse what the contract forbids; a compromise without
// its window start is malformed
#[test]
fn schemas_refuse_malformed_events() {
    let mut e = load("examples/party.compromised.json");
    e["data"]["events"]["urn:suiss:access:event:party.compromised"]
        .as_object_mut()
        .unwrap()
        .remove("window_from");
    let s = load("party.compromised.schema.json");
    let errors = support::schema::Schema::new(&s)
        .errors(&e["data"]["events"]["urn:suiss:access:event:party.compromised"]);
    assert_ne!(errors.len(), 0);
    let mut two = load("examples/party.disabled.json");
    two["data"]["events"]["urn:suiss:access:event:mandate-ended"] =
        Json::Object(serde_json::Map::default());
    let set = load("set.schema.json");
    assert_ne!(
        support::schema::Schema::new(&set)
            .errors(&two["data"])
            .len(),
        0
    );
}

/// Tenants by their `tnt_` ids (OP-149 m.15 (i)).
const TENANT: &str = "tnt_0123456789abcdefghjkmnpqrs";
const OTHER: &str = "tnt_zyxwvtsrqpnmkjhgfedcba9876";

// OP-149 m.15 (i): every surface names a tenant by its opaque tnt_ id, never its UUID
#[test]
fn tenants_are_named_by_their_opaque_id() {
    use access_crypto::opaque_id::IdKey;
    use access_crypto::secret::Secret;
    use access_identity_events::ports::TenantIds;
    let ids = IdKey::new(Secret::new([3; 32]));
    let t = ids.external(&[1; 16]).unwrap();
    assert!(t.starts_with("tnt_") && t.len() == 30);
    let e = IdentityEvent::tenant_created([2; 32], &t, "pool-default", 5);
    let mut claims = set_claims(&e.ready(), "https://id.example", "work", 1);
    set_tenant(&mut claims, &t);
    assert_set(&claims);
    let ce: Json = serde_json::from_slice(&cloud_event(&claims, &t, &[2; 16], 5).unwrap()).unwrap();
    assert_cloud_event(&ce);
    for v in [
        &ce["accesstenant"],
        &ce["subject"],
        &claims["access_tenant"],
    ] {
        assert_eq!(v, &Json::from(t.clone()));
    }
    let mut uuid = ce;
    uuid["accesstenant"] = Json::from("01010101-0101-0101-0101-010101010101");
    assert_ne!(
        support::schema::Schema::new(&load("cloudevent.schema.json"))
            .errors(&uuid)
            .len(),
        0
    );
}

fn sample(kind: Kind) -> Event {
    let d = Digest([7; 32]);
    let (subject, detail) = match kind {
        Kind::InstanceTerminated => (
            Subject::Instance(Id([4; 16])),
            Detail::Instance { party: Id([2; 16]) },
        ),
        Kind::PartyDisabled => (
            Subject::Party(Id([2; 16])),
            Detail::Disabled {
                reason: ReasonClass::Departed,
            },
        ),
        Kind::PartyCompromised => (
            Subject::Party(Id([2; 16])),
            Detail::Compromised {
                keys: vec![(Id([4; 16]), [5; 32])],
                occurred_at: None,
                window_from: 1,
                declared_at: 2,
                evidence: Digest([6; 32]),
            },
        ),
        Kind::ProjectionInvalidated => (Subject::Projection(Digest([3; 32])), Detail::None),
        Kind::AcceptanceChanged => (Subject::Acceptance(Id([10; 16])), Detail::None),
        Kind::MandateEnded | Kind::AuthorityExpired => {
            (Subject::Mandate(Id([5; 16])), Detail::None)
        }
        _ => (Subject::Grant(Id([5; 16])), Detail::None),
    };
    Event {
        kind,
        domain: d,
        source: if kind == Kind::PartyCompromised {
            Source::Claim(Id([8; 16]))
        } else {
            Source::Exercise(Digest([9; 32]))
        },
        subject,
        at: 1_793_750_400_000,
        detail,
    }
}

// OP-149 m.4, m.7: what the transmitter builds for every event meets the contracts, in both
// the SET and the webhook form
#[test]
fn built_events_meet_the_contracts() {
    let mut built = Vec::new();
    for (i, kind) in Kind::ALL.into_iter().enumerate() {
        built.push(authority_ready(&sample(kind), &[i as u8; 32]));
    }
    // OP-150 m.3 (m), MUST-NEVER-13: the product name in api_client.* is any registered
    // product's, first or third party
    let change = |kind, product: &str| {
        IdentityEvent::api_client(
            kind,
            [1; 32],
            &ClientChange {
                tenant: TENANT,
                realm: &[2; 16],
                client_id: "cli_abc",
                exercise: &[3; 32],
                platform_product: Some(&PlatformProduct::parse(product).unwrap()),
                at: 5,
            },
        )
    };
    for e in [
        change(IdentityKind::ApiClientCreated, "work"),
        change(IdentityKind::ApiClientUpdated, "acme-ledger"),
        change(IdentityKind::ApiClientDisabled, "work"),
        IdentityEvent::tenant_created([2; 32], TENANT, "pool-default", 5),
        IdentityEvent::organization(
            IdentityKind::OrganizationCreated,
            [3; 32],
            TENANT,
            &[4; 16],
            5,
        ),
        IdentityEvent::organization(
            IdentityKind::OrganizationUpdated,
            [4; 32],
            TENANT,
            &[4; 16],
            5,
        ),
        IdentityEvent::party_suspended([5; 32], &[2; 16], 5),
        // §9.9.3 rule 6, P50
        IdentityEvent::projection_invalidated([6; 32], &[7; 32], &[8; 32], &[9; 16], 5),
    ] {
        let back =
            IdentityEvent::from_outbox(e.kind.outbox_kind(), &e.to_outbox().unwrap()).unwrap();
        assert_eq!(back, e);
        built.push(e.ready());
    }
    // the realm's authorization server writes what the transmitter reads
    assert_eq!(
        IdentityKind::ProjectionInvalidated.outbox_kind(),
        access_identity_oauth::domain::tokens::INVALIDATED_OUTBOX
    );
    let mut names: Vec<&str> = built.iter().map(|r| r.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), NAMES.len());
    for r in &built {
        let mut claims = set_claims(r, "https://id.example/realms/shop", "work", 1_793_750_400);
        assert_set(&claims);
        // OP-149 m.17 (e)
        set_tenant(&mut claims, OTHER);
        assert_set(&claims);
        assert_eq!(claims["access_tenant"], OTHER);
        let ce: Json =
            serde_json::from_slice(&cloud_event(&claims, TENANT, &[2; 16], r.at).unwrap()).unwrap();
        assert_eq!(ce["accesstenant"], TENANT);
        assert_cloud_event(&ce);
    }
}

// SSF 1.0 §7.1, §8.1.1, RFC 8936 §2.5
#[test]
fn transmitter_documents_meet_the_contracts() {
    let iss = "https://id.example/realms/shop";
    assert_valid(
        "ssf-configuration.schema.json",
        &ssf_configuration(iss, &format!("{iss}/jwks.json")),
    );
    for (channel, endpoint) in [
        (
            Channel::Webhook,
            Some("https://work.example/v1/access/events"),
        ),
        (Channel::SsfPush, Some("https://work.example/ssf")),
        (Channel::SsfPoll, None),
    ] {
        assert_valid(
            "stream.schema.json",
            &stream_json(
                iss,
                &[1; 16],
                channel,
                endpoint,
                "work",
                &[urn("party.disabled")],
                "enabled",
            ),
        );
    }
    assert_valid(
        "poll-response.schema.json",
        &poll_response(&[(String::from("a"), String::from("x.y.z"))], true),
    );
}

fn every_signal() -> Vec<Signal> {
    let (id, s, at) = ([1; 32], [2; 16], 1_793_750_400_000);
    vec![
        Signal::session_revoked(id, s, Initiator::Admin, at),
        Signal::credential_change(id, s, CredentialType::App, ChangeType::Revoke, at),
        Signal::assurance_level(id, s, "aal2", Some("aal1"), at),
        Signal::token_claims_change(id, s, &["email"], at),
        Signal::device_compliance(id, s, false, at),
        Signal::risk_level(id, s, RiskLevel::High, Some(RiskLevel::Low), at),
        Signal::session_established(id, s, at),
        Signal::session_presented(id, s, at),
        Signal::account_disabled(id, s, at),
        Signal::account_purged(id, s, at),
        Signal::identifier_recycled(id, s, at),
        Signal::credential_compromise(id, None, CredentialType::Key, at),
    ]
}

fn signal_set(s: &Signal, receiver: &[u8]) -> Json {
    let iss = "https://id.example/realms/shop";
    let jti = derived_id("access/signal-set/v1", &s.id, receiver);
    let txn = derived_id("access/signal-txn/v1", &s.id, receiver);
    let sub_id = match s.subject {
        Some(_) => serde_json::json!({"format": "iss_sub", "iss": iss, "sub": "pairwise-sub"}),
        None => serde_json::json!({"format": "uri", "uri": iss}),
    };
    standard_claims(
        &Envelope {
            iss,
            aud: "rp",
            iat_s: 1,
            jti: &jti,
            txn: &txn,
        },
        &signal_uri(s.kind),
        &sub_id,
        s.event_body(),
    )
}

// TN-39, TN-41, TN-43: every CAEP and RISC event has a schema and an example, and what the
// transmitter builds meets them: one event per SET, `txn`, `sub_id`, no `sub`, no `exp`
#[test]
fn caep_and_risc_sets_meet_the_contracts() {
    let built = every_signal();
    let kinds: Vec<SignalKind> = built.iter().map(|s| s.kind).collect();
    assert_eq!(kinds, SignalKind::ALL.to_vec());
    for s in &built {
        let uri = signal_uri(s.kind);
        let example = load(&format!(
            "examples/{}",
            support::schema_of(&uri).replace(".schema", "")
        ));
        assert_eq!(assert_set(&example), uri);
        let claims = signal_set(s, &[9; 16]);
        assert_eq!(assert_set(&claims), uri);
        let o = claims.as_object().unwrap();
        assert!(!o.contains_key("sub") && !o.contains_key("exp"));
        assert_eq!(o["events"].as_object().unwrap().len(), 1);
        let ce: Json =
            serde_json::from_slice(&cloud_event(&claims, TENANT, &[2; 16], s.at).unwrap()).unwrap();
        assert_valid("cloudevent.schema.json", &ce);
    }
}

// TI-RT10: a signal's ids are not a subject hash, and two receivers of the same signal get
// unrelated jti and txn, so they cannot link their copies of one subject
#[test]
fn signal_ids_are_per_receiver_and_not_subject_hashes() {
    let s = Signal::session_established([7; 32], [2; 16], 0);
    let a = signal_set(&s, &[1; 16]);
    let b = signal_set(&s, &[2; 16]);
    assert_ne!(a["jti"], b["jti"]);
    assert_ne!(a["txn"], b["txn"]);
    let other = Signal::session_established([8; 32], [2; 16], 0);
    assert_ne!(signal_set(&other, &[1; 16])["jti"], a["jti"]);
    let subject_hash = access_kernel::json::b64url_encode(&access_crypto::oauth::opaque_digest(
        "access/signal-set/v1",
        &[2; 16],
    ));
    assert_ne!(a["jti"], Json::from(subject_hash));
}

// TN-41, §9.16: an Access event's CAEP counterpart meets the CAEP schema and shares the
// Access event's txn; authority-revoked has none
#[test]
fn counterparts_meet_the_caep_contracts() {
    for kind in [
        Kind::InstanceTerminated,
        Kind::AuthorityNarrowed,
        Kind::RevalidationRequired,
    ] {
        let r = authority_ready(&sample(kind), &[4; 32]);
        let standard = counterpart(r.name).unwrap();
        let uri = signal_uri(standard);
        let events = vec![urn(r.name), uri.clone()];
        assert_eq!(forms(r.name, Profile::Both, &events).len(), 2);
        let claims = standard_claims(
            &Envelope {
                iss: "https://id.example/realms/shop",
                aud: "rp",
                iat_s: 1,
                jti: &derived_id("access/set-counterpart/v1", &[4; 32], uri.as_bytes()),
                txn: &r.id,
            },
            &uri,
            &serde_json::json!({"format": "opaque", "id": r.sub_id}),
            counterpart_body(standard, r.name, r.at),
        );
        assert_eq!(assert_set(&claims), uri);
        assert_eq!(claims["txn"], set_claims(&r, "https://x", "rp", 1)["txn"]);
    }
    assert_eq!(counterpart("authority-revoked"), None);
}
