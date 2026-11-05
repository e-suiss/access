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

use access_identity_events::domain::catalog::{
    ClientChange, IdentityEvent, IdentityKind, NAMES, PlatformProduct, authority_ready, urn,
};
use access_identity_events::domain::set::{cloud_event, set_claims, set_tenant};
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
    assert_eq!(listed, NAMES.len() + 7);
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
    let change = |kind| {
        IdentityEvent::api_client(
            kind,
            [1; 32],
            &ClientChange {
                tenant: TENANT,
                realm: &[2; 16],
                client_id: "cli_abc",
                exercise: &[3; 32],
                platform_product: Some(PlatformProduct::Work),
                at: 5,
            },
        )
    };
    for e in [
        change(IdentityKind::ApiClientCreated),
        change(IdentityKind::ApiClientUpdated),
        change(IdentityKind::ApiClientDisabled),
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
