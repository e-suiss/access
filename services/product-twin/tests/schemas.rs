//! The seam schemas under `conformance/seams/schemas/` (§7.9.10.3, OP-156 m.3 (u)): each one
//! loads through the Kernel's own decoders, so a product needs no new primitive.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;

use access_product_twin::Schema;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/seams/schemas")
}

fn load(name: &str) -> Schema {
    Schema::parse(&std::fs::read_to_string(dir().join(format!("{name}.toml"))).unwrap()).unwrap()
}

// §7.9.10.3, E16
#[test]
fn every_seam_schema_loads_on_kernel_types_alone() {
    let mut names = Vec::new();
    for e in std::fs::read_dir(dir()).unwrap() {
        let path = e.unwrap().path();
        if path.extension().and_then(|x| x.to_str()) != Some("toml") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap().to_owned();
        let s = load(&stem);
        assert_eq!(s.namespace, stem, "{}", path.display());
        names.push(stem);
    }
    names.sort();
    assert_eq!(
        names,
        [
            "commerce",
            "health",
            "pay",
            "relay.interrupt",
            "ride",
            "serve"
        ]
    );
}

// §7.9.10.3
#[test]
fn ride_is_a_schema_a_membership_claim_and_an_amount() {
    let ride = load("ride");
    let request = ride.action("request").unwrap();
    assert_eq!(request.namespace, "ride");
    assert_eq!(
        ride.classes["request"]["fare"], "amount",
        "the fare bounds an amount budget"
    );
    let fare = ride.actions.iter().find(|a| a.name == "request").unwrap();
    assert_eq!(
        fare.reversibility,
        Some(access_kernel::schema::Reversibility::Compensable)
    );
    assert_eq!(
        ride.package()["actions"][0]["reversibility"],
        "compensable",
        "the publication carries the declared reversibility"
    );
    let driver = ride.claim("ride_driver").unwrap();
    assert_eq!(driver.use_, access_kernel::claim::SUBJECT_SELECTION);
    assert!(ride.spp(access_kernel::model::Id([1; 16])).is_some());
}

// §7.9.10.3, §7.9.15
#[test]
fn health_is_a_schema_a_guardian_claim_and_a_recipient() {
    let health = load("health");
    assert_eq!(health.classes["share"]["recipient"], "recipient");
    assert!(access_kernel::contribution::is_core_class(
        access_kernel::contribution::DISCLOSE
    ));
    let guardian = health.claim("health_guardian").unwrap();
    assert_eq!(guardian.use_, access_kernel::claim::SUBJECT_SELECTION);
}

// E12
#[test]
fn an_unclassified_parameter_or_an_unknown_type_is_refused() {
    let base = "product = \"X\"\nnamespace = \"x\"\ncatalog_version = 1\n";
    let unclassified = format!(
        "{base}[[actions]]\nname = \"a\"\nmajor = 1\neffect_class = \"none\"\nparams = {{ n = \"int\" }}\n"
    );
    assert!(Schema::parse(&unclassified).is_err());
    let unknown = format!(
        "{base}[[actions]]\nname = \"a\"\nmajor = 1\neffect_class = \"none\"\nparams = {{ n = \"money\" }}\nclasses = {{ n = \"amount\" }}\n"
    );
    assert!(Schema::parse(&unknown).is_err());
    let tabled = format!(
        "{base}[[claims]]\nclass = \"effect_attestation\"\nvalue = \"bytes\"\nuse = \"predicate-input\"\n"
    );
    assert!(Schema::parse(&tabled).is_err());
}
