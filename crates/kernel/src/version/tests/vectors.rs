//! `version.json`: version acceptance (L0-GEN-7, L0-ENC-38, OP-126 m.2).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::*;
use crate::codec::Canonical as _;

use crate::vector_rules::hex;

/// The stable reason of a version check failure, with its track.
fn reason(e: VersionError) -> (&'static str, &'static str) {
    let track = |t| match t {
        Track::Core => "core",
        Track::MetaSchema => "meta-schema",
        Track::Profile => "profile",
    };
    match e {
        VersionError::NotUnderstood(t) => ("not-understood", track(t)),
        VersionError::NotAdopted(t) => ("not-adopted", track(t)),
        VersionError::BelowMinimum(t) => ("below-minimum", track(t)),
    }
}

type Case = (
    &'static str,
    SpecVersions,
    SpecVersions,
    SpecVersions,
    SpecVersions,
);

fn cases() -> Vec<Case> {
    let az = |n| [("authzen", n)];
    alloc::vec![
        (
            "older-accepted",
            v(1, 1, &az(1)),
            v(2, 1, &az(2)),
            v(2, 1, &az(2)),
            v(1, 1, &[]),
        ),
        (
            "core-not-understood",
            v(2, 1, &[]),
            v(1, 1, &[]),
            v(1, 1, &[]),
            v(1, 1, &[])
        ),
        (
            "meta-schema-not-understood",
            v(1, 2, &[]),
            v(1, 1, &[]),
            v(1, 1, &[]),
            v(1, 1, &[]),
        ),
        (
            "profile-newer-not-understood",
            v(1, 1, &az(2)),
            v(1, 1, &az(1)),
            v(1, 1, &az(1)),
            v(1, 1, &[]),
        ),
        (
            "profile-unknown-not-understood",
            v(1, 1, &[("ssf", 1)]),
            v(1, 1, &az(1)),
            v(1, 1, &az(1)),
            v(1, 1, &[]),
        ),
        (
            "core-not-adopted",
            v(2, 1, &[]),
            v(2, 2, &[]),
            v(1, 1, &[]),
            v(1, 1, &[])
        ),
        (
            "profile-not-adopted",
            v(1, 1, &[("ssf", 1)]),
            v(2, 2, &[("ssf", 1)]),
            v(1, 1, &[]),
            v(1, 1, &[]),
        ),
        (
            "core-below-minimum",
            v(1, 2, &[]),
            v(3, 3, &[]),
            v(3, 3, &[]),
            v(2, 2, &[])
        ),
        (
            "profile-below-minimum",
            v(2, 2, &az(1)),
            v(3, 3, &az(3)),
            v(3, 3, &az(3)),
            v(2, 2, &az(2)),
        ),
        (
            "not-understood-before-not-adopted",
            v(3, 1, &[]),
            v(2, 1, &[]),
            v(1, 1, &[]),
            v(1, 1, &[]),
        ),
        (
            "not-adopted-before-below-minimum",
            v(2, 1, &[]),
            v(2, 2, &[]),
            v(1, 2, &[]),
            v(1, 2, &[]),
        ),
        (
            "profile-moves-only-its-track",
            v(1, 1, &az(2)),
            v(1, 1, &az(2)),
            v(1, 1, &az(2)),
            v(1, 1, &az(1)),
        ),
    ]
}

fn rules(id: &str) -> &'static [&'static str] {
    match id {
        "older-accepted" | "core-not-understood" | "profile-newer-not-understood" => {
            &["L0-ENC-38", "L0-GEN-7"]
        }
        _ => &["L0-ENC-38"],
    }
}

// L0-GEN-7, L0-ENC-38, OP-126 m.2
#[test]
fn version_vectors_match() {
    let mut lines = Vec::new();
    for (id, cited, supported, adopted, minimum) in cases() {
        let expect = match check_domain(&cited, &supported, &domain(&adopted, &minimum)) {
            Ok(()) => String::from("\"valid\": true"),
            Err(e) => {
                let (r, t) = reason(e);
                format!("\"error\": \"{r}\", \"track\": \"{t}\"")
            }
        };
        lines.push(format!(
            "  {{\"id\": \"{id}\", {}, \"cited\": \"{}\", \"supported\": \"{}\", \"adopted\": \"{}\", \"minimum\": \"{}\", {expect}}}",
            crate::vector_rules::field(rules(id)),
            hex(&cited.to_bytes().unwrap()),
            hex(&supported.to_bytes().unwrap()),
            hex(&adopted.to_bytes().unwrap()),
            hex(&minimum.to_bytes().unwrap()),
        ));
    }
    let json = format!(
        "{{\n \"rule\": \"OP-126\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"version.check\",\n \"cases\": [\n{}\n ]\n}}\n",
        lines.join(",\n")
    );
    crate::vector_rules::golden(
        "version.json",
        include_str!("../../../../../conformance/vectors/core/1/version.json"),
        &json,
    );
}
