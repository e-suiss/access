//! A domain's Replica Mirror and streamed Record Export (§16.6.1, T21, AP-14, TN-79, OP-158
//! m.3 (f), (g)): `mirror.cddl` and `export.cddl` frames as CBOR sequences.

use serde_json::{Map, Value, json};

use super::problems;
use crate::mirror::{EXPORT_PATH, EXPORTS_PATH, MIRROR_PATH, SEQUENCE};

fn parameter(name: &str, place: &str, required: bool) -> Value {
    json!({
        "name": name,
        "in": place,
        "required": required,
        "schema": { "type": "string", "minLength": 1, "maxLength": 128 },
    })
}

fn path_parameters(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{')?.strip_suffix('}'))
        .map(|n| parameter(n, "path", true))
        .collect()
}

fn operation(
    path: &str,
    (operation, summary): (&str, &str),
    query: &[&str],
    ok: (&str, &str, &str),
    refusals: &[(&str, &str)],
) -> Value {
    let mut responses = problems(refusals);
    responses.insert(
        ok.0.into(),
        json!({ "description": ok.2, "content": { ok.1: { "schema": {} } } }),
    );
    let mut parameters = path_parameters(path);
    parameters.extend(query.iter().map(|q| parameter(q, "query", false)));
    json!({
        "operationId": operation,
        "summary": summary,
        "parameters": parameters,
        "responses": responses,
    })
}

/// The served routes.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    let mut exports = operation(
        EXPORTS_PATH,
        (
            "startExport",
            "Starts a Record Export: the body is the ADP request that committed the access.audit_export Exercise, with its AIS, and the authenticated PEP is the one its AIS names. A package streams at once as a CBOR sequence (export.cddl) read 10 000 records at a time with no limit on the range; with `stream: \"mirror\"` the answer names the Replica Mirror run. Billing, quota or plan state never closes it (anti-hostage k.2). It is the domain's record, apart from a person's data export (TN-79).",
        ),
        &[],
        ("200", SEQUENCE, "The package."),
        &[
            (
                "400",
                "The request is not this PEP's allowed export Exercise, or its range or disclosure is refused.",
            ),
            ("401", "pep-unauthenticated: no authenticated PEP."),
            ("503", "Temporarily unavailable; retry."),
        ],
    );
    if let Value::Object(m) = &mut exports
        && let Some(Value::Object(r)) = m.get_mut("responses")
    {
        r.insert(
            "201".into(),
            json!({ "description": "The mirror run: its `export` id and first size.", "content": { "application/json": { "schema": {} } } }),
        );
    }
    paths.insert(EXPORTS_PATH.to_owned(), json!({ "post": exports }));
    paths.insert(
        EXPORT_PATH.to_owned(),
        json!({ "get": operation(
            EXPORT_PATH,
            (
                "getExport",
                "A started package's stream again from `from`, for the PEP that committed its Exercise (OP-158 m.3 (g)).",
            ),
            &["from"],
            ("200", SEQUENCE, "The package from `from`."),
            &[
                ("400", "No such run for this PEP, or `from` is outside its range."),
                ("401", "pep-unauthenticated: no authenticated PEP."),
                ("503", "Temporarily unavailable; retry."),
            ],
        )}),
    );
    paths.insert(
        MIRROR_PATH.to_owned(),
        json!({
            "get": operation(
                MIRROR_PATH,
                (
                    "getMirror",
                    "The Replica Mirror of run `export`: the records from tree size `from` and the signed checkpoints after size `checkpoint` with their key excerpts, as a CBOR sequence (mirror.cddl); when nothing is new within a few seconds, a heartbeat. Resumable from any size. Only the PEP that started the run reads it, and only while its Party still audits the domain (T21, G28). A replica copy is advisory: never a source of ALLOW (P43).",
                ),
                &["export", "from", "checkpoint"],
                ("200", SEQUENCE, "The frames."),
                &[
                    ("400", "No such mirror run for this PEP, its Party no longer audits the domain, or the query is malformed."),
                    ("401", "pep-unauthenticated: no authenticated PEP."),
                    ("503", "Temporarily unavailable; retry."),
                ],
            ),
            "post": operation(
                MIRROR_PATH,
                (
                    "ackMirror",
                    "A declared replica's signed-replica-ack (mirror.cddl): it holds the whole prefix up to `size` with `root`. It counts only under the key the domain declares for the replica and for a checkpoint the domain signed; without one, no revocation or CT3 commit is acknowledged (TI-13, SEC23).",
                ),
                &[],
                ("204", "application/json", "Kept."),
                &[
                    ("400", "replica-ack: malformed."),
                    ("403", "replica-unknown, replica-ack-signature or replica-ack-checkpoint: not counted."),
                    ("503", "Temporarily unavailable; retry."),
                ],
            ),
        }),
    );
}
