//! A domain's transparency routes (§9.16, T19, K15, OP-158 m.3 (c), (d)): the witnessed
//! checkpoints, the inclusion bundle (`inclusion-bundle.cddl`) and the C2SP hash tiles.

use serde_json::{Map, Value, json};

use super::problems;
use crate::transparency::{
    CHECKPOINTS_PATH, INCLUSION_PATH, PQ_CHECKPOINTS_PATH, PQ_INCLUSION_PATH, TILE_PATH,
};

fn parameter(name: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "schema": { "type": "string", "minLength": 1, "maxLength": 128 },
    })
}

fn get(
    paths: &mut Map<String, Value>,
    path: &str,
    (operation, summary): (&str, &str),
    ok: (&str, &str),
    refusals: &[(&str, &str)],
) {
    let mut responses = problems(refusals);
    responses.insert(
        "200".into(),
        json!({ "description": ok.1, "content": { ok.0: { "schema": {} } } }),
    );
    let names: Vec<Value> = path
        .split('/')
        .filter_map(|s| s.strip_prefix('{')?.strip_suffix('}'))
        .map(|n| parameter(n.trim_start_matches('*')))
        .collect();
    paths.insert(
        path.replace("{*index}", "{index}"),
        json!({ "get": {
            "operationId": operation,
            "summary": summary,
            "parameters": names,
            "responses": responses,
        }}),
    );
}

/// The served routes.
pub(super) fn paths(paths: &mut Map<String, Value>) {
    get(
        paths,
        CHECKPOINTS_PATH,
        (
            "listCheckpoints",
            "witnessed_through, the newest checkpoint an independent witness cosigned with its cosignatures and key excerpt, the declared witnesses and whether equivocation may be called detectable (§16.6, U9, OP-158 m.3 (c), (d)). Anyone may copy it.",
        ),
        ("application/json", "The domain's witnessed checkpoint."),
        &[
            ("404", "checkpoint-unknown: no such domain."),
            ("503", "checkpoints-unavailable: retry."),
        ],
    );
    get(
        paths,
        INCLUSION_PATH,
        (
            "getInclusionBundle",
            "The inclusion bundle of the record at `position` in the witnessed checkpoint of `size` (inclusion-bundle.cddl): the record disclosure with only `artifacts` opened, the inclusion proof and the checkpoint with its cosignatures (T19, §17.6.1 rule 5). For an authenticated PEP.",
        ),
        ("application/cbor", "The bundle."),
        &[
            ("401", "pep-required: no authenticated PEP."),
            (
                "404",
                "checkpoint-unknown: no such domain, size or position.",
            ),
            (
                "409",
                "checkpoint-not-witnessed: no independent witness cosigned a checkpoint of that size.",
            ),
            ("503", "checkpoints-unavailable: retry."),
        ],
    );
    get(
        paths,
        TILE_PATH,
        (
            "getTile",
            "A C2SP tlog-tiles hash tile of the witnessed tree: `index` in three-digit groups, `.p/<width>` for a partial tile (K15). Entries are not published.",
        ),
        (
            "application/octet-stream",
            "The tile's hashes, concatenated.",
        ),
        &[
            (
                "404",
                "checkpoint-unknown: no such tile in the witnessed tree.",
            ),
            ("409", "checkpoint-not-witnessed: nothing is witnessed yet."),
            ("503", "checkpoints-unavailable: retry."),
        ],
    );
    // CR-45 RA-2, RA-3, RA-4, RA-5, OP-159 m.13
    get(
        paths,
        PQ_CHECKPOINTS_PATH,
        (
            "listPqCheckpoints",
            "The domain's post-quantum re-anchor checkpoints: each a COSE_Sign1 over the C2SP note body signed with an ML-DSA operational key, with its witnesses' post-quantum cosigns, newest first (CR-45 RA-2, RA-3, pq-checkpoint.cddl, OP-159 m.3 (g)).",
        ),
        ("application/cbor", "The pq-checkpoint-list."),
        &[
            ("404", "checkpoint-unknown: no such domain."),
            ("503", "checkpoints-unavailable: retry."),
        ],
    );
    get(
        paths,
        PQ_INCLUSION_PATH,
        (
            "getPqInclusionBundle",
            "The inclusion bundle of the record at `position` against the post-quantum re-anchor checkpoint of `size`, with the consistency proof from the previous re-anchor (CR-45 RA-4, RA-5, OP-159 m.3 (g)). For an authenticated PEP.",
        ),
        ("application/cbor", "The bundle."),
        &[
            ("401", "pep-required: no authenticated PEP."),
            (
                "404",
                "checkpoint-unknown: no such domain, re-anchor checkpoint or position.",
            ),
            (
                "409",
                "checkpoint-not-witnessed: no independent witness cosigned that re-anchor checkpoint.",
            ),
            ("503", "checkpoints-unavailable: retry."),
        ],
    );
    algorithms(paths);
}

/// A request body: media type and schema.
type RequestBody<'a> = Option<(&'a str, Value)>;

fn post(
    paths: &mut Map<String, Value>,
    path: &str,
    (operation, summary): (&str, &str),
    (request, ok): (RequestBody<'_>, &[(&str, &str)]),
    refusals: &[(&str, &str)],
) {
    let mut responses = problems(refusals);
    for (status, description) in ok {
        responses.insert(
            (*status).into(),
            json!({ "description": description, "content": { "application/json": { "schema": {} } } }),
        );
    }
    let mut op = json!({
        "operationId": operation,
        "summary": summary,
        "parameters": [parameter("domain")],
        "responses": responses,
    });
    if let (Some((media, schema)), Some(o)) = (request, op.as_object_mut()) {
        o.insert(
            "requestBody".into(),
            json!({ "required": true, "content": { media: { "schema": schema } } }),
        );
    }
    paths.insert(path.to_owned(), json!({ "post": op }));
}

// §15.16, CR-45 RA-6, OP-159 m.3 (e), (f), (g), m.9 (h)
fn algorithms(paths: &mut Map<String, Value>) {
    use crate::algorithms::{ADMIT_PATH, REANCHOR_PATH, RETIRE_PATH};
    let common = [
        ("400", "The request is refused; nothing changed."),
        ("401", "pep-required: no authenticated PEP."),
        ("404", "not-found: no such domain."),
        ("503", "Temporarily unavailable; retry."),
    ];
    let mut admit = common.to_vec();
    admit.push((
        "409",
        "algorithm-profile-conflict: the domain declares the FIPS profile, so ML-DSA cannot join its allowlist.",
    ));
    post(
        paths,
        ADMIT_PATH,
        (
            "admitAlgorithm",
            "Adds the COSE algorithm {alg} to the domain's allowlist behind the CT3 time-lock (admit_algorithm, CR-44): the first request opens the 24 h lock (202, wait_until); the same request after it and within 7 days admits it (200). Adding ML-DSA makes the hybrid policy both (OP-159 m.3 (e), m.9 (h)).",
        ),
        (
            Some((
                "application/json",
                json!({ "type": "object", "required": ["alg"], "properties": { "alg": { "type": "integer" } } }),
            )),
            &[
                (
                    "202",
                    "The time-lock runs until wait_until; nothing changed yet.",
                ),
                ("200", "The algorithm is in the allowlist."),
            ],
        ),
        &admit,
    );
    let mut retire = common.to_vec();
    retire.push((
        "409",
        "reanchor-required: no anchored post-quantum re-anchor covers the head within the cadence; pq-key-unavailable: no ML-DSA key or binding; algorithm-profile-conflict: not a listed classical algorithm. Nothing is recorded.",
    ));
    post(
        paths,
        RETIRE_PATH,
        (
            "retireAlgorithm",
            "Retires a classical algorithm: the body is the ADP request of the root's algorithm_retire Exercise. A re-anchor runs first; only with an anchored re-anchor that covers the head is the Exercise decided, and only an allowed one leaves the allowlist and notifies the roots and domain administrators (§15.16, CR-45 RA-6, OP-159 m.3 (f)).",
        ),
        (
            Some(("application/json", json!({}))),
            &[("200", "The decision; an ALLOW retired the algorithm.")],
        ),
        &retire,
    );
    let mut again = common.to_vec();
    again.push((
        "409",
        "reanchor-no-pq-witness: no independent witness with a declared ML-DSA key (RB-0); pq-key-unavailable: no ML-DSA key; checkpoint-not-witnessed: no witnessed checkpoint yet.",
    ));
    post(
        paths,
        REANCHOR_PATH,
        (
            "reanchorDomain",
            "One post-quantum re-anchor of the latest witnessed checkpoint now: pending until an independent witness's ML-DSA cosign arrives, then published as pq_reanchor (CR-45 RA-2, RA-3, RA-6, RR-35).",
        ),
        (
            None,
            &[(
                "200",
                "status pending, or anchored with size, time and witnesses.",
            )],
        ),
        &again,
    );
}
