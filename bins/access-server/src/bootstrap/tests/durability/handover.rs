//! Cooperative handover and binding re-anchor between two `access-server` installs (OP-158 m.3 (l)),
//! on the real router, sequencer, store and `SoftHSM` signers with real `access-witness` processes
//! (OP-158 m.5, OP-153 m.3 (gg)): freeze, `C_k`, the export, the incoming provider's fold, the
//! double-signed batch, `C_{h+1}` and the witnesses' fence, the take-over, and the old
//! provider's refused writes and old-key artefacts afterwards.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use access_authority_core::adapters::transcript;
use access_authority_core::app::Incoming;
use access_authority_core::app::handover::{self, CONTINUATION_CLASS, NO_WRITE_CLASS};
use access_authority_core::domain::{ProofRef, Request as CoreRequest};
use access_authority_sequencer::adapters::{PgHeads, SocketSigner};
use access_authority_sequencer::ports::NoteSigner as _;
use access_authority_sequencer::witness::{Target, WitnessError, add_checkpoint, board, latest};
use access_authority_signer::adapters::call as sign_call;
use access_authority_signer::handover::{CONTINUATION, NO_WRITE};
use access_authority_signer::protocol::{Request as SignRequest, Response as SignResponse};
use access_http::adp::adapters::{Discovery, router as adp_router};
use access_http::adp::app::Service;
use access_http::{Limits, harden};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::ParamValue;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{self, ExerciseBasis, Payload};
use access_kernel::record::{RecordEnvelope, RecordKind};
use access_kernel::recovery::{CheckpointRef, HandoverInput};
use access_kernel::verify::key_scope::{
    BindingKey, Declarations, DomainMetadata, KeyScopeError, KeyUsage, operational_key,
};
use access_product_twin::witness::Witness;
use access_store::authority::{CommitBatch, HeadRow, LogRecord, read_head, read_log};
use access_store::handover::Role;
use access_store::scope::DomainId;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use suiss_crypto::note::Verifier;
use suiss_crypto::sig::PureBackend;
use suiss_ledger::checkpoint::cadence::Cadence;
use suiss_ledger::checkpoint::witness::Refused;
use suiss_ledger::replica::mirror::{Frame, read_all};

use super::super::authzen::{PEP, Pdp, pdp_timed};
use super::export::{routes, start};
use super::replica::{as_pep, bin, call, commit_export, domain_path, signer_socket, start_mirror};
use crate::checkpoints::domain_step;
use crate::checkpoints::publish::Publisher;

const OUTGOING: &str = "Suiss";
const INCOMING: &str = "Provider B Ltd";
const INDEPENDENT: &str = "Example Witness Ltd";

fn witness_bin() -> PathBuf {
    bin("access-witness", "access-witness")
}

fn now() -> u64 {
    access_authority_signer::adapters::now_ms()
}

fn target(w: &Witness, operator: &str) -> Target {
    Target::new(&w.url, &w.vkey, operator, OUTGOING).unwrap()
}

/// The declarations naming `witnesses` with their operators (OP-158 m.6 (e)).
fn declared(witnesses: &[(&Witness, &str, bool)]) -> Declarations {
    let mut d = access_authority_signer::domain::declared_default();
    for (w, operator, independent) in witnesses {
        let (name, rest) = w.vkey.split_once('+').unwrap();
        let b64 = rest.split_once('+').unwrap().1;
        let raw = suiss_crypto::note::base64_decode(b64).unwrap();
        let key: [u8; 32] = raw[1..].try_into().unwrap();
        d.witnesses
            .push(access_kernel::verify::key_scope::Witness::new(
                name.to_owned(),
                suiss_crypto::cose::PublicKey::Ed25519(key),
                suiss_crypto::cose::Algorithm::Ed25519,
                (*operator).to_owned(),
                *independent,
            ));
    }
    d
}

async fn declare(socket: &std::path::Path, domain: Digest, d: Declarations) {
    let answer = sign_call(
        socket,
        &SignRequest::Declare {
            domain,
            declared: Box::new(d),
        },
    )
    .await
    .unwrap();
    assert_eq!(answer, SignResponse::Opened);
}

/// One checkpointer step of `domain` now, due out of cycle at the head: the row and what the
/// witnesses gave.
async fn step(
    db: &access_store::testing::TestDb,
    socket: &std::path::Path,
    publisher: &Publisher,
    domain: Digest,
) -> (
    access_store::authority_checkpoint::AuthorityCheckpoint,
    crate::checkpoints::publish::Published,
) {
    let size = read_head(&db.app, &DomainId::from_bytes(domain.0))
        .await
        .unwrap()
        .pos
        + 1;
    board().want(domain, size);
    domain_step(
        (
            &PgHeads(db.app.clone()),
            &SocketSigner::new(socket.to_path_buf()),
            publisher,
        ),
        (&db.app, &db.sequencer),
        (domain, &mut Cadence::default()),
        now(),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn metadata_of(domains: &super::super::TestDomains, d: Digest) -> DomainMetadata {
    let signed = domains.metadata(d).await.unwrap();
    let msg = access_kernel::verify::cose::parse_sign1(&signed).unwrap();
    DomainMetadata::from_bytes(msg.payload.as_deref().unwrap()).unwrap()
}

/// The root's `domain_handover` Exercise to `binding` citing `C_k`, carrying the two
/// statements, committed through the decision point.
async fn hand_over(
    p: &Pdp,
    binding: &BindingKey,
    cited: (u64, [u8; 32]),
    reanchor: bool,
    statements: (Vec<u8>, Vec<u8>),
) -> Result<access_authority_core::app::Response, access_authority_core::CoreError> {
    let payload = Payload::DomainHandover(HandoverInput::new(
        BTreeMap::from([(binding.kid, binding.clone())]),
        CheckpointRef::new(cited.0, Digest(cited.1)),
        reanchor,
    ));
    let at = p.now().await;
    let validity = access_kernel::model::Window {
        from: at.saturating_sub(60_000),
        until: at + 300_000,
    };
    let intent =
        access_internal_api::instances::self_signed_intent(&payload, p.party, validity).unwrap();
    let digest = access_kernel::intent::intent_digest(&intent).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&p.domain));
    let ais = super::super::sign(
        &p.root,
        &access_kernel::ais::Statement {
            domain: p.domain,
            nonce: nonce.clone(),
            intent: digest,
            mode: Mode::Commit,
            pep: String::from(PEP),
            capacity: Capacity::Own,
            basis,
            iat: at,
            exercise: None,
        },
    )
    .unwrap();
    let inc = Incoming {
        request: CoreRequest {
            domain: p.domain,
            mode: Mode::Commit,
            nonce,
            intent,
            payload: Some(payload),
            basis,
            capacity: Capacity::Own,
            proofs: vec![ProofRef::Claim(statements.0), ProofRef::Claim(statements.1)],
            exercise: None,
            consistency: None,
        },
        ais: Some(ais),
        pep: String::from(PEP),
        requester: None,
        explain: false,
        status: None,
        context: None,
    };
    p.w.domains.exercise(&inc).await
}

/// The mirror of `export` from `from`: the records and the last checkpoint with its
/// cosignatures appended, and its excerpt.
async fn mirror(
    p: &Pdp,
    router: &axum::Router,
    export: [u8; 32],
    from: u64,
    until: u64,
) -> (Vec<RecordEnvelope>, String, Vec<u8>) {
    let mut records = Vec::new();
    let mut last = None;
    let mut at = from;
    for _ in 0..20 {
        let path = format!(
            "/access/v1/domains/{}/mirror?export={}&from={at}",
            domain_path(&p.domain),
            b64url_encode(&export)
        );
        let (s, b) = call(router, Request::get(path).body(Body::empty()).unwrap()).await;
        assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        for f in read_all(&b).unwrap() {
            match f {
                Frame::Record {
                    position, envelope, ..
                } if position >= from => {
                    records.push(RecordEnvelope::from_bytes(&envelope).unwrap());
                    at = position + 1;
                }
                Frame::Checkpoint {
                    note,
                    cosignatures,
                    excerpt,
                } => {
                    let mut cosigned = note;
                    for c in cosignatures {
                        cosigned.push_str(std::str::from_utf8(&c).unwrap());
                    }
                    last = Some((cosigned, excerpt.unwrap_or_default()));
                }
                _ => {}
            }
        }
        if at > until
            && last
                .as_ref()
                .is_some_and(|(n, _)| n.contains(&format!("\n{}\n", until + 1)))
        {
            break;
        }
    }
    let (note, excerpt) = last.unwrap();
    (records, note, excerpt)
}

fn adp(domains: &std::sync::Arc<super::super::TestDomains>) -> axum::Router {
    let limits = Limits::default();
    as_pep(
        harden(
            adp_router(
                Service::new(domains.clone(), limits.max_body_bytes),
                Discovery {
                    issuer: String::from("https://access.test"),
                },
            ),
            limits,
        ),
        PEP,
    )
}

async fn evaluate(router: &axum::Router, body: &serde_json::Value) -> (StatusCode, Vec<u8>) {
    call(
        router,
        Request::post("/access/v1/evaluation")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

/// A receipt-usage artefact signed by `domain`'s current operational key at `socket`: its
/// excerpt.
async fn artefact(socket: &std::path::Path, domain: Digest) -> (Vec<u8>, u64) {
    let at = now();
    match sign_call(
        socket,
        &SignRequest::Sign {
            domain,
            usage: KeyUsage::Receipt,
            content_type: String::from(access_kernel::receipt::CONTENT_TYPE),
            payload: vec![0xa0],
            at,
        },
    )
    .await
    .unwrap()
    {
        SignResponse::Signed { excerpt, .. } => (excerpt, at),
        other => panic!("{other:?}"),
    }
}

/// An old-binding checkpoint note of `size` the outgoing signer still signs: the witnesses
/// must not cosign it (U11).
async fn forged(socket: &std::path::Path, domain: Digest, size: u64) -> (String, Vec<u8>) {
    let origin = access_authority_signer::domain::origin(&domain);
    let root = access_crypto::random::bytes::<32>().unwrap();
    let body = suiss_crypto::note::Checkpoint {
        origin,
        size,
        root,
        extensions: vec![format!("issued_at {}", now())],
    }
    .to_body()
    .unwrap();
    let signed = SocketSigner::new(socket.to_path_buf())
        .sign_note(domain, body.clone(), now())
        .await
        .unwrap();
    (format!("{body}\n{}", signed.line), signed.excerpt)
}

fn verify(args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(bin("esuiss-access-verify", "access-verify"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut h, x| {
        let _ = std::fmt::Write::write_fmt(&mut h, format_args!("{x:02x}"));
        h
    })
}

/// A receipt the outgoing provider signed before the handover (`answer`), checked against the
/// incoming provider's metadata `m`, where its binding key is superseded at `C_{h+1}` citing
/// `C_k`: the real `access-verify` and the SDK verifier refuse it alone and accept it with the
/// inclusion bundle the outgoing provider serves for its record in `C_k` and the consistency
/// path to `C_{h+1}` (5780, L0-SIG-80, PI-15, U27, OP-159 m.17 (a)).
async fn superseded_receipt(
    p: &Pdp,
    answer: &[u8],
    m: &DomainMetadata,
    (ck, ch1): (
        &access_store::authority_checkpoint::AuthorityCheckpoint,
        &access_store::authority_checkpoint::AuthorityCheckpoint,
    ),
    witness: &Witness,
    served: &Target,
) {
    use access_kernel::receipt::{Expected, Receipt, ReceiptError};
    use access_verifier::artefact::{self, Evidence, SentError};
    use tower::ServiceExt as _;
    let d = p.domain;
    let answer: serde_json::Value = serde_json::from_slice(answer).unwrap();
    let member = |k: &str| {
        access_kernel::json::b64url_decode(answer["context"]["receipt"][k].as_str().unwrap())
            .unwrap()
    };
    let (sign1, excerpt) = (member("sign1"), member("excerpt"));
    let claimed = Receipt::from_bytes(
        &suiss_crypto::cose::parse_sign1(&sign1)
            .unwrap()
            .payload
            .unwrap(),
    )
    .unwrap();
    assert!(claimed.record < ck.size);
    let origin = access_authority_sequencer::checkpoint::origin(&d);
    let mut req = Request::get(format!(
        "/access/v1/domains/{origin}/checkpoints/{}/inclusion/{}",
        ck.size, claimed.record
    ))
    .body(Body::empty())
    .unwrap();
    req.extensions_mut()
        .insert(access_http::adp::adapters::Pep(PEP.into()));
    let r = access_http::transparency::router(crate::transparency::PgCheckpoints {
        app: p.w.db.app.clone(),
        witnesses: vec![served.clone()],
    })
    .oneshot(req)
    .await
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let bundle = axum::body::to_bytes(r.into_body(), 1 << 22)
        .await
        .unwrap()
        .to_vec();
    let leaves =
        access_store::witness::leaf_hashes(&p.w.db.app, &DomainId::from_bytes(d.0), 0, ch1.size)
            .await
            .unwrap();
    let path =
        suiss_ledger::checkpoint::proof::consistency(leaves.as_slice(), ck.size, ch1.size).unwrap();
    let log = super::checkpoint::log_vkey(&origin, &ck.excerpt);

    let root = std::env::temp_dir().join(format!("j2c-5780-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let file = |name: &str, bytes: &[u8]| {
        let f = root.join(name);
        std::fs::write(&f, bytes).unwrap();
        f.to_str().unwrap().to_owned()
    };
    let (m_file, r_file, x_file, e_file) = (
        file("metadata.cbor", &m.to_bytes().unwrap()),
        file("receipt.cose", &sign1),
        file("excerpt.cose", &excerpt),
        file("evidence.cbor", &bundle),
    );
    let hashes: Vec<String> = path.iter().map(|h| hex(h)).collect();
    let (d_hex, i_hex, now, at_size, at_root, at_path) = (
        hex(&d.0),
        hex(&claimed.intent.0),
        (claimed.iat + 1).to_string(),
        ch1.size.to_string(),
        hex(&ch1.root),
        hashes.join(","),
    );
    let base = [
        "receipt",
        "--metadata",
        m_file.as_str(),
        "--receipt",
        r_file.as_str(),
        "--excerpt",
        x_file.as_str(),
        "--domain",
        d_hex.as_str(),
        "--audience",
        PEP,
        "--intent",
        i_hex.as_str(),
        "--now",
        now.as_str(),
    ];
    let (ok, text) = verify(&base);
    assert!(!ok && text.contains("reject: receipt-key"), "{text}");
    let mut with = base.to_vec();
    with.extend([
        "--evidence",
        e_file.as_str(),
        "--origin",
        origin.as_str(),
        "--log",
        log.as_str(),
        "--cosigners",
        witness.vkey.as_str(),
    ]);
    let (ok, text) = verify(&with);
    assert!(!ok && text.contains("reject: receipt-key"), "{text}");
    with.extend([
        "--at-size",
        at_size.as_str(),
        "--at-root",
        at_root.as_str(),
        "--at-path",
        at_path.as_str(),
    ]);
    let (ok, text) = verify(&with);
    assert!(
        ok && text.contains(&hex(&claimed.to_bytes().unwrap())),
        "{text}"
    );

    let evidence = Evidence::from_bundle(
        &bundle,
        (
            origin.as_str(),
            Verifier::parse(&log).unwrap(),
            vec![Verifier::parse(&witness.vkey).unwrap()],
        ),
        Some((ch1.size, ch1.root, path.clone())),
    )
    .unwrap();
    let expected = Expected {
        domain: &d,
        audience: PEP,
        intent: &claimed.intent,
        now: claimed.iat + 1,
    };
    let sdk = |e: Option<&Evidence>| {
        artefact::receipt(&PureBackend, m, (&sign1, &excerpt, None), &expected, e)
    };
    assert_eq!(sdk(Some(&evidence)), Ok(claimed.clone()));
    assert_eq!(
        sdk(None),
        Err(SentError::Receipt(ReceiptError::Key(
            KeyScopeError::Superseded
        )))
    );
    let pep = access_sdk::authorize::Pep {
        audience: String::from(PEP),
        domain: d,
        metadata: m.clone(),
    };
    let digest = access_kernel::receipt::digest(&claimed).unwrap();
    assert_eq!(
        pep.receipt(
            &PureBackend,
            (&sign1, &excerpt, None),
            &claimed.intent,
            claimed.iat + 1,
            Some(&evidence.of(digest)),
        ),
        Ok(claimed.clone())
    );
    assert_eq!(
        pep.receipt(
            &PureBackend,
            (&sign1, &excerpt, None),
            &claimed.intent,
            claimed.iat + 1,
            None,
        ),
        Err(access_sdk::authorize::Denied::Receipt(ReceiptError::Key(
            KeyScopeError::Superseded
        )))
    );
    let _ = std::fs::remove_dir_all(&root);
}

// §16.6 HO-1…HO-9, U27, U11, PI-15, G32, AP-13, E20, F16, PI-14, OP-158 m.3 (l), Ek B 5780
#[tokio::test(flavor = "multi_thread")]
async fn a_domain_moves_to_a_second_install_and_the_old_provider_is_fenced() {
    let label = "w5-ho-a";
    let b_token = crate::testing::hsm("w5-ho-b");
    let p = pdp_timed(label, Some(0)).await;
    let a_socket = signer_socket(label);
    let d = p.domain;
    let id = DomainId::from_bytes(d.0);
    let router = routes(&p, 512);
    let mut first = None;
    for _ in 0..3 {
        let (s, b) = evaluate(&router, &p.allowed(Mode::Commit).await).await;
        assert_eq!(s, StatusCode::OK);
        first.get_or_insert(b);
    }
    let a_binding = p.w.domains.binding_key(d, false).await.unwrap();
    let suiss_crypto::cose::PublicKey::Ed25519(a_key) = a_binding.key else {
        panic!("ed25519 binding");
    };
    let root = std::env::temp_dir().join(format!("w5-ho-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let mut independent = Witness::start(
        &witness_bin(),
        &root,
        ("w5-independent", INDEPENDENT),
        d.0,
        a_key,
    )
    .unwrap();
    let own = Witness::start(&witness_bin(), &root, ("w5-own", OUTGOING), d.0, a_key).unwrap();
    let decl = declared(&[(&independent, INDEPENDENT, true), (&own, OUTGOING, false)]);
    declare(&a_socket, d, decl.clone()).await;
    let publisher = Publisher {
        targets: vec![target(&independent, INDEPENDENT), target(&own, OUTGOING)],
        sinks: Vec::new(),
    };
    let (_, out) = step(&p.w.db, &a_socket, &publisher, d).await;
    assert_eq!(out.independent, 1, "{out:?}");
    let before = metadata_of(&p.w.domains, d).await;
    let (old_excerpt, old_iat) = artefact(&a_socket, d).await;

    // G32
    let faulty = super::replay::faulty_allow(&p).await;
    let package_body = commit_export(
        &p,
        &router,
        &[("disclosure", ParamValue::Enum(String::from("full")))],
    )
    .await;
    let mirror_run = start_mirror(&p, &router).await;

    // HO-1, HO-2
    let frozen = p.w.domains.freeze(d, Role::Outgoing).await.unwrap();
    let head = read_head(&p.w.db.app, &id).await.unwrap().pos;
    assert_eq!(frozen.k, head + 1);
    let (s, b) = evaluate(&router, &p.allowed(Mode::Commit).await).await;
    assert_eq!(s, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&b));
    assert!(String::from_utf8_lossy(&b).contains("handover-frozen"));
    assert_eq!(read_head(&p.w.db.app, &id).await.unwrap().pos, head);

    // HO-4
    let (ck, out) = step(&p.w.db, &a_socket, &publisher, d).await;
    assert_eq!((ck.size, out.independent), (frozen.k, 1), "{out:?}");
    let (status, package, _) = start(&p, &router, &package_body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&package)
    );

    let (wb, signer_b) = super::super::World::open_install("w5-ho-b", b_token).await;
    super::super::schedule(&signer_b);
    let b_socket = signer_socket("w5-ho-b");
    let tenant_b = access_store::tenancy::create_tenant(&wb.db.app, "pool-default")
        .await
        .unwrap();

    // HO-5
    let received = handover::receive(&package, (ck.size, ck.root)).unwrap();
    assert_eq!(received.records.len() as u64, frozen.k);
    let mut replay = access_verifier::replay::Replay::new();
    for r in &received.disclosed {
        replay.push(r, true).unwrap();
    }
    let set = replay.set((0, frozen.k - 1), "provider-b", now()).unwrap();
    assert!(set.items.iter().any(|i| i.position == faulty), "{set:?}");
    let b_binding = wb.domains.binding_key(d, false).await.unwrap();
    assert_ne!(b_binding.kid, a_binding.kid);
    let cont = handover::continuation(&received, INCOMING, now());
    let continuation = wb
        .domains
        .sign_statement(d, false, CONTINUATION, cont.to_bytes().unwrap())
        .await
        .unwrap();
    let nw = handover::no_write(d, OUTGOING, (ck.size, ck.root), frozen.at, now());
    let no_write =
        p.w.domains
            .sign_statement(d, false, NO_WRITE, nw.to_bytes().unwrap())
            .await
            .unwrap();

    // OP-158 m.3 (l)
    let mut failing = cont.clone();
    failing.conformance = Digest([7; 32]);
    let unconformant = wb
        .domains
        .sign_statement(d, false, CONTINUATION, failing.to_bytes().unwrap())
        .await
        .unwrap();
    let refused = hand_over(
        &p,
        &b_binding,
        (ck.size, ck.root),
        false,
        (no_write.clone(), unconformant),
    )
    .await;
    assert!(
        matches!(
            refused,
            Err(access_authority_core::CoreError::Refused(
                "provider-not-conformant"
            ))
        ),
        "{refused:?}"
    );
    assert_eq!(read_head(&p.w.db.app, &id).await.unwrap().pos, head);

    // HO-3, HO-6
    let done = hand_over(
        &p,
        &b_binding,
        (ck.size, ck.root),
        false,
        (no_write, continuation.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        done.decision.outcome,
        access_kernel::combinator::Outcome::Allow,
        "{:?}",
        done.decision
    );
    let h = done.record.unwrap();
    assert_eq!(h, frozen.k + 3);
    let batch: Vec<RecordEnvelope> = read_log(&p.w.db.app, &id, frozen.k, h)
        .await
        .unwrap()
        .iter()
        .map(|r| RecordEnvelope::from_bytes(&r.envelope).unwrap())
        .collect();
    let class = |r: &RecordEnvelope| r.fields["class"].value.clone();
    assert_eq!(batch[0].header.kind, RecordKind::Claim);
    assert_eq!(
        class(&batch[0]),
        suiss_crypto::dcbor::Value::text(NO_WRITE_CLASS)
    );
    assert_eq!(
        class(&batch[1]),
        suiss_crypto::dcbor::Value::text(CONTINUATION_CLASS)
    );
    assert!(handover::moves_binding(&batch[3].to_bytes().unwrap()));
    let steps = p.w.domains.handover_steps(d).await.unwrap();
    assert!(
        steps
            .iter()
            .any(|s| s.step == "committed" && s.h == Some(h))
    );

    // HO-7
    let (ch1, out) = step(&p.w.db, &a_socket, &publisher, d).await;
    assert_eq!(
        (ch1.size, out.independent, out.cosigned),
        (h + 1, 1, 2),
        "{out:?}"
    );
    assert!(independent.cosigned(d.0).unwrap().contains(&(h + 1)));

    // U11
    let (s, b) = evaluate(&router, &p.allowed(Mode::Commit).await).await;
    assert_eq!(s, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&b));
    let tail = read_head(&p.w.db.sequencer, &id).await.unwrap();
    let mut frontier = suiss_ledger::merkle::Frontier::default();
    for leaf in access_store::witness::leaf_hashes(&p.w.db.app, &id, 0, h + 1)
        .await
        .unwrap()
    {
        frontier.push(leaf).unwrap();
    }
    let leaf = [9; 32];
    frontier.push(leaf).unwrap();
    let raw = access_store::authority::commit_batch(
        &p.w.db.sequencer,
        &id,
        access_store::authority::domain_tenant(&p.w.db.app, &id)
            .await
            .unwrap()
            .unwrap(),
        &CommitBatch {
            epoch: tail.epoch,
            after: h,
            records: vec![LogRecord {
                pos: h + 1,
                kind: "claim",
                recorded_at: now(),
                leaf_hash: leaf,
                envelope: vec![0xa1, 1],
            }],
            head: HeadRow {
                pos: h + 1,
                epoch: tail.epoch,
                leaf_hash: leaf,
                recorded_at: now(),
                frontier: frontier.nodes().to_vec(),
            },
            nonces: vec![],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            beside: vec![],
            effects: vec![],
        },
    )
    .await
    .unwrap_err();
    assert!(
        access_store::handover::refused_frozen(&raw)
            || matches!(raw, access_store::StoreError::HeadMoved),
        "{raw:?}"
    );
    assert_eq!(read_head(&p.w.db.app, &id).await.unwrap().pos, h);
    // U11, HO-7
    let (note, excerpt) = forged(&a_socket, d, h + 2).await;
    let fenced = add_checkpoint(
        &target(&independent, INDEPENDENT),
        &d,
        (Some((h + 1, ch1.root)), &[]),
        &note,
        &excerpt,
    )
    .await;
    assert!(
        matches!(fenced, Err(WitnessError::Said(Refused::Fenced, 403))),
        "{fenced:?}"
    );

    // HO-8
    let (records, _, ch1_excerpt) = mirror(&p, &router, mirror_run, frozen.k, h).await;
    let (entry, cosigned) = latest(&target(&independent, INDEPENDENT), &d)
        .await
        .unwrap();
    assert_eq!((entry.size, entry.root), (h + 1, ch1.root));
    let verifiers: Vec<Verifier> = [&independent, &own]
        .iter()
        .map(|w| Verifier::parse(&w.vkey).unwrap())
        .collect();
    let run = access_crypto::random::bytes::<16>().unwrap();
    let t = handover::take_over(
        &received,
        &records,
        (&continuation, &b_binding),
        (&cosigned, &verifiers),
        std::slice::from_ref(&a_binding),
        run,
    )
    .unwrap();
    assert_eq!((t.h, t.at), (h, ch1.root));
    wb.domains
        .adopt(
            *tenant_b.as_bytes(),
            &t,
            (&cosigned, &ch1_excerpt),
            decl,
            &[target(&independent, INDEPENDENT), target(&own, OUTGOING)],
        )
        .await
        .unwrap();
    let b_id = DomainId::from_bytes(d.0);
    assert_eq!(read_head(&wb.db.app, &b_id).await.unwrap().pos, h);
    assert_eq!(
        access_store::witness::witnessed_through(&wb.db.app, &b_id)
            .await
            .unwrap(),
        h + 1
    );
    // G32
    access_authority_core::app::divergence::declare(
        &wb.db.app,
        d,
        &access_authority_core::app::divergence::Declared {
            source: "verifier",
            by: None,
            range: set.range,
            items: u32::try_from(set.items.len()).unwrap(),
            first: set.items[0].position,
            set: &set.to_bytes().unwrap(),
        },
        now(),
    )
    .await
    .unwrap();

    // HO-8
    let m = metadata_of(&wb.domains, d).await;
    assert!(m.binding[&b_binding.kid].superseded.is_none());
    let old = m.binding[&a_binding.kid].superseded.unwrap();
    assert_eq!((old.at, old.cited), (Digest(ch1.root), Digest(ck.root)));

    let b_router = adp(&wb.domains);
    let (s, b) = evaluate(&b_router, &p.allowed(Mode::Commit).await).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    let after = read_head(&wb.db.app, &b_id).await.unwrap().pos;
    assert!(after > h);
    let b_publisher = Publisher {
        targets: vec![target(&independent, INDEPENDENT), target(&own, OUTGOING)],
        sinks: Vec::new(),
    };
    let (next, out) = step(&wb.db, &b_socket, &b_publisher, d).await;
    assert_eq!((next.size, out.independent), (after + 1, 1), "{out:?}");

    // U27
    let refused = operational_key(
        &PureBackend,
        &m,
        &d,
        &old_excerpt,
        KeyUsage::Receipt,
        old_iat,
        None,
    );
    assert_eq!(refused, Err(KeyScopeError::Superseded));
    assert!(
        operational_key(
            &PureBackend,
            &before,
            &d,
            &old_excerpt,
            KeyUsage::Receipt,
            old_iat,
            None
        )
        .is_ok()
    );

    // 5780, L0-SIG-64, L0-SIG-80, PI-15, U27, OP-159 m.17 (a)
    superseded_receipt(
        &p,
        &first.unwrap(),
        &m,
        (&ck, &ch1),
        &independent,
        &target(&independent, INDEPENDENT),
    )
    .await;

    independent.restart().unwrap();
    let (note, excerpt) = forged(&a_socket, d, next.size + 1).await;
    let fenced = add_checkpoint(
        &target(&independent, INDEPENDENT),
        &d,
        (Some((next.size, next.root)), &[]),
        &note,
        &excerpt,
    )
    .await;
    assert!(
        matches!(fenced, Err(WitnessError::Said(Refused::Fenced, 403))),
        "{fenced:?}"
    );
    assert!(board().witnessed(&d) > 0);
    let _ = std::fs::remove_dir_all(&root);
    drop(own);
    tokio::time::sleep(Duration::ZERO).await;
}

// §16.6.1 RB-0…RB-6, U71, CR-45 RA-4, OP-60, T20, OP-158 m.3 (l), m.9
#[tokio::test(flavor = "multi_thread")]
async fn a_binding_re_anchor_double_signs_rotates_the_binding_and_re_signs_no_record() {
    let label = "w5-ra";
    let p = pdp_timed(label, Some(0)).await;
    let socket = signer_socket(label);
    let d = p.domain;
    let id = DomainId::from_bytes(d.0);
    let router = routes(&p, 512);
    for _ in 0..2 {
        let (s, _) = evaluate(&router, &p.allowed(Mode::Commit).await).await;
        assert_eq!(s, StatusCode::OK);
    }
    let gen0 = p.w.domains.binding_key(d, false).await.unwrap();
    let suiss_crypto::cose::PublicKey::Ed25519(key0) = gen0.key else {
        panic!("ed25519 binding");
    };
    let root = std::env::temp_dir().join(format!("w5-ra-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let independent =
        Witness::start(&witness_bin(), &root, ("w5-ra-ind", INDEPENDENT), d.0, key0).unwrap();
    let publisher = Publisher {
        targets: vec![target(&independent, INDEPENDENT)],
        sinks: Vec::new(),
    };

    // RB-0
    let refused = p.w.domains.freeze(d, Role::Reanchor).await;
    assert!(
        matches!(
            refused,
            Err(access_authority_core::CoreError::Refused(
                "provider-not-conformant"
            ))
        ),
        "{refused:?}"
    );
    declare(&socket, d, declared(&[(&independent, INDEPENDENT, true)])).await;
    step(&p.w.db, &socket, &publisher, d).await;
    let before = metadata_of(&p.w.domains, d).await;
    let (old_excerpt, old_iat) = artefact(&socket, d).await;
    let (s, _) = evaluate(&router, &p.allowed(Mode::Commit).await).await;
    assert_eq!(s, StatusCode::OK);

    // RB-1, RB-3
    let frozen = p.w.domains.freeze(d, Role::Reanchor).await.unwrap();
    let (ck, out) = step(&p.w.db, &socket, &publisher, d).await;
    assert_eq!((ck.size, out.independent), (frozen.k, 1), "{out:?}");
    let log_before = read_log(&p.w.db.app, &id, 0, frozen.k - 1).await.unwrap();

    // RB-2
    let next = p.w.domains.binding_key(d, true).await.unwrap();
    assert_ne!(next.kid, gen0.kid);
    assert!(
        p.w.keys
            .signer(&access_authority_signer::adapters::binding_label_at(&d, 1))
            .is_ok()
    );

    // RB-4
    let cited = (ck.size, ck.root);
    let nw = handover::no_write(d, OUTGOING, cited, frozen.at, now());
    let no_write =
        p.w.domains
            .sign_statement(d, false, NO_WRITE, nw.to_bytes().unwrap())
            .await
            .unwrap();
    let cont = access_authority_signer::handover::Continuation {
        domain: d,
        provider: String::from(OUTGOING),
        from: cited,
        conformance: handover::conformance_digest(),
        at: now(),
    };
    let continuation =
        p.w.domains
            .sign_statement(d, true, CONTINUATION, cont.to_bytes().unwrap())
            .await
            .unwrap();
    let h = hand_over(&p, &next, cited, true, (no_write, continuation))
        .await
        .unwrap()
        .record
        .unwrap();
    let (forged_note, forged_excerpt) = forged(&socket, d, h + 2).await;

    // RB-5
    let (ch1, out) = step(&p.w.db, &socket, &publisher, d).await;
    assert_eq!((ch1.size, out.independent), (h + 1, 1), "{out:?}");

    // RB-6
    let run = frozen.run;
    assert_eq!(p.w.domains.thaw_reanchor(d, run).await.unwrap(), h + 1);
    let m = metadata_of(&p.w.domains, d).await;
    assert!(m.binding[&next.kid].superseded.is_none());
    let old = m.binding[&gen0.kid].superseded.unwrap();
    assert_eq!((old.at, old.cited), (Digest(ch1.root), Digest(ck.root)));
    assert_eq!(
        m.declared.ceremony_transcript,
        Some(transcript(&d, (ck.size, ck.root), (ch1.size, ch1.root)))
    );

    // CR-45 RA-4
    assert_eq!(
        read_log(&p.w.db.app, &id, 0, frozen.k - 1).await.unwrap(),
        log_before
    );
    let (s, b) = evaluate(&router, &p.allowed(Mode::Commit).await).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    let (later, out) = step(&p.w.db, &socket, &publisher, d).await;
    assert!(later.size > h + 1);
    assert_eq!(out.independent, 1, "{out:?}");

    // U71
    let fenced = add_checkpoint(
        &target(&independent, INDEPENDENT),
        &d,
        (Some((later.size, later.root)), &[]),
        &forged_note,
        &forged_excerpt,
    )
    .await;
    assert!(
        matches!(fenced, Err(WitnessError::Said(Refused::Fenced, 403))),
        "{fenced:?}"
    );
    assert!(
        operational_key(
            &PureBackend,
            &before,
            &d,
            &old_excerpt,
            KeyUsage::Receipt,
            old_iat,
            None
        )
        .is_ok()
    );
    // OP-159 m.3 (i), OP-158 m.16 (h)
    assert!(m.binding.values().any(|b| b.superseded.is_some_and(
        |s| s.cause == Some(access_kernel::verify::key_scope::SupersededCause::ReAnchor)
    )));
    assert!(
        operational_key(
            &PureBackend,
            &m,
            &d,
            &old_excerpt,
            KeyUsage::Receipt,
            old_iat,
            None
        )
        .is_ok()
    );
    assert_eq!(
        operational_key(
            &PureBackend,
            &m,
            &d,
            &old_excerpt,
            KeyUsage::Receipt,
            m.issued_at + 1,
            None
        ),
        Err(KeyScopeError::Superseded)
    );
    let (new_excerpt, new_iat) = artefact(&socket, d).await;
    assert!(
        operational_key(
            &PureBackend,
            &m,
            &d,
            &new_excerpt,
            KeyUsage::Receipt,
            new_iat,
            None
        )
        .is_ok()
    );
    let _ = std::fs::remove_dir_all(&root);
}
