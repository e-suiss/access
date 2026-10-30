use alloc::string::String;
use alloc::{format, vec};

use ed25519_dalek::Signer as _;

use super::*;
use crate::sig::PureBackend;

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn line(name: &str, id: u32, sig: &[u8]) -> String {
    let mut raw = id.to_be_bytes().to_vec();
    raw.extend_from_slice(sig);
    format!("\u{2014} {name} {}\n", base64_encode(&raw))
}

fn signed(body: &str, k: &ed25519_dalek::SigningKey, v: &Verifier) -> String {
    line(v.name(), v.id(), &k.sign(body.as_bytes()).to_bytes())
}

fn cosigned(body: &str, ts: u64, k: &ed25519_dalek::SigningKey, v: &Verifier) -> String {
    let mut sig = ts.to_be_bytes().to_vec();
    sig.extend_from_slice(&k.sign(&cosigned_message(ts, body)).to_bytes());
    line(v.name(), v.id(), &sig)
}

fn checkpoint() -> Checkpoint {
    Checkpoint {
        origin: String::from("example.com/log"),
        size: 20_852_163,
        root: [7; 32],
        extensions: vec![String::from("ext-line")],
    }
}

// OP-140 m.2: the example from C2SP signed-note verifies with its key
#[test]
fn c2sp_signed_note_example_verifies() {
    let v =
        Verifier::parse("example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k")
            .unwrap();
    let note = "This is an example message.\n\n\u{2014} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";
    let (n, ok) = verify_note(&PureBackend, note, core::slice::from_ref(&v)).unwrap();
    assert_eq!(n.body, "This is an example message.\n");
    assert_eq!(ok.len(), 1);
    assert_eq!(
        v.to_vkey(),
        "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
    );
    let tampered = note.replace("example message", "exampel message");
    assert!(matches!(
        verify_note(&PureBackend, &tampered, &[v]),
        Err(NoteError::Signature(_))
    ));
}

// C2SP tlog-cosignature: the signed message is the literal lines of the specification example
#[test]
fn cosignature_message_matches_the_specification() {
    let body =
        "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
    assert_eq!(
        cosigned_message(1_679_315_147, body),
        b"cosignature/v1\ntime 1679315147\nexample.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
    );
    let cp = Checkpoint::parse(body).unwrap();
    assert_eq!(cp.size, 20_852_163);
    assert_eq!(cp.to_body().unwrap(), body);
}

// OP-86, OP-140 m.2: a checkpoint signed by its log and cosigned by a witness
#[test]
fn signed_and_cosigned_checkpoint_verifies() {
    let (lk, wk) = (key(1), key(2));
    let log = Verifier::ed25519("example.com/log", lk.verifying_key().to_bytes()).unwrap();
    let witness = Verifier::cosigner("witness.example/w1", wk.verifying_key().to_bytes()).unwrap();
    let body = checkpoint().to_body().unwrap();
    let text = format!(
        "{body}\n{}{}",
        signed(&body, &lk, &log),
        cosigned(&body, 1_700_000_000, &wk, &witness)
    );
    let (cp, ok) = verify_checkpoint(
        &PureBackend,
        &text,
        "example.com/log",
        &log,
        core::slice::from_ref(&witness),
    )
    .unwrap();
    assert_eq!(cp, checkpoint());
    assert_eq!(ok[1].timestamp, Some(1_700_000_000));
    assert_eq!(
        verify_checkpoint(
            &PureBackend,
            &text,
            "other.example/log",
            &log,
            core::slice::from_ref(&witness)
        ),
        Err(NoteError::Checkpoint)
    );
    let only_witness = format!("{body}\n{}", cosigned(&body, 5, &wk, &witness));
    assert_eq!(
        verify_checkpoint(
            &PureBackend,
            &only_witness,
            "example.com/log",
            &log,
            core::slice::from_ref(&witness)
        ),
        Err(NoteError::Unverified)
    );
    let mut moved = 6_u64.to_be_bytes().to_vec();
    moved.extend_from_slice(&wk.sign(&cosigned_message(5, &body)).to_bytes());
    let bad_time = format!(
        "{body}\n{}{}",
        signed(&body, &lk, &log),
        line(witness.name(), witness.id(), &moved)
    );
    assert!(matches!(
        verify_checkpoint(&PureBackend, &bad_time, "example.com/log", &log, &[witness]),
        Err(NoteError::Signature(_))
    ));
}

// C2SP signed-note: unknown keys are ignored, a failing known key rejects, one must verify
#[test]
fn known_and_unknown_keys() {
    let (lk, other) = (key(1), key(3));
    let log = Verifier::ed25519("example.com/log", lk.verifying_key().to_bytes()).unwrap();
    let stranger = Verifier::ed25519("stranger.example", other.verifying_key().to_bytes()).unwrap();
    let body = checkpoint().to_body().unwrap();
    let both = format!(
        "{body}\n{}{}",
        signed(&body, &other, &stranger),
        signed(&body, &lk, &log)
    );
    assert_eq!(
        verify_note(&PureBackend, &both, core::slice::from_ref(&log))
            .unwrap()
            .1
            .len(),
        1
    );
    let forged = format!("{body}\n{}", signed(&body, &other, &log));
    assert!(matches!(
        verify_note(&PureBackend, &forged, core::slice::from_ref(&log)),
        Err(NoteError::Signature(_))
    ));
    let none = format!("{body}\n{}", signed(&body, &other, &stranger));
    assert_eq!(
        verify_note(&PureBackend, &none, core::slice::from_ref(&log)),
        Err(NoteError::Unverified)
    );
    let twice = format!(
        "{body}\n{}{}",
        signed(&body, &lk, &log),
        signed(&body, &lk, &log)
    );
    assert_eq!(parse_note(&twice), Err(NoteError::Duplicate));
}

// C2SP signed-note and tlog-checkpoint syntax
#[test]
fn malformed_notes_and_checkpoints_are_rejected() {
    let lk = key(1);
    let log = Verifier::ed25519("example.com/log", lk.verifying_key().to_bytes()).unwrap();
    let body = checkpoint().to_body().unwrap();
    let sig = signed(&body, &lk, &log);
    for bad in [
        format!("{body}{sig}"),
        format!("{body}\n"),
        format!("{body}\n{}", sig.replace('\u{2014}', "-")),
        format!("{body}\n{}", sig.trim_end()),
        format!("a\tb\n\n{sig}"),
    ] {
        assert!(parse_note(&bad).is_err(), "{bad:?}");
    }
    for body in [
        "example.com/log\n01\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n",
        "example.com/log\n\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n",
        "example.com/log\n1\nBwcH\n",
        "example.com/log\n1\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n\n",
        "bad origin\n1\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n",
        "example.com/log\n1\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
    ] {
        assert!(Checkpoint::parse(body).is_err(), "{body:?}");
    }
    assert!(
        Checkpoint::parse("example.com/log\n0\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n")
            .is_ok()
    );
}

// RFC 4648 §3.5: only canonical base64 is accepted
#[test]
fn base64_is_canonical() {
    for (raw, text) in [
        (&b""[..], ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
    ] {
        assert_eq!(base64_encode(raw), text);
        assert_eq!(base64_decode(text).unwrap(), raw);
    }
    for bad in [
        "Zh==", "Zm9=", "Zg", "Zg=", "Z===", "Zg==Zg==", "Zm9v\n", "Zm-v",
    ] {
        assert_eq!(base64_decode(bad), Err(NoteError::Base64), "{bad}");
    }
}

// C2SP signed-note: verifier keys carry an ID the key must derive
#[test]
fn verifier_keys_are_checked() {
    let k = key(4).verifying_key().to_bytes();
    let v = Verifier::cosigner("w.example", k).unwrap();
    assert_eq!(Verifier::parse(&v.to_vkey()).unwrap(), v);
    let wrong_id = v
        .to_vkey()
        .replacen(&format!("{:08x}", v.id()), "00000000", 1);
    assert_eq!(Verifier::parse(&wrong_id), Err(NoteError::VerifierKey));
    assert_eq!(Verifier::ed25519("has space", k), Err(NoteError::Name));
    assert_eq!(Verifier::ed25519("a+b", k), Err(NoteError::Name));
    assert_eq!(Verifier::ed25519("", k), Err(NoteError::Name));
    let long: String = core::iter::repeat_n('a', MAX_NAME + 1).collect();
    assert_eq!(Verifier::ed25519(&long, k), Err(NoteError::Name));
}

// C2SP signed-note: a bounded number of signatures
#[test]
fn signature_count_is_bounded() {
    let lk = key(1);
    let body = checkpoint().to_body().unwrap();
    let mut text = format!("{body}\n");
    for i in 0..=u32::try_from(MAX_SIGNATURES).unwrap() {
        let v = Verifier::ed25519(&format!("k{i}.example"), lk.verifying_key().to_bytes()).unwrap();
        text.push_str(&signed(&body, &lk, &v));
    }
    assert_eq!(parse_note(&text), Err(NoteError::TooLarge));
}

fn vector_cases() -> Vec<(&'static str, String)> {
    let (lk, wk, xk) = (key(1), key(2), key(3));
    let log = Verifier::ed25519("example.com/log", lk.verifying_key().to_bytes()).unwrap();
    let witness = Verifier::cosigner("witness.example/w1", wk.verifying_key().to_bytes()).unwrap();
    let stranger = Verifier::ed25519("stranger.example", xk.verifying_key().to_bytes()).unwrap();
    let body = checkpoint().to_body().unwrap();
    let plain = Checkpoint {
        extensions: Vec::new(),
        ..checkpoint()
    }
    .to_body()
    .unwrap();
    let sig = signed(&body, &lk, &log);
    let co = cosigned(&body, 1_700_000_000, &wk, &witness);
    vec![
        (
            "log-signed",
            format!("{plain}\n{}", signed(&plain, &lk, &log)),
        ),
        ("log-and-witness", format!("{body}\n{sig}{co}")),
        (
            "unknown-key-ignored",
            format!("{body}\n{}{sig}", signed(&body, &xk, &stranger)),
        ),
        ("witness-only", format!("{body}\n{co}")),
        (
            "body-tampered",
            format!("{}\n{sig}", body.replace("20852163", "20852164")),
        ),
        ("extension-dropped", format!("{plain}\n{sig}")),
        (
            "cosignature-time-moved",
            format!("{body}\n{sig}{}", {
                let mut moved = 1_700_000_001_u64.to_be_bytes().to_vec();
                moved.extend_from_slice(
                    &wk.sign(&cosigned_message(1_700_000_000, &body)).to_bytes(),
                );
                line(witness.name(), witness.id(), &moved)
            }),
        ),
        ("duplicate-signature", format!("{body}\n{sig}{sig}")),
        ("no-separator", format!("{body}{sig}")),
        (
            "hyphen-not-em-dash",
            format!("{body}\n{}", sig.replace('\u{2014}', "-")),
        ),
        ("size-leading-zero", {
            let b = body.replace("\n20852163\n", "\n020852163\n");
            format!("{b}\n{}", signed(&b, &lk, &log))
        }),
        ("base64-non-canonical", {
            let b = body.replace(
                "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
                "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwd=",
            );
            format!("{b}\n{}", signed(&b, &lk, &log))
        }),
        ("control-character", {
            let b = body.replace("ext-line", "ext\tline");
            format!("{b}\n{}", signed(&b, &lk, &log))
        }),
    ]
}

fn case_rules(id: &str) -> &'static [&'static str] {
    match id {
        "log-signed" | "size-leading-zero" | "base64-non-canonical" => &["L2-CKP-1", "L2-CKP-3"],
        "log-and-witness" | "extension-dropped" | "cosignature-time-moved" => {
            &["L2-CKP-3", "L2-CKP-4"]
        }
        "unknown-key-ignored" | "witness-only" | "body-tampered" => &["L2-CKP-3"],
        _ => &["L2-CKP-2"],
    }
}

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// OP-86, OP-140 m.3: checkpoint golden vectors, byte for byte
#[test]
fn checkpoint_vectors_match() {
    extern crate std;
    use core::fmt::Write as _;
    let (lk, wk) = (key(1), key(2));
    let log = Verifier::ed25519("example.com/log", lk.verifying_key().to_bytes()).unwrap();
    let witness = Verifier::cosigner("witness.example/w1", wk.verifying_key().to_bytes()).unwrap();
    let mut json = String::from(
        "{\n \"rule\": \"OP-86\",\n \"track\": \"exchange\",\n \"version\": 1,\n \"operation\": \"note.checkpoint\",\n \"rules\": [\"L2-CKP-1\", \"L2-CKP-2\", \"L2-CKP-3\", \"L2-CKP-4\"],\n",
    );
    let _ = writeln!(json, " \"origin\": \"example.com/log\",");
    let _ = writeln!(json, " \"log\": \"{}\",", log.to_vkey());
    let _ = writeln!(json, " \"cosigners\": [\"{}\"],", witness.to_vkey());
    json.push_str(" \"cases\": [\n");
    let all = vector_cases();
    for (i, (id, text)) in all.iter().enumerate() {
        let expect = match verify_checkpoint(
            &PureBackend,
            text,
            "example.com/log",
            &log,
            core::slice::from_ref(&witness),
        ) {
            Ok((cp, ok)) => {
                let times: Vec<String> = ok
                    .iter()
                    .filter_map(|a| a.timestamp.map(|t| format!("{t}")))
                    .collect();
                format!(
                    "\"size\": {}, \"root\": \"{}\", \"extensions\": {}, \"cosigned\": [{}]",
                    cp.size,
                    base64_encode(&cp.root),
                    cp.extensions.len(),
                    times.join(", ")
                )
            }
            Err(e) => format!("\"error\": \"{}\"", e.code()),
        };
        let sep = if i + 1 == all.len() { "" } else { "," };
        let _ = writeln!(
            json,
            "  {{\"id\": \"{id}\", \"rules\": [{}], \"note\": {}, {expect}}}{sep}",
            case_rules(id)
                .iter()
                .map(|r| format!("\"{r}\""))
                .collect::<Vec<_>>()
                .join(", "),
            json_string(text)
        );
    }
    json.push_str(" ]\n}\n");
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        for path in [
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../conformance/vectors/exchange/1/checkpoint.json"
            ),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/vectors/exchange/1/checkpoint.json"
            ),
        ] {
            std::fs::write(path, &json).unwrap();
        }
    }
    assert_eq!(
        json,
        include_str!("../../vectors/exchange/1/checkpoint.json")
    );
}
