#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    clippy::unnecessary_literal_bound,
    reason = "test code; the scripted ports answer in place"
)]

use std::sync::Mutex;

use access_edge_core::ipc::Summary;
use access_edge_core::saml::Kind;

use super::*;

/// Scripted ports: worker replies in order, and the edge answers by call.
struct Script {
    worker: Mutex<Vec<Reply>>,
    ops: Mutex<Vec<Op>>,
    attests: Mutex<Vec<Attest>>,
    issue: Result<Vec<u8>, String>,
    sp: SpAnswer,
}

impl Ports for Script {
    async fn parse(&self, op: Op, _: Vec<u8>) -> Result<Reply, String> {
        self.ops.lock().unwrap().push(op);
        let mut w = self.worker.lock().unwrap();
        Ok(if w.is_empty() {
            Reply::WorkerFailed
        } else {
            w.remove(0)
        })
    }

    async fn attest(&self, body: Vec<u8>) -> Result<Vec<u8>, String> {
        let a = Attest::decode(&body).unwrap();
        self.attests.lock().unwrap().push(a.clone());
        match a {
            Attest::Sp { .. } => Ok(self.sp.encode()),
            Attest::Issue { .. } => self.issue.clone(),
        }
    }

    fn realm(&self) -> &str {
        "acme"
    }
}

fn facts(signed: Signed) -> Facts {
    Facts {
        kind: Kind::Authn,
        id: String::from("_r1"),
        issue_instant: String::from("2026-11-10T10:00:00Z"),
        destination: None,
        issuer: String::from("https://sp.test"),
        acs_url: None,
        acs_index: None,
        protocol_binding: None,
        force_authn: false,
        is_passive: false,
        nameid_format: None,
        allow_create: None,
        sp_name_qualifier: None,
        requester_ids: vec![],
        proxy_count: None,
        signed,
        name_id: None,
        session_indexes: vec![],
        soap: false,
    }
}

fn ok(output: Vec<u8>) -> Reply {
    Reply::Ok {
        summary: Summary::default(),
        output,
    }
}

fn script(worker: Vec<Reply>, issue: Result<Vec<u8>, String>, certs: Vec<Vec<u8>>) -> Script {
    Script {
        worker: Mutex::new(worker),
        ops: Mutex::new(Vec::new()),
        attests: Mutex::new(Vec::new()),
        issue,
        sp: SpAnswer {
            found: true,
            certs,
            requests_signed: false,
        },
    }
}

fn redirect() -> Forward {
    Forward {
        realm: String::from("acme"),
        handle: [7; 32],
        binding: Binding::Redirect,
        message: Some(binding::encode(&b64::encode(b"deflated"))),
        relay_state: Some(String::from("r")),
        sig_alg: Some(binding::encode(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        )),
        signature: Some(binding::encode(&b64::encode(&[1, 2, 3]))),
    }
}

// OP-155 m.3 (c), IDI-8: the message is read without keys, the pinned certificates come from
// access-server, the redirect signature and the message are verified with them, and only the
// verified facts go back with the handle.
#[tokio::test]
async fn a_redirect_request_is_verified_then_redeemed() {
    let s = script(
        vec![
            ok(facts(Signed::Absent).encode().unwrap()),
            ok(access_edge_core::saml::encode_verified("x").unwrap()),
            ok(facts(Signed::Absent).encode().unwrap()),
        ],
        Ok(access_identity_saml::wire::decided()),
        vec![vec![0x30, 0x00]],
    );
    assert_eq!(handle(&s, &redirect()).await, Done::Done);
    assert_eq!(
        *s.ops.lock().unwrap(),
        [Op::SamlRequest, Op::SamlRedirect, Op::SamlRequest]
    );
    let attests = s.attests.lock().unwrap();
    assert!(matches!(&attests[0], Attest::Sp { entity, .. } if entity == "https://sp.test"));
    assert!(
        matches!(&attests[1], Attest::Issue { handle, redirect_signed: true, facts: Some(_), .. } if *handle == [7; 32])
    );
}

// IDI-7, CVE-2022-39299: a refused message or a refused handle ends with its code; no issue call
// follows a refusal, and a handle the channel refuses yields nothing signed.
#[tokio::test]
async fn refusals_end_the_forward() {
    let s = script(
        vec![Reply::Refused(String::from("xml-doctype"))],
        Ok(access_identity_saml::wire::decided()),
        vec![],
    );
    assert_eq!(
        handle(&s, &redirect()).await,
        Done::Refused(String::from("xml-doctype"))
    );
    assert!(s.attests.lock().unwrap().is_empty());

    let forged = script(
        vec![ok(facts(Signed::Absent).encode().unwrap())],
        Err(String::from("edge-attest")),
        vec![],
    );
    let post = Forward {
        binding: Binding::Post,
        message: Some(b64::encode(b"<samlp:AuthnRequest/>")),
        sig_alg: None,
        signature: None,
        ..redirect()
    };
    assert_eq!(
        handle(&forged, &post).await,
        Done::Refused(String::from("edge-attest"))
    );

    let other = Forward {
        realm: String::from("other"),
        ..redirect()
    };
    assert_eq!(
        handle(&forged, &other).await,
        Done::Refused(String::from("edge-realm"))
    );

    let mut unknown = script(
        vec![ok(facts(Signed::Absent).encode().unwrap())],
        Ok(vec![]),
        vec![],
    );
    unknown.sp.found = false;
    assert_eq!(
        handle(&unknown, &post).await,
        Done::Refused(String::from("saml-unknown-sp"))
    );
    assert_eq!(unknown.attests.lock().unwrap().len(), 1);
}
