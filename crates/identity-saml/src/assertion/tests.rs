#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use aws_lc_rs::rsa::{
    KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey,
};
use aws_lc_rs::signature::{self, KeyPair as _, RsaKeyPair, UnparsedPublicKey};

use super::*;
use crate::dsig::Signature;
use crate::encrypt::XmlEnc;
use crate::sp::b64;
use crate::xml::Node;

struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), SignError> {
        aws_lc_rs::rand::fill(out).map_err(|_| SignError(String::from("rng")))
    }
}

struct TestSigner {
    key: RsaKeyPair,
}

impl TestSigner {
    fn new() -> Self {
        Self {
            key: RsaKeyPair::generate(KeySize::Rsa3072).unwrap(),
        }
    }

    fn verify(&self, signed: &[u8], value: &[u8]) -> bool {
        UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            self.key.public_key().as_ref(),
        )
        .verify(signed, value)
        .is_ok()
    }
}

impl XmlSigner for TestSigner {
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the port is async; this test key signs in place"
    )]
    async fn sign(&self, signed_info: Vec<u8>, alg: SigAlg) -> Result<Signature, SignError> {
        assert_eq!(alg, SigAlg::RsaSha256);
        let mut sig = vec![0; self.key.public_modulus_len()];
        self.key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                &signed_info,
                &mut sig,
            )
            .unwrap();
        Ok(Signature {
            value: sig,
            certificate: vec![0x30, 0x00],
        })
    }
}

struct NoEncrypt;

impl Encrypter for NoEncrypt {
    fn encrypt(&self, _: &El, _: &[u8]) -> Result<El, SignError> {
        Err(SignError(String::from("unused")))
    }
}

fn sp() -> Sp {
    Sp::from_json(&serde_json::json!({
        "entity_id": "https://sp.test",
        "acs": [{ "url": "https://sp.test/acs", "index": 0, "binding": "post", "default": true }],
        "attributes": [
            { "name": "urn:oid:0.9.2342.19200300.100.1.3", "friendly_name": "mail", "source": "email" },
            { "name": "https://aws.amazon.com/SAML/Attributes/Role", "values": ["arn:a,arn:b", "arn:c,arn:d"] },
        ],
    }))
    .unwrap()
}

const NOW: u64 = 1_794_304_800_000;

fn issue() -> Issue {
    Issue {
        idp: String::from("https://idp.test/saml/metadata"),
        acs: String::from("https://sp.test/acs"),
        in_response_to: Some(String::from("_r1")),
        now: NOW,
        auth_time: NOW - 30_000,
        aal: 2,
        name_id: String::from("pairwise-value"),
        format: NameIdFormat::Persistent,
        sp_name_qualifier: Some(String::from("https://sp.test")),
        attributes: vec![
            Released {
                name: String::from("urn:oid:0.9.2342.19200300.100.1.3"),
                name_format: uri::ATTR_URI,
                friendly_name: Some(String::from("mail")),
                values: vec![String::from("a@x.test")],
            },
            Released {
                name: String::from("https://aws.amazon.com/SAML/Attributes/Role"),
                name_format: uri::ATTR_URI,
                friendly_name: None,
                values: vec![String::from("arn:a,arn:b"), String::from("arn:c,arn:d")],
            },
        ],
        idp_initiated: false,
    }
}

fn kids(e: &El) -> Vec<&El> {
    e.children
        .iter()
        .filter_map(|c| match c {
            Node::El(e) => Some(e),
            Node::Text(_) => None,
        })
        .collect()
}

fn text_of(e: &El) -> String {
    e.children
        .iter()
        .filter_map(|c| match c {
            Node::Text(t) => Some(t.as_str()),
            Node::El(_) => None,
        })
        .collect()
}

/// Checks an enveloped signature the way a verifier does: the digest of the element without its
/// signature, then the signature over the canonical `SignedInfo`.
fn verify(signer: &TestSigner, el: &El) {
    let sig_at = el
        .children
        .iter()
        .position(|c| matches!(c, Node::El(e) if e.local == "Signature"))
        .unwrap();
    let Node::El(sig) = &el.children[sig_at] else {
        panic!()
    };
    let mut bare = el.clone();
    bare.children.remove(sig_at);
    let si = kids(sig)[0];
    let reference = kids(si)[2];
    assert_eq!(
        reference.get("URI").unwrap(),
        format!("#{}", el.get("ID").unwrap())
    );
    let digest = b64::decode(&text_of(kids(reference)[2])).unwrap();
    assert_eq!(
        digest,
        crate::alg::DigestAlg::Sha256.digest(bare.canonical().as_bytes())
    );
    let value = b64::decode(&text_of(kids(sig)[1])).unwrap();
    assert!(signer.verify(si.canonical().as_bytes(), &value));
}

// §10.6.1 rules 1-6, 9, Ek B 4764, 4772, 4775, 4777: schema order, audience, bearer
// confirmation without NotBefore, SessionIndex = ID, class from AAL, both signatures.
#[tokio::test]
async fn a_response_follows_the_ten_rules_and_both_signatures_verify() {
    let signer = TestSigner::new();
    let sp = sp();
    let i = issue();
    let a_id = new_id(&OsRandom).unwrap();
    assert!(a_id.starts_with('_') && a_id.len() == 41);
    let mut a = assertion(&sp, &i, &a_id);
    sign(&signer, &mut a, "ID", Some(1), SigAlg::RsaSha256, true)
        .await
        .unwrap();
    let order: Vec<&str> = kids(&a).iter().map(|e| e.local).collect();
    assert_eq!(
        order,
        [
            "Issuer",
            "Signature",
            "Subject",
            "Conditions",
            "AuthnStatement",
            "AttributeStatement"
        ]
    );
    verify(&signer, &a);
    let subject = kids(&a)[2];
    let data = kids(kids(subject)[1])[0];
    assert_eq!(data.get("Recipient"), Some("https://sp.test/acs"));
    assert_eq!(data.get("InResponseTo"), Some("_r1"));
    assert_eq!(data.get("NotBefore"), None);
    assert_eq!(
        data.get("NotOnOrAfter"),
        Some(time::format(NOW + 300_000).as_str())
    );
    let conditions = kids(&a)[3];
    assert_eq!(
        conditions.get("NotBefore"),
        Some(time::format(NOW - 60_000).as_str())
    );
    assert_eq!(text_of(kids(kids(conditions)[0])[0]), "https://sp.test");
    let authn = kids(&a)[4];
    assert_eq!(authn.get("SessionIndex"), Some(a_id.as_str()));
    assert_eq!(
        authn.get("SessionNotOnOrAfter"),
        Some(time::format(NOW - 30_000 + 8 * 3_600_000).as_str())
    );
    assert_eq!(text_of(kids(kids(authn)[0])[0]), uri::AC_MOBILE_2F);
    let attrs = kids(kids(&a)[5]);
    assert_eq!(
        attrs[1].get("Name"),
        Some("https://aws.amazon.com/SAML/Attributes/Role")
    );
    assert_eq!(kids(attrs[1]).len(), 2);
    assert_eq!(attrs[0].get("NameFormat"), Some(uri::ATTR_URI));

    let xml = issue_and(&signer, &sp, &i).await;
    assert!(xml.starts_with("<samlp:Response xmlns:samlp="));
    assert!(xml.contains("Destination=\"https://sp.test/acs\""));
    assert!(xml.contains("InResponseTo=\"_r1\""));
    assert!(!xml.contains("EncryptedAttribute"));
    assert!(!xml.contains("rsa-sha1"));
}

async fn issue_and(signer: &TestSigner, sp: &Sp, i: &Issue) -> String {
    super::issue(sp, i, signer, &OsRandom, &NoEncrypt)
        .await
        .unwrap()
}

// OP-155 m.3 (e): AAL to AuthnContextClassRef.
#[test]
fn the_class_comes_from_the_assurance_vector() {
    let (x, y) = (new_value(&OsRandom).unwrap(), new_value(&OsRandom).unwrap());
    assert_ne!(x, y);
    assert_eq!(x.len(), 43);
    assert_eq!(class_ref(1, Aal3Class::X509), uri::AC_PPT);
    assert_eq!(class_ref(2, Aal3Class::X509), uri::AC_MOBILE_2F);
    assert_eq!(class_ref(3, Aal3Class::X509), uri::AC_X509);
    assert_eq!(class_ref(3, Aal3Class::RefedsMfa), uri::AC_REFEDS_MFA);
}

// IDP-15: an IdP-initiated assertion lives 2 minutes and names no request.
#[test]
fn an_unsolicited_assertion_is_short_and_answers_nothing() {
    let i = Issue {
        in_response_to: None,
        idp_initiated: true,
        ..issue()
    };
    let a = assertion(&sp(), &i, "_a");
    let data = kids(kids(kids(&a)[1])[1])[0];
    assert_eq!(data.get("InResponseTo"), None);
    assert_eq!(
        data.get("NotOnOrAfter"),
        Some(time::format(NOW + 120_000).as_str())
    );
}

// §10.6.1 rule 7, CR-4, Ek B 4765: sign, then encrypt with aes256-gcm and rsa-oaep for the SP's
// key; the SP's private key opens exactly the signed assertion.
#[tokio::test]
async fn an_encrypted_assertion_round_trips_against_the_sp_key() {
    let sp_key = aws_lc_rs::rsa::KeyPair::generate(KeySize::Rsa2048).unwrap();
    let pkcs8 =
        aws_lc_rs::encoding::AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&sp_key).unwrap();
    let rc = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let cert = rcgen::CertificateParams::new(vec![String::from("sp.test")])
        .unwrap()
        .self_signed(&rc)
        .unwrap();
    let signer = TestSigner::new();
    let mut a = assertion(&sp(), &issue(), "_enc1");
    sign(&signer, &mut a, "ID", Some(1), SigAlg::RsaSha256, true)
        .await
        .unwrap();
    let e = XmlEnc(&OsRandom).encrypt(&a, cert.der()).unwrap();
    assert_eq!(e.local, "EncryptedAssertion");
    let data = kids(&e)[0];
    assert_eq!(
        kids(data)[0].get("Algorithm"),
        Some(crate::encrypt::AES256_GCM)
    );
    let key_info = kids(data)[1];
    let ek = kids(key_info)[0];
    assert_eq!(kids(ek)[0].get("Algorithm"), Some(crate::encrypt::RSA_OAEP));
    let wrapped = b64::decode(&text_of(kids(kids(ek)[1])[0])).unwrap();
    let body = b64::decode(&text_of(kids(kids(data)[2])[0])).unwrap();
    let private = PrivateDecryptingKey::from_pkcs8(pkcs8.as_ref()).unwrap();
    let oaep = OaepPrivateDecryptingKey::new(private).unwrap();
    let mut key = vec![0; oaep.min_output_size()];
    let key = oaep
        .decrypt(&OAEP_SHA256_MGF1SHA256, &wrapped, &mut key, None)
        .unwrap()
        .to_vec();
    let opening = aws_lc_rs::aead::LessSafeKey::new(
        aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::AES_256_GCM, &key).unwrap(),
    );
    let (nonce, rest) = body.split_at(12);
    let mut rest = rest.to_vec();
    let plain = opening
        .open_in_place(
            aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce).unwrap(),
            aws_lc_rs::aead::Aad::empty(),
            &mut rest,
        )
        .unwrap();
    assert_eq!(plain, a.canonical().as_bytes());
    verify(&signer, &a);
}
