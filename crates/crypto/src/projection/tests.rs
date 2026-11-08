use access_kernel::intent::{ContextRefs, ParamValue};
use access_kernel::json::{self, b64url_decode};
use access_kernel::model::{
    ActionSet, AuthoritySet, Binding, Bound, Consumption, Independence, ProofKind, RequirementTerm,
    ResourceRef, ResourceSelector, Structural, SubjectSelector, Window,
};
use access_kernel::pap::{Holder, holder_digest};
use access_kernel::validity::{ProfileVariant, Revalidation};
use access_kernel::verify::cose::{Algorithm, KeySet};
use access_kernel::verify::projection::{
    AccessTokenRules, Kind, ProjectionError as VerifyError, verify_access_token, verify_pap_sd_jwt,
};
use access_kernel::verify::sd_jwt::Rules;
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::SoftSigner;

use super::*;
use crate::sd_jwt::{KeyBinding, present};

const HOUR: u64 = 3_600_000;
const IAT: u64 = 10 * HOUR + 1234;
const NOW: u64 = 10 * HOUR + 5000;
const RS: &str = "https://rs.example";
const AS: &str = "https://as.example";

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

const ACTOR: Id = Id([0xa1; 16]);
const PRINCIPAL: Id = Id([0xa2; 16]);
const RECIPIENT: Id = Id([0xa3; 16]);

fn parties() -> BTreeMap<Id, PartyPseudonym> {
    BTreeMap::from([
        (ACTOR, PartyPseudonym::new("pw-actor").unwrap()),
        (PRINCIPAL, PartyPseudonym::new("pw-principal").unwrap()),
        (RECIPIENT, PartyPseudonym::new("pw-recipient").unwrap()),
    ])
}

fn action(name: &str) -> ActionRef {
    ActionRef {
        namespace: String::from("shop.pay"),
        name: String::from(name),
        major: 1,
        schema: d(9),
    }
}

fn bounds(prefix: bool) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::from([action("refund"), action("capture")]),
            prefix: if prefix {
                BTreeSet::from([(String::from("shop"), d(20))])
            } else {
                BTreeSet::new()
            },
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from("shop"),
            prefix: vec![String::from("orders")],
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::from([
            (
                String::from("amount"),
                Bound::Range {
                    min: Some(-5),
                    max: Some(100),
                    unit: String::from("eur"),
                },
            ),
            (
                String::from("payee"),
                Bound::Subject(SubjectSelector::Party(RECIPIENT)),
            ),
        ]),
        recipient: Some(SubjectSelector::Party(RECIPIENT)),
        purpose: None,
    }
}

fn term() -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Authentication,
        class: String::from("phishing_resistant"),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: Some(300_000),
        independence: Independence::None,
        consumption: Consumption::SingleUse,
        source: Some(SubjectSelector::Party(PRINCIPAL)),
        assurance: BTreeMap::new(),
    }
}

fn holder(key: &dyn Signer) -> Holder {
    Holder {
        instance: Id([6; 16]),
        key: key.public_key(),
    }
}

fn contract(holder: &Holder, prefix: bool) -> ValidityContract {
    ValidityContract {
        issuing_exercise: d(3),
        basis_ref: vec![9, 9],
        holder: holder_digest(holder).unwrap(),
        audience: BTreeSet::from([String::from(RS), String::from("pep:shop")]),
        bounds: bounds(prefix),
        class: ProfileVariant::BoundedStaleness.class(),
        variant: ProfileVariant::BoundedStaleness,
        profile_version: 1,
        params: BTreeMap::new(),
        horizon: 11 * HOUR + 999,
        max_staleness_ms: Some(60_000),
        freshness_sources: BTreeSet::new(),
        revalidation: Revalidation::default(),
        offline_slice: BTreeSet::new(),
        local_requirements: BTreeSet::from([term()]),
        verifier_profile_ref: d(7),
        clock_source: String::from("trusted"),
        clock_skew_ms: 60_000,
        must_understand: BTreeSet::new(),
        status: None,
    }
}

fn pap(holder_key: &dyn Signer, capacity: Capacity) -> Pap {
    let h = holder(holder_key);
    Pap {
        domain: d(1),
        projection_exercise: d(3),
        validity: contract(&h, true),
        holder: h,
        capacity,
        bounds: bounds(true),
        local_requirements: BTreeSet::from([term()]),
        lineage_commitment: d(4),
        iat: IAT,
    }
}

fn keys(signer: &dyn Signer) -> KeySet {
    let key = signer.public_key();
    let mut set = KeySet::default();
    set.insert(thumbprint(&key), key).unwrap();
    set.allowed.extend([Algorithm::Ed25519, Algorithm::Es256]);
    set
}

fn signers() -> [SoftSigner; 2] {
    [
        SoftSigner::generate_p256().unwrap().0,
        SoftSigner::generate_ed25519().unwrap().0,
    ]
}

fn payload_of(jwt: &str) -> String {
    let p = jwt.split('.').nth(1).unwrap();
    String::from_utf8(b64url_decode(p).unwrap()).unwrap()
}

// MD-10
fn assert_no_party_ids(payload: &str) {
    for id in [ACTOR, PRINCIPAL, RECIPIENT] {
        assert!(!payload.contains(&b64url_encode(&id.0)), "{payload}");
    }
}

// OP-143 m.6 (a), L0-SIG-50…52
#[test]
fn pap_sd_jwt_verifies_in_the_kernel() {
    for domain_key in signers() {
        for holder_key in signers() {
            let pap = pap(&holder_key, Capacity::For(PRINCIPAL));
            let issued = pap_sd_jwt(&domain_key, &pap, &parties()).unwrap();
            assert_eq!(issued.disclosures.len(), 0);
            let kb = KeyBinding {
                signer: &holder_key,
                audience: "pep:shop",
                nonce: "n-1",
                iat: NOW,
            };
            let presentation = present(&issued, &BTreeSet::new(), Some(&kb)).unwrap();
            let rules = Rules {
                typ: PAP_TYP,
                audience: "pep:shop",
                nonce: "n-1",
                now: NOW,
                skew_ms: 60_000,
            };
            let v = verify_pap_sd_jwt(
                &PureBackend,
                &presentation,
                &keys(&domain_key),
                &rules,
                &d(1),
            )
            .unwrap();
            let c = &v.claims;
            assert_eq!(
                c.get("iss").and_then(Json::as_str),
                Some(digest_text(&d(1)).as_str())
            );
            assert_eq!(c.get("iat").and_then(Json::as_int), Some(36_001));
            assert_eq!(c.get("exp").and_then(Json::as_int), Some(39_600));
            assert_eq!(
                c.get("capacity")
                    .and_then(|x| x.get("for"))
                    .and_then(Json::as_str),
                Some("pw-principal")
            );
            assert_eq!(
                c.get("bounds")
                    .and_then(|b| b.get("recipient"))
                    .and_then(|r| r.get("party"))
                    .and_then(Json::as_str),
                Some("pw-recipient")
            );
            assert_eq!(
                c.get("lineage_commitment").and_then(Json::as_str),
                Some(digest_text(&d(4)).as_str())
            );
            assert_no_party_ids(&payload_of(&issued.jwt));
            let unbound = present(&issued, &BTreeSet::new(), None).unwrap();
            assert_eq!(
                verify_pap_sd_jwt(&PureBackend, &unbound, &keys(&domain_key), &rules, &d(1))
                    .map(|_| ()),
                Err(VerifyError::SdJwt(
                    access_kernel::verify::sd_jwt::SdJwtError::KeyBinding
                ))
            );
            assert_eq!(
                verify_pap_sd_jwt(
                    &PureBackend,
                    &presentation,
                    &keys(&domain_key),
                    &rules,
                    &d(2)
                )
                .map(|_| ()),
                Err(VerifyError::Domain)
            );
        }
    }
}

// MD-10, INV-38, L0-ENC-21
#[test]
fn pap_claims_map_the_pap() {
    let [p256, _] = signers();
    let pap = pap(&p256, Capacity::Own);
    let claims = Json::Object(pap_claims(&pap, &parties()).unwrap());
    let text = output::to_string(&claims);
    assert_no_party_ids(&text);
    assert_eq!(claims.get("capacity").and_then(Json::as_str), Some("own"));
    assert_eq!(
        claims
            .get("cnf")
            .and_then(|c| c.get("jwk"))
            .and_then(|j| j.get("kty"))
            .and_then(Json::as_str),
        Some("EC")
    );
    assert_eq!(
        claims
            .get("holder")
            .and_then(|h| h.get("instance"))
            .and_then(Json::as_str),
        Some(b64url_encode(&[6; 16]).as_str())
    );
    assert!(text.contains(&digest_text(&d(9))));
    assert!(text.contains(r#""source":{"party":"pw-principal"}"#));
    assert!(text.contains(r#""payee":{"subject":{"party":"pw-recipient"}}"#));
    assert_eq!(
        json::parse(text.as_bytes(), 1 << 16).unwrap(),
        claims,
        "the Kernel reads back what is written"
    );
}

// MD-10
#[test]
fn a_party_without_pseudonym_is_refused() {
    let [p256, _] = signers();
    let mut few = parties();
    few.remove(&RECIPIENT);
    assert_eq!(
        pap_sd_jwt(&p256, &pap(&p256, Capacity::Own), &few).map(|_| ()),
        Err(ProjectionError::Pseudonym)
    );
    let mut late = pap(&p256, Capacity::Own);
    late.iat = late.validity.horizon + 1;
    assert_eq!(
        pap_sd_jwt(&p256, &late, &parties()).map(|_| ()),
        Err(ProjectionError::Time)
    );
    assert_eq!(PartyPseudonym::new(""), Err(ProjectionError::Pseudonym));
    assert_eq!(PartyPseudonym::new("a b"), Err(ProjectionError::Pseudonym));
    assert!(PartyPseudonym::new(&"x".repeat(MAX_PSEUDONYM + 1)).is_err());
}

fn intent() -> IntentEnvelope {
    IntentEnvelope {
        action: action("refund"),
        resources: vec![ResourceRef {
            namespace: String::from("shop"),
            path: vec![String::from("orders"), String::from("o1")],
            incarnation: 0,
        }],
        params: BTreeMap::from([
            (
                String::from("amount"),
                ParamValue::Amount {
                    value: 40,
                    unit: String::from("eur"),
                },
            ),
            (String::from("payee"), ParamValue::Subject(RECIPIENT)),
        ]),
        opaque: BTreeMap::from([(String::from("note"), d(11))]),
        recipient: Some(RECIPIENT),
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 10 * HOUR,
            until: 11 * HOUR,
        },
    }
}

struct Fixture {
    holder: Holder,
    validity: ValidityContract,
    intent: IntentEnvelope,
}

fn fixture(prefix: bool) -> Fixture {
    let [p256, _] = signers();
    let holder = holder(&p256);
    Fixture {
        validity: contract(&holder, prefix),
        holder,
        intent: intent(),
    }
}

fn projection<'a>(f: &'a Fixture, authority: Authority<'a>) -> AccessTokenProjection<'a> {
    AccessTokenProjection {
        issuer: AS,
        domain: &DOMAIN,
        projection_exercise: &EXERCISE,
        actor_party: &ACTOR,
        capacity: Capacity::For(PRINCIPAL),
        validity: &f.validity,
        authority,
        audience: RS,
        client_id: "client-1",
        confirmation: Confirmation::Jkt(thumbprint(&f.holder.key)),
        iat: IAT,
    }
}

const DOMAIN: Digest = Digest([1; 32]);
const EXERCISE: Digest = Digest([3; 32]);

fn verify_token(
    token: &str,
    signer: &dyn Signer,
    confirmation: &Confirmation,
) -> Result<access_kernel::verify::projection::AccessToken, VerifyError> {
    verify_access_token(
        &PureBackend,
        token,
        &keys(signer),
        &AccessTokenRules {
            issuer: AS,
            audience: RS,
            domain: &DOMAIN,
            confirmation,
            now: NOW,
            skew_ms: 60_000,
        },
    )
}

// §9.9.1, §9.9.4, §9.13.5, RFC 9068
#[test]
fn access_tokens_verify_in_the_kernel() {
    let f = fixture(false);
    for signer in signers() {
        let p = projection(&f, Authority::Intent(&f.intent));
        let token = access_token(&signer, &p, &parties()).unwrap();
        let t = verify_token(&token, &signer, &p.confirmation).unwrap();
        assert_eq!(t.kind, Kind::Intent);
        let c = &t.claims;
        assert_eq!(c.get("sub").and_then(Json::as_str), Some("pw-principal"));
        assert_eq!(
            c.get("act")
                .and_then(|a| a.get("sub"))
                .and_then(Json::as_str),
            Some("pw-actor")
        );
        assert_eq!(
            c.get("jti").and_then(Json::as_str),
            Some(digest_text(&EXERCISE).as_str())
        );
        let Some(Json::Array(details)) = c.get("authorization_details") else {
            panic!("no details");
        };
        let [detail] = details.as_slice() else {
            panic!("one detail");
        };
        assert_eq!(
            detail.get("type").and_then(Json::as_str),
            Some("shop.pay:refund:1")
        );
        assert_eq!(
            detail.get("intent").and_then(Json::as_str),
            Some(digest_text(&intent_digest(&f.intent).unwrap()).as_str())
        );
        assert_eq!(
            detail.get("recipient").and_then(Json::as_str),
            Some("pw-recipient")
        );
        assert_no_party_ids(&payload_of(&token));
        let other = Confirmation::Jkt([0; 32]);
        assert_eq!(
            verify_token(&token, &signer, &other).map(|_| ()),
            Err(VerifyError::Confirmation)
        );

        let mut own = projection(&f, Authority::Bounds);
        own.capacity = Capacity::Own;
        own.confirmation = Confirmation::X5tS256([8; 32]);
        let token = access_token(&signer, &own, &parties()).unwrap();
        let t = verify_token(&token, &signer, &own.confirmation).unwrap();
        assert_eq!(t.kind, Kind::Bounds);
        assert_eq!(t.claims.get("sub").and_then(Json::as_str), Some("pw-actor"));
        assert!(t.claims.get("act").is_none());
        let Some(Json::Array(details)) = t.claims.get("authorization_details") else {
            panic!("no details");
        };
        assert_eq!(details.len(), 2);
        assert_no_party_ids(&payload_of(&token));
    }
}

// §9.9.3 rule 1, §9.13.5
#[test]
fn access_token_inputs_are_checked() {
    let f = fixture(false);
    let [p256, _] = signers();
    let mut p = projection(&f, Authority::Bounds);
    p.audience = "https://other.example";
    assert_eq!(
        access_token(&p256, &p, &parties()),
        Err(ProjectionError::Audience)
    );
    p.audience = "";
    assert_eq!(
        access_token(&p256, &p, &parties()),
        Err(ProjectionError::Audience)
    );
    let mut p = projection(&f, Authority::Bounds);
    p.client_id = "";
    assert_eq!(
        access_token(&p256, &p, &parties()),
        Err(ProjectionError::Member)
    );
    let mut p = projection(&f, Authority::Bounds);
    p.iat = f.validity.horizon + 1;
    assert_eq!(
        access_token(&p256, &p, &parties()),
        Err(ProjectionError::Time)
    );
    let prefixed = fixture(true);
    assert_eq!(
        access_token(&p256, &projection(&prefixed, Authority::Bounds), &parties()),
        Err(ProjectionError::Authority)
    );
    let mut few = parties();
    few.remove(&PRINCIPAL);
    assert_eq!(
        access_token(&p256, &projection(&f, Authority::Bounds), &few),
        Err(ProjectionError::Pseudonym)
    );
}

// L0-ENC-21, RFC 7493
#[test]
fn cbor_maps_to_i_json() {
    assert_eq!(
        from_cbor(&d(1).to_value()),
        Ok(Json::Str(digest_text(&d(1))))
    );
    assert_eq!(
        from_cbor(&Value::Unsigned(1 << 53)),
        Err(JsonOutError::Range)
    );
    assert_eq!(
        from_cbor(&Value::Unsigned((1 << 53) - 1)),
        Ok(Json::Int((1 << 53) - 1))
    );
    assert_eq!(
        from_cbor(&Value::Negative((1 << 53) - 2)),
        Ok(Json::Int(1 - (1 << 53)))
    );
    assert_eq!(
        from_cbor(&Value::Negative((1 << 53) - 1)),
        Err(JsonOutError::Range)
    );
    assert_eq!(
        from_cbor(&Value::Tag(1, Box::new(Value::Unsigned(1)))),
        Err(JsonOutError::Shape)
    );
    assert_eq!(
        from_cbor(&Value::Map(vec![(Value::Unsigned(1), Value::Bool(true))])),
        Err(JsonOutError::Shape)
    );
    let s = Json::Object(vec![(
        String::from("k\n\"\\"),
        Json::Array(vec![Json::Str(String::from("\u{0}é\u{1f}")), Json::Null]),
    )]);
    assert_eq!(
        json::parse(output::to_string(&s).as_bytes(), 1024).unwrap(),
        s
    );
}

// TNI-13, MD-9, TN-70
#[test]
fn support_names_the_subject_and_the_operator() {
    let f = fixture(false);
    for signer in signers() {
        let support = projection(&f, Authority::Bounds);
        assert_eq!(support.capacity, Capacity::For(PRINCIPAL));
        let token = access_token(&signer, &support, &parties()).unwrap();
        let header = token.split('.').next().unwrap();
        let header = String::from_utf8(b64url_decode(header).unwrap()).unwrap();
        assert!(
            header.contains(&format!(r#""typ":"{ACCESS_TOKEN_TYP}""#)),
            "{header}"
        );
        let c = verify_token(&token, &signer, &support.confirmation)
            .unwrap()
            .claims;
        assert_eq!(c.get("sub").and_then(Json::as_str), Some("pw-principal"));
        let act = c.get("act").unwrap();
        assert_eq!(act.get("sub").and_then(Json::as_str), Some("pw-actor"));
        assert_eq!(act.get("iss").and_then(Json::as_str), Some(AS));

        let mut own = projection(&f, Authority::Bounds);
        own.capacity = Capacity::Own;
        let token = access_token(&signer, &own, &parties()).unwrap();
        let c = verify_token(&token, &signer, &own.confirmation)
            .unwrap()
            .claims;
        assert_eq!(c.get("sub").and_then(Json::as_str), Some("pw-actor"));
        assert!(c.get("act").is_none());
    }
}
