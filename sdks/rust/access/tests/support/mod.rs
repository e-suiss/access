//! Fixtures: a domain with receipt, token and status-list keys, a PEP and a resource server
//! for a door-opening action, signed receipts, authority tokens, DPoP proofs, JWKS, status
//! lists and introspection answers, plus in-memory ports.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test fixtures shared by several test binaries"
)]

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::json::b64url_encode;
use access_kernel::meta::{ExerciseBasis, exercise_id};
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::receipt::{self, Receipt};
use access_kernel::status::{CWT_CONTENT_TYPE, ListToken};
use access_kernel::verify::cose::{Algorithm, PublicKey, to_be_signed};
use access_kernel::verify::key_scope::{
    BindingKey, BindingScope, DomainMetadata, EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage,
    METADATA_CONTENT_TYPE, OperationalKey, SpecVersions, thumbprint,
};
use access_sdk::authorize::{Action, Actor, Ask, Intent, Nonce, Pep, Resource};
use access_sdk::resource::{
    Config, Introspector, KeySource, Keys, NonceSource, Ports, Profile, Replay, ReplayStore,
    ResourceServer, Revocations, StatusSource,
};
use access_sdk::transport::{Answer, Fault, Response};
use ed25519_dalek::Signer as _;
use suiss_crypto::dcbor::{self, Limits, Value};

pub(crate) const HOUR: u64 = 3_600_000;
pub(crate) const NOW: u64 = 12 * HOUR;
pub(crate) const PEP: &str = "pep.example";
pub(crate) const RS: &str = "https://rs.example";
pub(crate) const ISSUER: &str = "https://as.example";
pub(crate) const LIST_URI: &str = "https://as.example/access/v1/status-lists/1";
pub(crate) const REQUEST_URI: &str = "https://rs.example/doors/1";
pub(crate) const RECORD: u64 = 41;
pub(crate) const BASIS_POS: u64 = 40;

pub(crate) const BINDING_SEED: u8 = 1;
pub(crate) const RECEIPT_SEED: u8 = 2;
pub(crate) const TOKEN_SEED: u8 = 3;
pub(crate) const LIST_SEED: u8 = 4;
pub(crate) const HOLDER_SEED: u8 = 5;
pub(crate) const OTHER_SEED: u8 = 6;

pub(crate) struct Door;
impl Resource for Door {
    const NAMESPACE: &'static str = "door";
}

pub(crate) struct Open;
impl Action for Open {
    const NAMESPACE: &'static str = "door";
    const NAME: &'static str = "open";
}

pub(crate) fn d(n: u8) -> Digest {
    Digest([n; 32])
}

pub(crate) fn domain() -> Digest {
    d(1)
}

pub(crate) fn ed(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

pub(crate) fn ed_pub(seed: u8) -> PublicKey {
    PublicKey::Ed25519(ed(seed).verifying_key().to_bytes())
}

pub(crate) fn kid(seed: u8) -> [u8; 32] {
    thumbprint(&ed_pub(seed))
}

pub(crate) fn sign1(seed: u8, content_type: &str, payload: &[u8]) -> Vec<u8> {
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::int(Algorithm::Ed25519.cose())),
            (Value::Unsigned(3), Value::text(content_type)),
            (Value::Unsigned(4), Value::Bytes(kid(seed).to_vec())),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let sig = ed(seed)
        .sign(&to_be_signed(&prot, payload).unwrap())
        .to_bytes()
        .to_vec();
    let body = Value::Array(vec![
        Value::Bytes(prot),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

pub(crate) fn op_key(usage: KeyUsage) -> OperationalKey {
    let seed = match usage {
        KeyUsage::Receipt => RECEIPT_SEED,
        KeyUsage::Token => TOKEN_SEED,
        _ => LIST_SEED,
    };
    let key = ed_pub(seed);
    OperationalKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        valid_from: 11 * HOUR + HOUR / 2,
        valid_until: 12 * HOUR + HOUR / 2,
        usage: BTreeSet::from([usage]),
    }
}

pub(crate) fn metadata() -> DomainMetadata {
    let key = ed_pub(BINDING_SEED);
    let b = BindingKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        scope: BindingScope::Domain,
        superseded: None,
    };
    DomainMetadata {
        domain: domain(),
        genesis: d(9),
        issued_at: 10 * HOUR,
        binding: BTreeMap::from([(b.kid, b)]),
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_window_max_ms: HOUR,
        operational_keys: vec![
            op_key(KeyUsage::Receipt),
            op_key(KeyUsage::Token),
            op_key(KeyUsage::StatusList),
        ],
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
    }
}

/// The metadata as the domain serves it, signed by the binding key `seed`.
pub(crate) fn signed_metadata_by(seed: u8, m: &DomainMetadata) -> Vec<u8> {
    sign1(seed, METADATA_CONTENT_TYPE, &m.to_bytes().unwrap())
}

pub(crate) fn signed_metadata() -> Vec<u8> {
    signed_metadata_by(BINDING_SEED, &metadata())
}

pub(crate) fn excerpt(usage: KeyUsage) -> Vec<u8> {
    let e = KeyExcerpt {
        domain: domain(),
        key: op_key(usage),
    };
    sign1(BINDING_SEED, EXCERPT_CONTENT_TYPE, &e.to_bytes().unwrap())
}

pub(crate) fn action() -> ActionRef {
    ActionRef {
        namespace: "door".to_owned(),
        name: "open".to_owned(),
        major: 1,
        schema: d(9),
    }
}

pub(crate) fn envelope() -> IntentEnvelope {
    IntentEnvelope {
        action: action(),
        resources: vec![ResourceRef {
            namespace: "door".to_owned(),
            path: vec!["1".to_owned()],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: 2 * NOW,
        },
    }
}

pub(crate) fn intent() -> Intent<Door, Open> {
    Intent::of(envelope()).unwrap()
}

pub(crate) fn intent_hash() -> Digest {
    intent_digest(&envelope()).unwrap()
}

pub(crate) fn nonce() -> Nonce {
    Nonce::new(vec![0xab; 16]).unwrap()
}

pub(crate) fn basis() -> ExerciseBasis {
    ExerciseBasis::Public(Id([7; 16]))
}

pub(crate) fn pep() -> Pep {
    Pep {
        audience: PEP.to_owned(),
        domain: domain(),
        metadata: metadata(),
    }
}

pub(crate) fn text_digest(d: &Digest) -> String {
    format!("sha-256:{}", b64url_encode(&d.0))
}

// ---------------------------------------------------------------- receipts

pub(crate) fn receipt_for(nonce: &[u8], audience: &str, intent: &Digest) -> Receipt {
    Receipt {
        domain: domain(),
        exercise: exercise_id(&domain(), nonce).unwrap(),
        record: RECORD,
        intent: *intent,
        instance: None,
        ais: None,
        capacity: Capacity::Own,
        basis: basis(),
        audience: audience.to_owned(),
        iat: NOW - 1_000,
        drawn: false,
        agency: Vec::new(),
    }
}

pub(crate) fn signed_receipt(r: &Receipt) -> (Vec<u8>, Vec<u8>) {
    (
        sign1(RECEIPT_SEED, receipt::CONTENT_TYPE, &r.to_bytes().unwrap()),
        excerpt(KeyUsage::Receipt),
    )
}

pub(crate) fn allow_body(r: &Receipt, extra_context: &str) -> Vec<u8> {
    let (sign1, excerpt) = signed_receipt(r);
    format!(
        r#"{{"decision":true,"context":{{"outcome":"allow","exercise":"{}","receipt":{{"sign1":"{}","excerpt":"{}"}},"versions":{{"core":1,"meta_schema":1}}{}}}}}"#,
        b64url_encode(&r.exercise.0),
        b64url_encode(&sign1),
        b64url_encode(&excerpt),
        extra_context
    )
    .into_bytes()
}

pub(crate) fn ok(body: Vec<u8>) -> Answer {
    Answer::Response(Response::new(200, body))
}

pub(crate) fn status(code: u16) -> Answer {
    Answer::Response(Response::new(code, b"{}".to_vec()))
}

pub(crate) fn ask<'a>(
    intent: &'a Intent<Door, Open>,
    nonce: &'a Nonce,
    actor: &'a Actor,
    basis: &'a ExerciseBasis,
) -> Ask<'a, Door, Open> {
    Ask {
        intent,
        nonce,
        actor,
        basis,
        capacity: Capacity::Own,
        continued: None,
        content_position: None,
    }
}

// ---------------------------------------------------------------- tokens

pub(crate) fn jws(seed: u8, typ: &str, claims: &str) -> String {
    let header = format!(
        r#"{{"alg":"Ed25519","kid":"{}","typ":"{}"}}"#,
        b64url_encode(&kid(seed)),
        typ
    );
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(claims.as_bytes())
    );
    let sig = ed(seed).sign(input.as_bytes()).to_bytes();
    format!("{input}.{}", b64url_encode(&sig))
}

pub(crate) fn exercise() -> Digest {
    d(0x33)
}

pub(crate) fn family() -> [u8; 16] {
    let mut f = [0; 16];
    f.copy_from_slice(&exercise().0[..16]);
    f
}

pub(crate) fn basis_ref(pos: u64) -> String {
    b64url_encode(
        &dcbor::encode(
            &Value::Array(vec![domain().to_value(), Value::Unsigned(pos)]),
            Limits::CEILING,
        )
        .unwrap(),
    )
}

/// What a token says; every field has the AS's default.
#[derive(Clone, Debug)]
pub(crate) struct TokenSpec {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) aud_json: Option<String>,
    pub(crate) iat_s: u64,
    pub(crate) exp_s: u64,
    pub(crate) kind: &'static str,
    pub(crate) action_type: String,
    pub(crate) schema: Digest,
    pub(crate) intent: Digest,
    pub(crate) domain: Digest,
    pub(crate) jkt: [u8; 32],
    pub(crate) act: Option<String>,
    pub(crate) detail_capacity: String,
    pub(crate) status_json: Option<String>,
    pub(crate) contract_status_json: Option<String>,
    pub(crate) family: Option<[u8; 16]>,
    pub(crate) access_contract: Option<Digest>,
    pub(crate) horizon_ms: u64,
    pub(crate) max_staleness_ms: Option<u64>,
    pub(crate) extra: String,
    pub(crate) contract_audience: String,
}

impl TokenSpec {
    pub(crate) fn intent_token() -> Self {
        Self {
            issuer: ISSUER.to_owned(),
            audience: RS.to_owned(),
            aud_json: None,
            iat_s: NOW / 1000 - 60,
            exp_s: NOW / 1000 + 240,
            kind: "intent",
            action_type: "door:open:1".to_owned(),
            schema: d(9),
            intent: intent_hash(),
            domain: domain(),
            jkt: kid(HOLDER_SEED),
            act: None,
            detail_capacity: r#""own""#.to_owned(),
            status_json: Some(format!(
                r#"{{"status_list":{{"idx":0,"uri":"{LIST_URI}"}}}}"#
            )),
            contract_status_json: None,
            family: Some(family()),
            access_contract: Some(d(0x44)),
            horizon_ms: NOW + 240_000,
            max_staleness_ms: None,
            extra: String::new(),
            contract_audience: format!(r#""{RS}""#),
        }
    }

    pub(crate) fn bounds_token() -> Self {
        Self {
            kind: "bounds",
            ..Self::intent_token()
        }
    }

    pub(crate) fn claims(&self) -> String {
        let aud = self
            .aud_json
            .clone()
            .unwrap_or_else(|| format!(r#""{}""#, self.audience));
        let act = self
            .act
            .as_ref()
            .map(|a| format!(r#","act":{a}"#))
            .unwrap_or_default();
        let intent = if self.kind == "intent" {
            format!(r#","intent":"{}""#, text_digest(&self.intent))
        } else {
            String::new()
        };
        let staleness = self
            .max_staleness_ms
            .map(|d| format!(r#","max_staleness_ms":{d}"#))
            .unwrap_or_default();
        let contract_status = self
            .contract_status_json
            .as_ref()
            .map(|s| format!(r#","status":{s}"#))
            .unwrap_or_default();
        let (class, variant) = if self.kind == "intent" {
            ("online", "online-strict")
        } else {
            ("intermittent", "bounded-staleness")
        };
        let validity = format!(
            r#"{{"audience":[{}],"horizon":{},"profile":{{"class":"{class}","variant":"{variant}","version":1}}{staleness}{contract_status}}}"#,
            self.contract_audience, self.horizon_ms
        );
        let status = self
            .status_json
            .as_ref()
            .map(|s| format!(r#","status":{s}"#))
            .unwrap_or_default();
        let family = self
            .family
            .map(|f| format!(r#","family":"{}""#, b64url_encode(&f)))
            .unwrap_or_default();
        let contract = self
            .access_contract
            .as_ref()
            .map(|c| format!(r#","access_contract":"{}""#, text_digest(c)))
            .unwrap_or_default();
        format!(
            r#"{{"iss":"{}","sub":"p-1"{act},"aud":{aud},"exp":{},"iat":{},"jti":"{}","client_id":"c-1","cnf":{{"jkt":"{}"}},"authorization_details":[{{"type":"{}","kind":"{}","schema":"{}","domain":"{}","exercise":"{}","basis_ref":"{}","capacity":{},"validity":{validity}{intent}}}]{family}{contract}{status}{}}}"#,
            self.issuer,
            self.exp_s,
            self.iat_s,
            text_digest(&exercise()),
            b64url_encode(&self.jkt),
            self.action_type,
            self.kind,
            text_digest(&self.schema),
            text_digest(&self.domain),
            text_digest(&exercise()),
            basis_ref(BASIS_POS),
            self.detail_capacity,
            self.extra
        )
    }

    pub(crate) fn signed(&self) -> String {
        jws(TOKEN_SEED, "at+jwt", &self.claims())
    }
}

pub(crate) fn jwks_of(seed: u8) -> Vec<u8> {
    let PublicKey::Ed25519(x) = ed_pub(seed) else {
        panic!("ed25519 key")
    };
    format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","use":"sig","kid":"{}","x":"{}"}}]}}"#,
        b64url_encode(&kid(seed)),
        b64url_encode(&x)
    )
    .into_bytes()
}

pub(crate) fn ath(token: &str) -> String {
    access_kernel::verify::dpop::ath(token)
}

pub(crate) fn proof_with(
    seed: u8,
    token: &str,
    jti: &str,
    method: &str,
    uri: &str,
    nonce: Option<&str>,
) -> String {
    let PublicKey::Ed25519(x) = ed_pub(seed) else {
        panic!("ed25519 key")
    };
    let header = format!(
        r#"{{"alg":"Ed25519","jwk":{{"crv":"Ed25519","kty":"OKP","x":"{}"}},"typ":"dpop+jwt"}}"#,
        b64url_encode(&x)
    );
    let nonce = nonce
        .map(|n| format!(r#","nonce":"{n}""#))
        .unwrap_or_default();
    let payload = format!(
        r#"{{"ath":"{}","htm":"{method}","htu":"{uri}","iat":{},"jti":"{jti}"{nonce}}}"#,
        ath(token),
        NOW / 1000 - 1
    );
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = ed(seed).sign(input.as_bytes()).to_bytes();
    format!("{input}.{}", b64url_encode(&sig))
}

pub(crate) fn proof(token: &str, jti: &str) -> String {
    proof_with(HOLDER_SEED, token, jti, "POST", REQUEST_URI, None)
}

// ---------------------------------------------------------------- status lists

pub(crate) fn zlib(bits: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(bits, 6)
}

pub(crate) fn list_jwt(iat_s: u64, revoked: bool) -> Vec<u8> {
    list_jwt_by(LIST_SEED, iat_s, revoked)
}

pub(crate) fn list_jwt_by(seed: u8, iat_s: u64, revoked: bool) -> Vec<u8> {
    let claims = format!(
        r#"{{"sub":"{LIST_URI}","iat":{iat_s},"exp":{},"ttl":300,"status_list":{{"bits":1,"lst":"{}"}},"as_of":{BASIS_POS}}}"#,
        iat_s + 600,
        b64url_encode(&zlib(&[u8::from(revoked)]))
    );
    jws(seed, "statuslist+jwt", &claims).into_bytes()
}

pub(crate) fn list_cwt(iat_s: u64, revoked: bool) -> Response {
    let token = ListToken {
        uri: LIST_URI.to_owned(),
        iat: iat_s,
        exp: None,
        ttl: Some(300),
        lst: zlib(&[u8::from(revoked)]),
        aggregation_uri: None,
        as_of: BASIS_POS,
    };
    Response {
        status: 200,
        content_type: Some(CWT_CONTENT_TYPE.to_owned()),
        key_excerpt: Some(excerpt(KeyUsage::StatusList)),
        body: sign1(LIST_SEED, CWT_CONTENT_TYPE, &token.to_bytes().unwrap()),
    }
}

// ---------------------------------------------------------------- introspection

pub(crate) fn introspection_body(spec: &TokenSpec, active: bool, as_of: u64) -> Vec<u8> {
    if !active {
        return br#"{"active":false}"#.to_vec();
    }
    let claims = spec.claims();
    let inner = &claims[1..claims.len() - 1];
    format!(r#"{{"active":true,"token_type":"DPoP","as_of":"{as_of}",{inner}}}"#).into_bytes()
}

// ---------------------------------------------------------------- ports

#[derive(Default)]
pub(crate) struct Memory {
    pub(crate) keys: RefCell<Option<Keys>>,
    pub(crate) list: RefCell<Option<Answer>>,
    pub(crate) introspection: RefCell<Option<Answer>>,
    pub(crate) seen: RefCell<BTreeSet<[u8; 32]>>,
    pub(crate) replay_down: Cell<bool>,
    pub(crate) nonce_required: RefCell<Option<String>>,
    pub(crate) ended: RefCell<BTreeSet<[u8; 16]>>,
    pub(crate) calls: Cell<u32>,
}

impl Memory {
    pub(crate) fn healthy() -> Self {
        let m = Self::default();
        *m.keys.borrow_mut() = Some(Keys::Fetched(ok(signed_metadata())));
        *m.list.borrow_mut() = Some(ok(list_jwt(NOW / 1000 - 60, false)));
        *m.introspection.borrow_mut() = Some(ok(introspection_body(
            &TokenSpec::intent_token(),
            true,
            BASIS_POS + 5,
        )));
        m
    }

    pub(crate) fn ports(&self) -> Ports<'_, Self, Self, Self, Self, Self, Self> {
        Ports {
            keys: self,
            replay: self,
            nonces: self,
            status: self,
            introspection: self,
            revocations: self,
        }
    }
}

impl KeySource for Memory {
    fn metadata(&self) -> Keys {
        self.calls.set(self.calls.get() + 1);
        self.keys
            .borrow()
            .clone()
            .unwrap_or(Keys::Fetched(Answer::Unanswered(Fault::Unreachable)))
    }
}

impl ReplayStore for Memory {
    fn record(&self, key: &[u8; 32], _until: u64) -> Replay {
        if self.replay_down.get() {
            return Replay::Unavailable;
        }
        if self.seen.borrow_mut().insert(*key) {
            Replay::Fresh
        } else {
            Replay::Seen
        }
    }
}

impl NonceSource for Memory {
    fn accept(&self, nonce: Option<&str>) -> bool {
        match (&*self.nonce_required.borrow(), nonce) {
            (None, _) => true,
            (Some(required), Some(given)) => required == given,
            (Some(_), None) => false,
        }
    }
}

impl StatusSource for Memory {
    fn list(&self, _uri: &str) -> Answer {
        self.calls.set(self.calls.get() + 1);
        self.list
            .borrow()
            .clone()
            .unwrap_or(Answer::Unanswered(Fault::Unreachable))
    }
}

impl Introspector for Memory {
    fn introspect(&self, _token: &str) -> Answer {
        self.calls.set(self.calls.get() + 1);
        self.introspection
            .borrow()
            .clone()
            .unwrap_or(Answer::Unanswered(Fault::Unreachable))
    }
}

impl Revocations for Memory {
    fn family_ended(&self, family: &[u8; 16]) -> bool {
        self.ended.borrow().contains(family)
    }
}

pub(crate) fn config(profile: Profile) -> Config {
    Config {
        issuer: ISSUER.to_owned(),
        audience: RS.to_owned(),
        domain: domain(),
        metadata: metadata(),
        profile,
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        key_epoch_ms: HOUR,
    }
}

pub(crate) fn server(profile: Profile) -> ResourceServer {
    ResourceServer::new(config(profile)).unwrap()
}
