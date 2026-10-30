//! Subcommands. Each one reads its inputs and hands them to the Kernel unchanged.

use access_kernel::binding::{self, Error};
use access_kernel::codec::{Canonical, ModelError};
use access_kernel::digest::{self, Digest, ProofError};
use access_kernel::record::{Disclosure, Header, RecordEnvelope, RecordError};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{self, KeySet};
use access_kernel::verify::key_scope::OperationalKey;

use crate::args::{Options, Usage, hex};

/// The verification result: acceptance with named outputs, or rejection with a stable name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Accepted; outputs in print order.
    Accept(Vec<(&'static str, String)>),
    /// Rejected, with the reason name.
    Reject(String),
}

fn reject(e: Error) -> Outcome {
    Outcome::Reject(e.name())
}

/// A subcommand: name, options, one-line summary and the function that runs it.
pub(crate) struct Command {
    pub(crate) name: &'static str,
    pub(crate) options: &'static [&'static str],
    pub(crate) summary: &'static str,
    pub(crate) run: fn(&Options) -> Result<Outcome, Usage>,
}

const RESOLVE: &[&str] = &["metadata", "trusted", "domain", "excerpt", "usage", "iat"];

/// Every subcommand.
pub(crate) const COMMANDS: &[Command] = &[
    Command {
        name: "metadata",
        options: &["signed", "trusted"],
        summary: "Domain Metadata (COSE_Sign1) against the trusted binding key-set",
        run: metadata,
    },
    Command {
        name: "key",
        options: RESOLVE,
        summary: "operational key for an artefact of --domain signed at --iat, from Domain Metadata and a key excerpt",
        run: key,
    },
    Command {
        name: "cose",
        options: &[
            "sign1",
            "content-type",
            "keys",
            "metadata",
            "trusted",
            "domain",
            "excerpt",
            "usage",
            "iat",
        ],
        summary: "COSE_Sign1 artefact against a key-set, or against the operational key that `key` resolves",
        run: cose_sign1,
    },
    Command {
        name: "jws",
        options: &[
            "token", "keys", "typ", "issuer", "audience", "now", "skew-ms",
        ],
        summary: "Access-native compact JWS and its claims",
        run: jws,
    },
    Command {
        name: "sd-jwt",
        options: &[
            "presentation",
            "keys",
            "typ",
            "audience",
            "nonce",
            "now",
            "skew-ms",
        ],
        summary: "Access-native SD-JWT presentation with key binding",
        run: sd_jwt,
    },
    Command {
        name: "validity",
        options: &[
            "contract",
            "now",
            "audience",
            "understood",
            "last-refresh",
            "online",
            "skew-ms",
            "iat",
            "horizon-cap-ms",
        ],
        summary: "validity contract at the moment of use",
        run: validity,
    },
    Command {
        name: "inclusion",
        options: &["index", "size", "root", "path", "leaf", "leaf-hash"],
        summary: "RFC 9162 inclusion proof",
        run: inclusion,
    },
    Command {
        name: "consistency",
        options: &["first", "second", "first-root", "second-root", "path"],
        summary: "RFC 9162 consistency proof",
        run: consistency,
    },
    Command {
        name: "record",
        options: &["envelope", "disclosure", "size", "root", "path"],
        summary: "record envelope or disclosure, and optionally its inclusion in the domain log",
        run: record,
    },
];

fn metadata(o: &Options) -> Result<Outcome, Usage> {
    let (signed, trusted) = (o.file("signed")?, o.file("trusted")?);
    Ok(match binding::verify_metadata(&signed, &trusted) {
        Ok(m) => Outcome::Accept(vec![("metadata", hex(&m))]),
        Err(e) => reject(e),
    })
}

fn resolve(o: &Options) -> Result<Result<Vec<u8>, Error>, Usage> {
    let mut metadata = o.file("metadata")?;
    if o.has("trusted") {
        match binding::verify_metadata(&metadata, &o.file("trusted")?) {
            Ok(m) => metadata = m,
            Err(e) => return Ok(Err(e)),
        }
    }
    let domain = Digest(o.hash("domain")?)
        .to_bytes()
        .map_err(|_| Usage("--domain cannot be encoded".to_owned()))?;
    let excerpt = o.file("excerpt")?;
    Ok(binding::operational_key(
        &metadata,
        &domain,
        &excerpt,
        o.text("usage")?,
        o.uint("iat")?,
    ))
}

fn key(o: &Options) -> Result<Outcome, Usage> {
    Ok(match resolve(o)? {
        Ok(k) => Outcome::Accept(vec![("key", hex(&k))]),
        Err(e) => reject(e),
    })
}

fn cose_sign1(o: &Options) -> Result<Outcome, Usage> {
    let sign1 = o.file("sign1")?;
    let content_type = o.text("content-type")?;
    let keys = match (o.has("keys"), o.has("metadata")) {
        (true, false) if RESOLVE.iter().any(|n| o.has(n)) => {
            return Err(Usage(
                "--keys does not combine with the key-resolution options".to_owned(),
            ));
        }
        (true, false) => match KeySet::from_bytes(&o.file("keys")?) {
            Ok(k) => k,
            Err(_) => return Ok(reject(Error::Input)),
        },
        (false, true) => match resolve(o)? {
            Ok(k) => match OperationalKey::from_bytes(&k) {
                Ok(k) => k.key_set(),
                Err(_) => return Ok(reject(Error::Input)),
            },
            Err(e) => return Ok(reject(e)),
        },
        _ => return Err(Usage("give either --keys or --metadata".to_owned())),
    };
    Ok(
        match cose::verify_sign1(&PureBackend, &sign1, &keys, content_type) {
            Ok(v) => Outcome::Accept(vec![("kid", hex(&v.kid)), ("payload", hex(&v.payload))]),
            Err(e) => reject(Error::Cose(e)),
        },
    )
}

fn jws(o: &Options) -> Result<Outcome, Usage> {
    let token = o.text_file("token")?;
    let keys = o.file("keys")?;
    Ok(
        match binding::verify_jws_compact(
            &token,
            &keys,
            o.text("typ")?,
            o.text("issuer")?,
            o.text("audience")?,
            o.uint("now")?,
            o.uint("skew-ms")?,
        ) {
            Ok(payload) => Outcome::Accept(vec![("payload", payload)]),
            Err(e) => reject(e),
        },
    )
}

fn sd_jwt(o: &Options) -> Result<Outcome, Usage> {
    let presentation = o.text_file("presentation")?;
    let keys = o.file("keys")?;
    Ok(
        match binding::verify_sd_jwt(
            &presentation,
            &keys,
            o.text("typ")?,
            o.text("audience")?,
            o.text("nonce")?,
            o.uint("now")?,
            o.uint("skew-ms")?,
        ) {
            Ok(claims) => Outcome::Accept(vec![("claims", claims)]),
            Err(e) => reject(e),
        },
    )
}

fn validity(o: &Options) -> Result<Outcome, Usage> {
    let contract = o.file("contract")?;
    Ok(
        match binding::check_validity(
            &contract,
            o.uint("now")?,
            o.text("audience")?,
            o.words("understood"),
            o.opt_uint("last-refresh")?,
            o.boolean("online")?,
            o.uint("skew-ms")?,
            o.uint("iat")?,
            o.uint("horizon-cap-ms")?,
        ) {
            Ok(()) => Outcome::Accept(Vec::new()),
            Err(e) => reject(e),
        },
    )
}

const fn proof_name(e: ProofError) -> &'static str {
    match e {
        ProofError::Range => "range",
        ProofError::Length => "length",
        ProofError::Mismatch => "mismatch",
        _ => "proof",
    }
}

fn proof(result: Result<(), ProofError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Accept(Vec::new()),
        Err(e) => Outcome::Reject(proof_name(e).to_owned()),
    }
}

fn inclusion(o: &Options) -> Result<Outcome, Usage> {
    let leaf = match (o.has("leaf"), o.has("leaf-hash")) {
        (true, false) => digest::leaf_hash(&o.file("leaf")?),
        (false, true) => o.hash("leaf-hash")?,
        _ => return Err(Usage("give either --leaf or --leaf-hash".to_owned())),
    };
    Ok(proof(digest::verify_inclusion(
        o.uint("index")?,
        o.uint("size")?,
        &leaf,
        &o.hashes("path")?,
        &o.hash("root")?,
    )))
}

fn consistency(o: &Options) -> Result<Outcome, Usage> {
    Ok(proof(digest::verify_consistency(
        o.uint("first")?,
        o.uint("second")?,
        &o.hash("first-root")?,
        &o.hash("second-root")?,
        &o.hashes("path")?,
    )))
}

const fn model_name(e: ModelError) -> &'static str {
    match e {
        ModelError::Cbor(_) => "cbor",
        ModelError::Shape => "shape",
        ModelError::Missing => "missing",
        ModelError::Unknown => "unknown",
        ModelError::SetOrder => "set-order",
        ModelError::Range => "range",
    }
}

fn record_name(e: RecordError) -> String {
    match e {
        RecordError::Model(m) => model_name(m).to_owned(),
        RecordError::Encode => "encode".to_owned(),
        RecordError::Proof(p) => format!("inclusion: {}", proof_name(p)),
    }
}

struct Opened {
    header: Header,
    leaf: digest::Hash,
    domain: Option<Digest>,
}

fn open(o: &Options) -> Result<Result<Opened, RecordError>, Usage> {
    Ok(match (o.has("envelope"), o.has("disclosure")) {
        (true, false) => RecordEnvelope::from_bytes(&o.file("envelope")?)
            .map_err(RecordError::from)
            .and_then(|env| {
                Ok(Opened {
                    leaf: env.leaf_hash()?,
                    domain: Some(env.domain()?),
                    header: env.header,
                })
            }),
        (false, true) => Disclosure::from_bytes(&o.file("disclosure")?)
            .map_err(RecordError::from)
            .and_then(|d| {
                Ok(Opened {
                    leaf: d.leaf_hash()?,
                    domain: d.header.domain,
                    header: d.header,
                })
            }),
        _ => return Err(Usage("give either --envelope or --disclosure".to_owned())),
    })
}

fn record(o: &Options) -> Result<Outcome, Usage> {
    let proof_args = ["size", "root", "path"].map(|n| o.has(n));
    if proof_args.contains(&true) && proof_args.contains(&false) {
        return Err(Usage(
            "give all of --size, --root and --path, or none".to_owned(),
        ));
    }
    let opened = match open(o)? {
        Ok(r) => r,
        Err(e) => return Ok(Outcome::Reject(record_name(e))),
    };
    if proof_args.contains(&true) {
        let checked = digest::verify_inclusion(
            opened.header.pos,
            o.uint("size")?,
            &opened.leaf,
            &o.hashes("path")?,
            &o.hash("root")?,
        );
        if let Err(e) = checked {
            return Ok(Outcome::Reject(record_name(RecordError::Proof(e))));
        }
    }
    let mut out = vec![
        ("leaf_hash", hex(&opened.leaf)),
        ("pos", opened.header.pos.to_string()),
    ];
    if let Some(d) = opened.domain {
        out.push(("domain", hex(&d.0)));
    }
    Ok(Outcome::Accept(out))
}
