//! ISO 18013-5 mdoc presentations under OID4VP (HAIP; Ek B 4832): a `DeviceResponse` with one
//! document, its `issuerAuth` (`COSE_Sign1`, ES256, `x5chain`) over the Mobile Security Object,
//! the issuer-signed items checked against the MSO's value digests, and the device signature
//! over the OID4VP session transcript. CBOR is read as [`super::cbor`] profiles it; device-signed
//! elements, `deviceMac` and `null`/float element values are refused.

use access_kernel::json::{Json, b64url_encode};
use access_kernel::model::TrustedTime;
use access_kernel::verify::Backend;
use access_kernel::verify::cose::PublicKey;

use super::cbor::{self, Cbor};
use super::dcql::{Path, Step};
use super::time::rfc3339_ms;

/// Largest `DeviceResponse`.
pub const MAX_RESPONSE: usize = 1024 * 1024;
/// Most certificates in `x5chain`.
pub const MAX_CHAIN: usize = 4;
/// Shortest `random` of an issuer-signed item (ISO 18013-5 §9.1.2.5).
pub const MIN_RANDOM: usize = 16;

const TAG_TDATE: u64 = 0;
const TAG_CBOR: u64 = 24;
const TAG_SIGN1: u64 = 18;
const TAG_FULL_DATE: u64 = 1004;
const ES256: i64 = -7;
const X5CHAIN: i64 = 33;

/// Why an mdoc presentation is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MdocError {
    /// Not a `DeviceResponse` with exactly one document in the profile.
    #[error("mdoc-malformed")]
    Malformed,
    /// `issuerAuth` or `deviceSignature` not ES256, or a `crit` header.
    #[error("mdoc-alg")]
    Algorithm,
    /// The issuer signature does not verify.
    #[error("mdoc-issuer-signature")]
    IssuerSignature,
    /// An item's digest is not the one the MSO signed, or the doc type differs.
    #[error("mdoc-digest")]
    Digest,
    /// Outside the MSO's validity.
    #[error("mdoc-validity")]
    Validity,
    /// The device signature over the session transcript does not verify, or is a MAC.
    #[error("mdoc-device-auth")]
    DeviceAuth,
}

impl MdocError {
    /// Stable code.
    #[must_use]
    pub fn code(self) -> String {
        self.to_string()
    }
}

/// An mdoc read but not verified: the caller checks [`Parsed::chain`] against its trust and
/// calls [`Parsed::verify`] with the leaf's key.
#[derive(Clone, Debug)]
pub struct Parsed {
    /// The document's `docType`.
    pub doctype: String,
    /// `x5chain`, DER, leaf first.
    pub chain: Vec<Vec<u8>>,
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
    items: Vec<(String, Vec<u8>)>,
    device_namespaces: Vec<u8>,
    device_protected: Vec<u8>,
    device_signature: Vec<u8>,
}

/// A verified mdoc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presented {
    /// `{namespace: {element: value}}` of the disclosed items.
    pub claims: Json,
    /// `[namespace, element]` of every disclosed item.
    pub disclosed: Vec<Path>,
    /// The MSO's `status.status_list`, when it names one.
    pub status: Option<(u64, String)>,
    /// The MSO's `validUntil`, milliseconds.
    pub until: u64,
}

fn decode(bytes: &[u8]) -> Result<Cbor, MdocError> {
    cbor::decode(bytes).map_err(|_| MdocError::Malformed)
}

fn embedded(v: &Cbor) -> Result<&[u8], MdocError> {
    match v {
        Cbor::Tag(TAG_CBOR, inner) => match inner.as_ref() {
            Cbor::Bytes(b) => Ok(b),
            _ => Err(MdocError::Malformed),
        },
        _ => Err(MdocError::Malformed),
    }
}

fn get<'v>(v: &'v Cbor, key: &str) -> Result<&'v Cbor, MdocError> {
    v.get(key).ok_or(MdocError::Malformed)
}

fn text(v: &Cbor) -> Result<&str, MdocError> {
    match v {
        Cbor::Text(t) => Ok(t),
        _ => Err(MdocError::Malformed),
    }
}

fn bytes(v: &Cbor) -> Result<&[u8], MdocError> {
    match v {
        Cbor::Bytes(b) => Ok(b),
        _ => Err(MdocError::Malformed),
    }
}

fn uint(v: &Cbor) -> Result<u64, MdocError> {
    match v {
        Cbor::Uint(n) => Ok(*n),
        _ => Err(MdocError::Malformed),
    }
}

struct Sign1<'v> {
    protected: &'v [u8],
    unprotected: &'v Cbor,
    payload: Option<&'v [u8]>,
    signature: &'v [u8],
}

fn sign1(v: &Cbor) -> Result<Sign1<'_>, MdocError> {
    let v = match v {
        Cbor::Tag(TAG_SIGN1, inner) => inner.as_ref(),
        other => other,
    };
    let Cbor::Array(parts) = v else {
        return Err(MdocError::Malformed);
    };
    let [protected, unprotected, payload, signature] = parts.as_slice() else {
        return Err(MdocError::Malformed);
    };
    let payload = match payload {
        Cbor::Bytes(b) => Some(b.as_slice()),
        Cbor::Null => None,
        _ => return Err(MdocError::Malformed),
    };
    if !matches!(unprotected, Cbor::Map(_)) {
        return Err(MdocError::Malformed);
    }
    Ok(Sign1 {
        protected: bytes(protected)?,
        unprotected,
        payload,
        signature: bytes(signature)?,
    })
}

fn es256_only(s: &Sign1<'_>) -> Result<Cbor, MdocError> {
    let header = decode(s.protected)?;
    if header.get_int(1).and_then(Cbor::as_i64) != Some(ES256)
        || header.get_int(2).is_some()
        || s.unprotected.get_int(1).is_some()
        || s.unprotected.get_int(2).is_some()
    {
        return Err(MdocError::Algorithm);
    }
    Ok(header)
}

fn chain(header: &Cbor, unprotected: &Cbor) -> Result<Vec<Vec<u8>>, MdocError> {
    match unprotected
        .get_int(X5CHAIN)
        .or_else(|| header.get_int(X5CHAIN))
    {
        Some(Cbor::Bytes(b)) => Ok(vec![b.clone()]),
        Some(Cbor::Array(items)) if !items.is_empty() && items.len() <= MAX_CHAIN => {
            items.iter().map(|i| bytes(i).map(<[u8]>::to_vec)).collect()
        }
        _ => Err(MdocError::Malformed),
    }
}

/// Reads a `DeviceResponse` (the `vp_token` value, decoded from base64url).
///
/// # Errors
/// [`MdocError`].
pub fn parse(response: &[u8]) -> Result<Parsed, MdocError> {
    if response.len() > MAX_RESPONSE {
        return Err(MdocError::Malformed);
    }
    let r = decode(response)?;
    if text(get(&r, "version")?)? != "1.0" || uint(get(&r, "status")?)? != 0 {
        return Err(MdocError::Malformed);
    }
    let Cbor::Array(docs) = get(&r, "documents")? else {
        return Err(MdocError::Malformed);
    };
    let [doc] = docs.as_slice() else {
        return Err(MdocError::Malformed);
    };
    let doctype = String::from(text(get(doc, "docType")?)?);
    let issuer_signed = get(doc, "issuerSigned")?;
    let issuer = sign1(get(issuer_signed, "issuerAuth")?)?;
    let header = es256_only(&issuer)?;
    let chain = chain(&header, issuer.unprotected)?;
    let payload = issuer.payload.ok_or(MdocError::Malformed)?;
    let mut items = Vec::new();
    if let Some(namespaces) = issuer_signed.get("nameSpaces") {
        let Cbor::Map(namespaces) = namespaces else {
            return Err(MdocError::Malformed);
        };
        for (ns, list) in namespaces {
            let ns = text(ns)?;
            let Cbor::Array(list) = list else {
                return Err(MdocError::Malformed);
            };
            for item in list {
                embedded(item)?;
                items.push((String::from(ns), cbor::encode(item)));
            }
        }
    }
    let device_signed = get(doc, "deviceSigned")?;
    let dns_item = get(device_signed, "nameSpaces")?;
    if decode(embedded(dns_item)?)? != Cbor::Map(Vec::new()) {
        return Err(MdocError::Malformed);
    }
    let device = get(device_signed, "deviceAuth")?
        .get("deviceSignature")
        .ok_or(MdocError::DeviceAuth)?;
    let device = sign1(device)?;
    es256_only(&device).map_err(|_| MdocError::DeviceAuth)?;
    if device.payload.is_some() {
        return Err(MdocError::DeviceAuth);
    }
    Ok(Parsed {
        doctype,
        chain,
        protected: issuer.protected.to_vec(),
        payload: payload.to_vec(),
        signature: issuer.signature.to_vec(),
        items,
        device_namespaces: cbor::encode(dns_item),
        device_protected: device.protected.to_vec(),
        device_signature: device.signature.to_vec(),
    })
}

fn verify_es256(
    backend: &impl Backend,
    key: &PublicKey,
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> bool {
    let PublicKey::P256(sec1) = key else {
        return false;
    };
    suiss_crypto::cose::to_be_signed(protected, payload)
        .is_ok_and(|tbs| access_kernel::verify::p256(backend, sec1, &tbs, signature, false).is_ok())
}

fn cose_key(v: &Cbor) -> Result<PublicKey, MdocError> {
    let kty = v.get_int(1).and_then(Cbor::as_i64);
    let crv = v.get_int(-1).and_then(Cbor::as_i64);
    let x = v.get_int(-2).map(bytes).transpose()?;
    let y = v.get_int(-3).map(bytes).transpose()?;
    match (kty, crv, x, y) {
        (Some(2), Some(1), Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => {
            let key = PublicKey::P256([&[0x04][..], x, y].concat());
            key.check().map_err(|_| MdocError::DeviceAuth)?;
            Ok(key)
        }
        _ => Err(MdocError::DeviceAuth),
    }
}

/// The CBOR item as JSON: text, integers, booleans, dates as text, bytes as base64url; `null`,
/// other tags and non-text map keys are not read.
#[must_use]
pub fn to_json(v: &Cbor) -> Option<Json> {
    Some(match v {
        Cbor::Uint(_) | Cbor::Nint(_) => Json::Int(v.as_i64()?),
        Cbor::Bytes(b) => Json::Str(b64url_encode(b)),
        Cbor::Text(t) => Json::Str(t.clone()),
        Cbor::Bool(b) => Json::Bool(*b),
        Cbor::Array(items) => Json::Array(items.iter().map(to_json).collect::<Option<_>>()?),
        Cbor::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(k, v)| match k {
                    Cbor::Text(k) => to_json(v).map(|v| (k.clone(), v)),
                    _ => None,
                })
                .collect::<Option<_>>()?,
        ),
        Cbor::Tag(TAG_TDATE | TAG_FULL_DATE, inner) => match inner.as_ref() {
            Cbor::Text(t) => Json::Str(t.clone()),
            _ => return None,
        },
        Cbor::Tag(..) | Cbor::Null => return None,
    })
}

/// `SessionTranscript` for OID4VP over `direct_post.jwt` (OID4VP 1.0 Appendix B.2.6.1):
/// `[null, null, ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwk_thumbprint,
/// response_uri]))]]`.
#[must_use]
pub fn session_transcript(
    client_id: &str,
    nonce: &str,
    jwk_thumbprint: &[u8; 32],
    response_uri: &str,
) -> Vec<u8> {
    let info = cbor::encode(&Cbor::Array(vec![
        Cbor::text(client_id),
        Cbor::text(nonce),
        Cbor::Bytes(jwk_thumbprint.to_vec()),
        Cbor::text(response_uri),
    ]));
    cbor::encode(&Cbor::Array(vec![
        Cbor::Null,
        Cbor::Null,
        Cbor::Array(vec![
            Cbor::text("OpenID4VPHandover"),
            Cbor::Bytes(suiss_crypto::digest::sha256(&info).to_vec()),
        ]),
    ]))
}

/// `DeviceAuthenticationBytes`: `#6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript,
/// DocType, DeviceNameSpacesBytes])`.
///
/// # Errors
/// [`MdocError::Malformed`] when the transcript or the name spaces are not CBOR.
pub fn device_authentication(
    transcript: &[u8],
    doctype: &str,
    device_namespaces: &[u8],
) -> Result<Vec<u8>, MdocError> {
    let inner = cbor::encode(&Cbor::Array(vec![
        Cbor::text("DeviceAuthentication"),
        decode(transcript)?,
        Cbor::text(doctype),
        decode(device_namespaces)?,
    ]));
    Ok(cbor::encode(&Cbor::Tag(
        TAG_CBOR,
        Box::new(Cbor::Bytes(inner)),
    )))
}

fn status_of(mso: &Cbor) -> Result<Option<(u64, String)>, MdocError> {
    let Some(status) = mso.get("status") else {
        return Ok(None);
    };
    let list = get(status, "status_list")?;
    Ok(Some((
        uint(get(list, "idx")?)?,
        String::from(text(get(list, "uri")?)?),
    )))
}

fn tdate(v: &Cbor) -> Result<u64, MdocError> {
    match v {
        Cbor::Tag(TAG_TDATE, inner) => rfc3339_ms(text(inner)?).ok_or(MdocError::Malformed),
        _ => Err(MdocError::Malformed),
    }
}

impl Parsed {
    /// Verifies the issuer signature with the `x5chain` leaf key the caller trusts, the items
    /// against the MSO, its validity at `now`, and the device signature over `transcript`.
    ///
    /// # Errors
    /// [`MdocError`].
    pub fn verify(
        &self,
        backend: &impl Backend,
        issuer: &PublicKey,
        transcript: &[u8],
        now: TrustedTime,
        skew_ms: u64,
    ) -> Result<Presented, MdocError> {
        if !verify_es256(
            backend,
            issuer,
            &self.protected,
            &self.payload,
            &self.signature,
        ) {
            return Err(MdocError::IssuerSignature);
        }
        let mso = decode(embedded(&decode(&self.payload)?)?)?;
        if text(get(&mso, "version")?)? != "1.0"
            || text(get(&mso, "digestAlgorithm")?)? != "SHA-256"
        {
            return Err(MdocError::Malformed);
        }
        if text(get(&mso, "docType")?)? != self.doctype {
            return Err(MdocError::Digest);
        }
        let validity = get(&mso, "validityInfo")?;
        let from = tdate(get(validity, "validFrom")?)?;
        let until = tdate(get(validity, "validUntil")?)?;
        if now.saturating_add(skew_ms) < from || now > until.saturating_add(skew_ms) {
            return Err(MdocError::Validity);
        }
        let digests = get(&mso, "valueDigests")?;
        let mut namespaces: Vec<(String, Json)> = Vec::new();
        let mut disclosed = Vec::new();
        for (ns, encoded) in &self.items {
            let item = decode(embedded(&decode(encoded)?)?)?;
            let id = uint(get(&item, "digestID")?)?;
            if bytes(get(&item, "random")?)?.len() < MIN_RANDOM {
                return Err(MdocError::Malformed);
            }
            let name = text(get(&item, "elementIdentifier")?)?;
            let expected = match get(digests, ns)? {
                Cbor::Map(m) => m.iter().find(|(k, _)| *k == Cbor::Uint(id)).map(|(_, v)| v),
                _ => None,
            }
            .ok_or(MdocError::Digest)?;
            if bytes(expected)? != suiss_crypto::digest::sha256(encoded).as_slice() {
                return Err(MdocError::Digest);
            }
            let path = vec![Step::Key(ns.clone()), Step::Key(String::from(name))];
            if disclosed.contains(&path) {
                return Err(MdocError::Malformed);
            }
            disclosed.push(path);
            let value = to_json(get(&item, "elementValue")?).ok_or(MdocError::Malformed)?;
            match namespaces.iter_mut().find(|(n, _)| n == ns) {
                Some((_, Json::Object(m))) => m.push((String::from(name), value)),
                _ => namespaces.push((ns.clone(), Json::Object(vec![(String::from(name), value)]))),
            }
        }
        let device_key = cose_key(get(get(&mso, "deviceKeyInfo")?, "deviceKey")?)?;
        let auth = device_authentication(transcript, &self.doctype, &self.device_namespaces)?;
        if !verify_es256(
            backend,
            &device_key,
            &self.device_protected,
            &auth,
            &self.device_signature,
        ) {
            return Err(MdocError::DeviceAuth);
        }
        Ok(Presented {
            claims: Json::Object(namespaces),
            disclosed,
            status: status_of(&mso)?,
            until,
        })
    }
}
