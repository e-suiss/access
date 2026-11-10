//! `tl.read` (OP-155 m.3 (p); Ek B 4834): an ETSI TS 119 612 trusted list (the EU `LoTL` or a
//! national list), checked against the parser limits first, read into a deterministic CBOR
//! summary: sequence number, next update, list type, the pointers to other lists with their
//! signing certificates, every service with its provider, type, status and certificates, and the
//! certificates of the enveloped signature's `KeyInfo`. The worker verifies no signature and
//! holds no key; the caller decides what it trusts.

use access_edge_core::ipc::Summary;
use quick_xml::Reader;
use quick_xml::events::Event;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::parse;

/// Longest text value kept.
const MAX_TEXT: usize = 2048;
/// Largest certificate kept.
const MAX_CERT: usize = 16 * 1024;

#[derive(Default)]
struct Service {
    provider: String,
    type_uri: String,
    status: String,
    certificates: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Pointer {
    location: String,
    certificates: Vec<Vec<u8>>,
}

#[derive(Default)]
struct List {
    sequence: Option<u64>,
    next_update: String,
    tsl_type: String,
    pointers: Vec<Pointer>,
    services: Vec<Service>,
    signer: Vec<Vec<u8>>,
    provider_name: Option<String>,
}

fn local(name: &str) -> String {
    String::from(name.rsplit(':').next().unwrap_or(name))
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(text: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0_u32, 0_u32);
    let mut padding = false;
    for c in text.bytes() {
        if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        if c == b'=' {
            padding = true;
            continue;
        }
        let v = ALPHABET
            .iter()
            .position(|a| *a == c)
            .and_then(|p| u32::try_from(p).ok())
            .ok_or("tl-malformed")?;
        if padding {
            return Err("tl-malformed");
        }
        acc = (acc << 6) | v;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((acc >> bits) & 0xff).map_err(|_| "tl-malformed")?);
            acc &= (1_u32 << bits).saturating_sub(1);
        }
        if out.len() > MAX_CERT {
            return Err("tl-too-large");
        }
    }
    Ok(out)
}

fn ends(path: &[String], tail: &[&str]) -> bool {
    path.len() >= tail.len()
        && path
            .iter()
            .rev()
            .zip(tail.iter().rev())
            .all(|(p, t)| p == t)
}

fn within(path: &[String], name: &str) -> bool {
    path.iter().any(|p| p == name)
}

impl List {
    fn text(&mut self, path: &[String], text: &str) -> Result<(), &'static str> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(());
        }
        if text.len() > MAX_TEXT && !ends(path, &["X509Certificate"]) {
            return Err("tl-too-large");
        }
        if ends(path, &["SchemeInformation", "TSLSequenceNumber"]) {
            self.sequence = Some(text.parse().map_err(|_| "tl-malformed")?);
        } else if ends(path, &["SchemeInformation", "NextUpdate", "dateTime"]) {
            text.clone_into(&mut self.next_update);
        } else if ends(path, &["SchemeInformation", "TSLType"]) && !within(path, "OtherTSLPointer")
        {
            text.clone_into(&mut self.tsl_type);
        } else if ends(path, &["OtherTSLPointer", "TSLLocation"]) {
            if let Some(p) = self.pointers.last_mut() {
                text.clone_into(&mut p.location);
            }
        } else if ends(path, &["X509Certificate"]) {
            let der = b64(text)?;
            if within(path, "Signature") {
                self.signer.push(der);
            } else if within(path, "OtherTSLPointer") {
                if let Some(p) = self.pointers.last_mut() {
                    p.certificates.push(der);
                }
            } else if within(path, "TSPService")
                && within(path, "ServiceDigitalIdentity")
                && let Some(s) = self.services.last_mut()
            {
                s.certificates.push(der);
            }
        } else if ends(path, &["ServiceInformation", "ServiceTypeIdentifier"]) {
            if let Some(s) = self.services.last_mut() {
                text.clone_into(&mut s.type_uri);
            }
        } else if ends(path, &["ServiceInformation", "ServiceStatus"]) {
            if let Some(s) = self.services.last_mut() {
                text.clone_into(&mut s.status);
            }
        } else if ends(path, &["TSPInformation", "TSPName", "Name"]) && self.provider_name.is_none()
        {
            self.provider_name = Some(text.to_owned());
        }
        Ok(())
    }
}

impl List {
    fn to_value(&self) -> Value {
        let certs =
            |c: &[Vec<u8>]| Value::Array(c.iter().map(|d| Value::Bytes(d.clone())).collect());
        Value::Map(vec![
            (
                Value::text("pointers"),
                Value::Array(
                    self.pointers
                        .iter()
                        .map(|p| {
                            Value::Map(vec![
                                (Value::text("location"), Value::text(&p.location)),
                                (Value::text("certificates"), certs(&p.certificates)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                Value::text("sequence"),
                Value::Unsigned(self.sequence.unwrap_or(0)),
            ),
            (Value::text("tsl_type"), Value::text(&self.tsl_type)),
            (Value::text("next_update"), Value::text(&self.next_update)),
            (
                Value::text("services"),
                Value::Array(
                    self.services
                        .iter()
                        .map(|s| {
                            Value::Map(vec![
                                (Value::text("provider"), Value::text(&s.provider)),
                                (Value::text("service_type"), Value::text(&s.type_uri)),
                                (Value::text("status"), Value::text(&s.status)),
                                (Value::text("certificates"), certs(&s.certificates)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (Value::text("signer"), certs(&self.signer)),
        ])
    }
}

/// Reads a trusted list into its summary; the segment is the summary's deterministic CBOR.
///
/// # Errors
/// A stable refusal code.
pub(crate) fn read(input: &[u8]) -> Result<(Summary, Vec<u8>), &'static str> {
    let summary = parse::xml(input)?;
    if summary.root != "TrustServiceStatusList" {
        return Err("tl-malformed");
    }
    let text = core::str::from_utf8(input).map_err(|_| "xml-encoding")?;
    let mut reader = Reader::from_str(text);
    let mut path: Vec<String> = Vec::new();
    let mut list = List::default();
    loop {
        match reader.read_event().map_err(|_| "xml-malformed")? {
            Event::Start(e) => {
                let name = local(e.name().as_ref());
                match name.as_str() {
                    "OtherTSLPointer" => list.pointers.push(Pointer::default()),
                    "TSPService" => list.services.push(Service {
                        provider: list.provider_name.clone().unwrap_or_default(),
                        ..Service::default()
                    }),
                    "TrustServiceProvider" => list.provider_name = None,
                    _ => {}
                }
                path.push(name);
            }
            Event::End(_) => {
                path.pop();
            }
            Event::Text(t) => {
                let t: &str = &t;
                list.text(&path, t)?;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if list.sequence.is_none() || list.next_update.is_empty() {
        return Err("tl-malformed");
    }
    let out = dcbor::encode(&list.to_value(), Limits::CEILING).map_err(|_| "tl-too-large")?;
    Ok((summary, out))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        reason = "test code"
    )]

    use suiss_crypto::dcbor::{self, Limits, Value};

    use super::read;

    fn b64(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n =
                c.iter().fold(0_u32, |acc, b| (acc << 8) | u32::from(*b)) << (8 * (3 - c.len()));
            for i in 0..4 {
                if i <= c.len() {
                    out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// A trusted list in the TS 119 612 shape, with `cert` as every listed certificate.
    fn list(cert: &[u8]) -> String {
        let c = b64(cert);
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <tsl:SchemeInformation>
    <tsl:TSLSequenceNumber>42</tsl:TSLSequenceNumber>
    <tsl:TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</tsl:TSLType>
    <tsl:PointersToOtherTSL>
      <tsl:OtherTSLPointer>
        <tsl:ServiceDigitalIdentities><tsl:ServiceDigitalIdentity><tsl:DigitalId>
          <tsl:X509Certificate>{c}</tsl:X509Certificate>
        </tsl:DigitalId></tsl:ServiceDigitalIdentity></tsl:ServiceDigitalIdentities>
        <tsl:TSLLocation>https://tl.example.eu/xx.xml</tsl:TSLLocation>
      </tsl:OtherTSLPointer>
    </tsl:PointersToOtherTSL>
    <tsl:NextUpdate><tsl:dateTime>2027-05-01T00:00:00Z</tsl:dateTime></tsl:NextUpdate>
  </tsl:SchemeInformation>
  <tsl:TrustServiceProviderList>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation><tsl:TSPName><tsl:Name xml:lang="en">Example PID Provider</tsl:Name></tsl:TSPName></tsl:TSPInformation>
      <tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation>
        <tsl:ServiceTypeIdentifier>http://uri.etsi.org/19602/SvcType/PID/Issuance</tsl:ServiceTypeIdentifier>
        <tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>{c}</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>
        <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
      </tsl:ServiceInformation></tsl:TSPService></tsl:TSPServices>
    </tsl:TrustServiceProvider>
  </tsl:TrustServiceProviderList>
  <ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{c}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
</tsl:TrustServiceStatusList>"#
        )
    }

    fn cert() -> Vec<u8> {
        let mut v = std::process::id().to_be_bytes().to_vec();
        v.extend_from_slice(b"not a certificate, only bytes to carry");
        v
    }

    // OP-155 m.3 (p), Ek B 4834
    #[test]
    fn a_trusted_list_is_read_into_its_summary() {
        let c = cert();
        let (summary, out) = read(list(&c).as_bytes()).unwrap();
        assert_eq!(summary.root, "TrustServiceStatusList");
        let v = dcbor::decode(&out, Limits::CEILING).unwrap();
        assert_eq!(v.get("sequence"), Some(&Value::Unsigned(42)));
        assert_eq!(
            v.get("next_update"),
            Some(&Value::text("2027-05-01T00:00:00Z"))
        );
        let Some(Value::Array(services)) = v.get("services") else {
            panic!("{v:?}")
        };
        assert_eq!(services.len(), 1);
        assert_eq!(
            services[0].get("provider"),
            Some(&Value::text("Example PID Provider"))
        );
        assert_eq!(
            services[0].get("certificates"),
            Some(&Value::Array(vec![Value::Bytes(c.clone())]))
        );
        let Some(Value::Array(pointers)) = v.get("pointers") else {
            panic!("{v:?}")
        };
        assert_eq!(
            pointers[0].get("location"),
            Some(&Value::text("https://tl.example.eu/xx.xml"))
        );
        assert_eq!(v.get("signer"), Some(&Value::Array(vec![Value::Bytes(c)])));
    }

    // OP-155 m.3 (c), (p)
    #[test]
    fn anything_else_is_refused() {
        assert_eq!(read(b"<other/>").err(), Some("tl-malformed"));
        let doctype = br#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "b">]><r>&a;</r>"#;
        assert_eq!(read(doctype).err(), Some("xml-doctype"));
        let bad = list(&cert()).replace("<tsl:TSLSequenceNumber>42", "<tsl:TSLSequenceNumber>x");
        assert_eq!(read(bad.as_bytes()).err(), Some("tl-malformed"));
    }
}
