//! SPNEGO for the Kerberos gateway (RFC 4559, RFC 4178; §10.6.4, IDP-17, OP-155 m.3 (o)).
//! Sans-I/O. The parser worker reads a `Negotiate` token into a [`Token`] (`spnego.read`), so
//! the gateway never parses ASN.1 itself; this module holds that summary's wire form, the
//! gateway's checks on it before any ticket reaches libgssapi, the `Authorization` header and
//! the `NegTokenResp` the gateway answers with.

use suiss_crypto::dcbor::{self, Limits, Value};

/// `1.3.6.1.5.5.2`, SPNEGO.
pub const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// `1.2.840.113554.1.2.2`, Kerberos V5.
pub const OID_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// `1.2.840.48018.1.2.2`, the Kerberos OID Windows sends.
pub const OID_MS_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// `1.3.6.1.4.1.311.2.2.10`, NTLMSSP.
pub const OID_NTLM: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

/// The start of a raw NTLMSSP message.
pub const NTLMSSP: &[u8] = b"NTLMSSP\0";

/// Longest `Negotiate` token, decoded: the parser worker's DER ceiling.
pub const MAX_TOKEN: usize = 8 * 1024;

/// Longest realm or service name component.
pub const MAX_NAME: usize = 255;

/// The mechanism a token offers first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mech {
    /// Kerberos V5, with its AP-REQ read.
    Kerberos,
    /// NTLM: never accepted (IDP-17).
    Ntlm,
}

/// What the parser worker read from a `Negotiate` token.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    /// The mechanism.
    pub mech: Mech,
    /// Kerberos: the ticket's realm.
    pub realm: String,
    /// Kerberos: the ticket's service name, components joined by `/`.
    pub sname: String,
    /// Kerberos: the ticket's enctype.
    pub etype: i32,
    /// Kerberos: the ticket's key version, when the ticket names one.
    pub kvno: Option<u32>,
    /// Kerberos: the GSS-API initial context token that carries the AP-REQ, for libgssapi.
    pub krb5: Vec<u8>,
}

impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Token")
            .field("mech", &self.mech)
            .field("realm", &self.realm)
            .field("sname", &self.sname)
            .field("etype", &self.etype)
            .field("kvno", &self.kvno)
            .finish_non_exhaustive()
    }
}

/// Why a summary is not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed SPNEGO summary")]
pub struct SummaryError;

fn text(v: &Value, key: &str) -> Result<String, SummaryError> {
    match v.get(key) {
        Some(Value::Text(t)) if !t.is_empty() && t.len() <= 512 => Ok(t.clone()),
        _ => Err(SummaryError),
    }
}

impl Token {
    /// An NTLM token's summary.
    #[must_use]
    pub const fn ntlm() -> Self {
        Self {
            mech: Mech::Ntlm,
            realm: String::new(),
            sname: String::new(),
            etype: 0,
            kvno: None,
            krb5: Vec::new(),
        }
    }

    /// The service principal the ticket is for, `sname@realm`.
    #[must_use]
    pub fn spn(&self) -> String {
        let mut s = self.sname.clone();
        s.push('@');
        s.push_str(&self.realm);
        s
    }

    /// The summary as deterministic CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![(
            Value::text("mech"),
            Value::text(match self.mech {
                Mech::Kerberos => "kerberos",
                Mech::Ntlm => "ntlm",
            }),
        )];
        if self.mech == Mech::Kerberos {
            entries.extend([
                (Value::text("realm"), Value::text(&self.realm)),
                (Value::text("sname"), Value::text(&self.sname)),
                (Value::text("etype"), Value::int(i64::from(self.etype))),
                (Value::text("token"), Value::Bytes(self.krb5.clone())),
            ]);
            if let Some(k) = self.kvno {
                entries.push((Value::text("kvno"), Value::Unsigned(u64::from(k))));
            }
        }
        dcbor::encode(&Value::Map(entries), Limits::CEILING).unwrap_or_default()
    }

    /// Reads a summary.
    ///
    /// # Errors
    /// [`SummaryError`].
    pub fn decode(body: &[u8]) -> Result<Self, SummaryError> {
        let v = dcbor::decode(body, Limits::CEILING).map_err(|_| SummaryError)?;
        let Value::Map(entries) = &v else {
            return Err(SummaryError);
        };
        let keys = ["mech", "realm", "sname", "etype", "token", "kvno"];
        if !entries
            .iter()
            .all(|(k, _)| matches!(k, Value::Text(t) if keys.contains(&t.as_str())))
        {
            return Err(SummaryError);
        }
        match text(&v, "mech")?.as_str() {
            "ntlm" if entries.len() == 1 => Ok(Self::ntlm()),
            "kerberos" => {
                let etype = match v.get("etype") {
                    Some(Value::Unsigned(n)) => i32::try_from(*n).map_err(|_| SummaryError)?,
                    Some(Value::Negative(n)) => i32::try_from(*n)
                        .ok()
                        .and_then(|n| (-1_i32).checked_sub(n))
                        .ok_or(SummaryError)?,
                    _ => return Err(SummaryError),
                };
                let kvno = match v.get("kvno") {
                    None => None,
                    Some(Value::Unsigned(n)) => Some(u32::try_from(*n).map_err(|_| SummaryError)?),
                    Some(_) => return Err(SummaryError),
                };
                let krb5 = match v.get("token") {
                    Some(Value::Bytes(b)) if !b.is_empty() && b.len() <= MAX_TOKEN => b.clone(),
                    _ => return Err(SummaryError),
                };
                Ok(Self {
                    mech: Mech::Kerberos,
                    realm: text(&v, "realm")?,
                    sname: text(&v, "sname")?,
                    etype,
                    kvno,
                    krb5,
                })
            }
            _ => Err(SummaryError),
        }
    }
}

/// Why the gateway refuses a token before libgssapi sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// NTLM, raw or offered first in SPNEGO (IDP-17).
    Ntlm,
    /// A ticket for another service principal than the configured one, compared exactly.
    Spn,
    /// A ticket under an enctype other than AES256 (RC4 included).
    Enctype,
    /// A ticket without a key version.
    Kvno,
}

/// The gateway's own checks (OP-155 m.3 (o)): Kerberos, the exact SPN, AES256 and a key version.
/// access-server checks the same facts again against the realm's keytab policy.
///
/// # Errors
/// [`Refusal`].
pub fn check(t: &Token, spn: &str) -> Result<u32, Refusal> {
    if t.mech != Mech::Kerberos {
        return Err(Refusal::Ntlm);
    }
    if t.spn() != spn {
        return Err(Refusal::Spn);
    }
    if !access_internal_api::edge::kerberos::ENCTYPES.contains(&t.etype) {
        return Err(Refusal::Enctype);
    }
    t.kvno.ok_or(Refusal::Kvno)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn sextet(c: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|a| *a == c)
        .and_then(|p| u32::try_from(p).ok())
}

/// Standard base64 with padding.
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut b = [0_u8; 3];
        for (d, s) in b.iter_mut().zip(chunk) {
            *d = *s;
        }
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18_u32, 12, 6, 0].iter().enumerate() {
            let c = ALPHABET
                .get(usize::try_from((n >> shift) & 0x3f).unwrap_or(0))
                .map_or('=', |c| char::from(*c));
            out.push(if i <= chunk.len() { c } else { '=' });
        }
    }
    out
}

fn unbase64(text: &str) -> Option<Vec<u8>> {
    let input = text.as_bytes();
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return None;
    }
    let quads = input.len() / 4;
    let mut out = Vec::new();
    for (q, chunk) in input.chunks(4).enumerate() {
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && q.checked_add(1) != Some(quads)) {
            return None;
        }
        let data = chunk.len().saturating_sub(pad);
        let mut acc = 0_u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = if i < data { sextet(*c)? } else { 0 };
            acc = (acc << 6) | v;
        }
        let [_, b0, b1, b2] = acc.to_be_bytes();
        out.extend([b0, b1, b2].iter().take(3_usize.saturating_sub(pad)));
    }
    Some(out)
}

/// The token of an `Authorization: Negotiate <base64>` header value; `None` for any other
/// scheme, an empty or oversized token, or base64 that does not decode.
#[must_use]
pub fn authorization(value: &str) -> Option<Vec<u8>> {
    let (scheme, token) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("negotiate") {
        return None;
    }
    let token = token.trim();
    if token.len() > MAX_TOKEN.div_ceil(3).saturating_mul(4) {
        return None;
    }
    unbase64(token).filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN)
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else if let Ok(n) = u8::try_from(len) {
        out.extend([0x81, n]);
    } else {
        let [hi, lo] = u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes();
        out.extend([0x82, hi, lo]);
    }
    out.extend_from_slice(value);
    out
}

/// The `NegTokenResp` that completes a Kerberos acceptance (RFC 4178 §4.2.2): `accept-completed`,
/// Kerberos as the supported mechanism, and libgssapi's AP-REP when there is one.
#[must_use]
pub fn accept_completed(ap_rep: Option<&[u8]>) -> Vec<u8> {
    let mut fields = tlv(0xa0, &tlv(0x0a, &[0]));
    fields.extend(tlv(0xa1, &tlv(0x06, OID_KRB5)));
    if let Some(r) = ap_rep {
        fields.extend(tlv(0xa2, &tlv(0x04, r)));
    }
    tlv(0xa1, &tlv(0x30, &fields))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn token(sname: &str, etype: i32, kvno: Option<u32>) -> Token {
        Token {
            mech: Mech::Kerberos,
            realm: String::from("CORP.EXAMPLE"),
            sname: String::from(sname),
            etype,
            kvno,
            krb5: vec![0x60, 0x00],
        }
    }

    // IDP-17, OP-155 m.3 (o)
    #[test]
    fn ntlm_another_spn_and_rc4_are_refused_before_libgssapi() {
        let spn = "HTTP/access.corp.example@CORP.EXAMPLE";
        let t = token("HTTP/access.corp.example", 18, Some(3));
        assert_eq!(check(&t, spn), Ok(3));
        assert_eq!(check(&Token::ntlm(), spn), Err(Refusal::Ntlm));
        assert_eq!(
            check(&token("HTTP/other.corp.example", 18, Some(3)), spn),
            Err(Refusal::Spn)
        );
        assert_eq!(
            check(&token("HTTP/access.corp.example", 23, Some(3)), spn),
            Err(Refusal::Enctype)
        );
        assert_eq!(
            check(&token("HTTP/access.corp.example", 20, None), spn),
            Err(Refusal::Kvno)
        );
    }

    // OP-155 m.3 (o)
    #[test]
    fn summaries_round_trip_and_headers_are_bounded() {
        let t = token("HTTP/access.corp.example", -128, Some(7));
        assert_eq!(Token::decode(&t.encode()).unwrap(), t);
        assert_eq!(
            Token::decode(&Token::ntlm().encode()).unwrap(),
            Token::ntlm()
        );
        let raw = [1_u8, 2, 3, 4, 5];
        assert_eq!(
            authorization(&format!("Negotiate {}", base64(&raw))),
            Some(raw.to_vec())
        );
        assert_eq!(authorization(&format!("Basic {}", base64(&raw))), None);
        assert_eq!(authorization("Negotiate"), None);
        assert_eq!(authorization("Negotiate !!!!"), None);
        let huge = base64(&vec![0_u8; MAX_TOKEN + 1]);
        assert_eq!(authorization(&format!("Negotiate {huge}")), None);
        let resp = accept_completed(Some(&[0x6f, 0x00]));
        assert_eq!(&resp[..2], &[0xa1, u8::try_from(resp.len() - 2).unwrap()]);
        assert!(resp.windows(OID_KRB5.len()).any(|w| w == OID_KRB5));
    }
}
