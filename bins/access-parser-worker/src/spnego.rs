//! `spnego.read` (RFC 4559, RFC 4178, RFC 4121, RFC 4120; OP-155 m.3 (o), RR-28): the Kerberos
//! gateway's `Negotiate` token, read here so that ASN.1 never parses in the gateway. A raw
//! NTLMSSP message or a `NegTokenInit` offering NTLM first is summarised as NTLM, for the gateway
//! to refuse. Otherwise the first mechanism must be Kerberos with its token present; the AP-REQ's
//! ticket gives its realm, service name, enctype and key version, in the clear by design. Nothing
//! is decrypted. Bounded like `der.check`: at most 8 KiB, definite shortest lengths.

use access_edge_core::ipc::Summary;
use access_edge_core::spnego::{
    MAX_NAME, Mech, NTLMSSP, OID_KRB5, OID_MS_KRB5, OID_NTLM, OID_SPNEGO, Token,
};
use access_parse::der::{OCTET_STRING, OID, Reader, SEQUENCE};

use crate::parse::MAX_DER;

const MALFORMED: &str = "spnego-malformed";
const MECH: &str = "spnego-mech";

const GSS_TOKEN: u8 = 0x60;
const AP_REQ: u8 = 0x6e;
const TICKET: u8 = 0x61;
const INTEGER: u8 = 0x02;
const GENERAL_STRING: u8 = 0x1b;
const BIT_STRING: u8 = 0x03;
const TOK_AP_REQ: [u8; 2] = [0x01, 0x00];

fn reader(input: &[u8]) -> Result<Reader<'_>, &'static str> {
    Reader::new(input).map_err(|_| MALFORMED)
}

fn whole(input: &[u8], tag: u8) -> Result<&[u8], &'static str> {
    let mut r = reader(input)?;
    let v = r.tagged(tag).map_err(|_| MALFORMED)?;
    if r.is_empty() { Ok(v) } else { Err(MALFORMED) }
}

fn context<'a>(r: &mut Reader<'a>, n: u8) -> Result<&'a [u8], &'static str> {
    r.tagged(0xa0 | n).map_err(|_| MALFORMED)
}

fn integer(v: &[u8]) -> Result<i64, &'static str> {
    let body = whole(v, INTEGER)?;
    let (&first, rest) = body.split_first().ok_or(MALFORMED)?;
    let redundant = rest
        .first()
        .is_some_and(|b| (first == 0 && b & 0x80 == 0) || (first == 0xff && b & 0x80 != 0));
    if body.len() > 5 || redundant {
        return Err(MALFORMED);
    }
    let start = if first & 0x80 != 0 { -1_i64 } else { 0 };
    Ok(body
        .iter()
        .fold(start, |acc, b| acc.wrapping_shl(8) | i64::from(*b)))
}

fn name(v: &[u8]) -> Result<String, &'static str> {
    component(whole(v, GENERAL_STRING)?)
}

fn component(s: &[u8]) -> Result<String, &'static str> {
    let printable = !s.is_empty()
        && s.len() <= MAX_NAME
        && s.iter()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'/' | b'@'));
    if printable {
        core::str::from_utf8(s)
            .map(String::from)
            .map_err(|_| MALFORMED)
    } else {
        Err(MALFORMED)
    }
}

struct Ticket {
    realm: String,
    sname: String,
    etype: i32,
    kvno: Option<u32>,
}

fn ticket(v: &[u8]) -> Result<Ticket, &'static str> {
    let mut t = reader(whole(whole(v, TICKET)?, SEQUENCE)?)?;
    if integer(context(&mut t, 0)?)? != 5 {
        return Err(MALFORMED);
    }
    let realm = name(context(&mut t, 1)?)?;
    let mut sname = reader(whole(context(&mut t, 2)?, SEQUENCE)?)?;
    integer(context(&mut sname, 0)?)?;
    let mut parts = reader(whole(context(&mut sname, 1)?, SEQUENCE)?)?;
    let mut components = Vec::new();
    while !parts.is_empty() {
        let tlv = parts.next_tlv().map_err(|_| MALFORMED)?;
        if tlv.tag != GENERAL_STRING || components.len() >= 4 {
            return Err(MALFORMED);
        }
        components.push(component(tlv.value)?);
    }
    if components.is_empty() || !sname.is_empty() {
        return Err(MALFORMED);
    }
    let mut enc = reader(whole(context(&mut t, 3)?, SEQUENCE)?)?;
    if !t.is_empty() {
        return Err(MALFORMED);
    }
    let etype = i32::try_from(integer(context(&mut enc, 0)?)?).map_err(|_| MALFORMED)?;
    let mut kvno = None;
    let mut next = enc.next_tlv().map_err(|_| MALFORMED)?;
    if next.tag == 0xa1 {
        kvno = Some(u32::try_from(integer(next.value)?).map_err(|_| MALFORMED)?);
        next = enc.next_tlv().map_err(|_| MALFORMED)?;
    }
    if next.tag != 0xa2 || whole(next.value, OCTET_STRING)?.is_empty() || !enc.is_empty() {
        return Err(MALFORMED);
    }
    Ok(Ticket {
        realm,
        sname: components.join("/"),
        etype,
        kvno,
    })
}

/// The AP-REQ inside a Kerberos GSS-API initial context token (RFC 4121 §4.1).
fn krb5(token: &[u8]) -> Result<Token, &'static str> {
    let mut inner = reader(whole(token, GSS_TOKEN)?)?;
    let mech = inner.tagged(OID).map_err(|_| MALFORMED)?;
    if mech != OID_KRB5 && mech != OID_MS_KRB5 {
        return Err(MECH);
    }
    let rest = inner_rest(token, mech.len())?;
    let (id, ap) = rest.split_at_checked(2).ok_or(MALFORMED)?;
    if id != TOK_AP_REQ {
        return Err(MALFORMED);
    }
    let mut req = reader(whole(whole(ap, AP_REQ)?, SEQUENCE)?)?;
    if integer(context(&mut req, 0)?)? != 5 || integer(context(&mut req, 1)?)? != 14 {
        return Err(MALFORMED);
    }
    whole(context(&mut req, 2)?, BIT_STRING)?;
    let t = ticket(context(&mut req, 3)?)?;
    context(&mut req, 4)?;
    if !req.is_empty() {
        return Err(MALFORMED);
    }
    Ok(Token {
        mech: Mech::Kerberos,
        realm: t.realm,
        sname: t.sname,
        etype: t.etype,
        kvno: t.kvno,
        krb5: token.to_vec(),
    })
}

/// What follows the mechanism OID inside a GSS-API initial context token: raw bytes, not DER.
fn inner_rest(token: &[u8], oid_len: usize) -> Result<&[u8], &'static str> {
    let body = whole(token, GSS_TOKEN)?;
    let skip = oid_len.checked_add(2).ok_or(MALFORMED)?;
    body.get(skip..).ok_or(MALFORMED)
}

fn neg_token_init(v: &[u8]) -> Result<Token, &'static str> {
    let mut init = reader(whole(v, SEQUENCE)?)?;
    let mut types = reader(whole(context(&mut init, 0)?, SEQUENCE)?)?;
    let first = types.tagged(OID).map_err(|_| MALFORMED)?;
    if first == OID_NTLM {
        return Ok(Token::ntlm());
    }
    if first != OID_KRB5 && first != OID_MS_KRB5 {
        return Err(MECH);
    }
    let mut mech_token = None;
    while !init.is_empty() {
        let tlv = init.next_tlv().map_err(|_| MALFORMED)?;
        match tlv.tag {
            0xa1 | 0xa3 => {}
            0xa2 => mech_token = Some(whole(tlv.value, OCTET_STRING)?),
            _ => return Err(MALFORMED),
        }
    }
    krb5(mech_token.ok_or(MECH)?)
}

/// Reads `input`, a decoded `Negotiate` token.
///
/// # Errors
/// `der-too-large`, `spnego-malformed`, or `spnego-mech` for a mechanism other than Kerberos
/// and NTLM or a Kerberos offer without its token.
pub(crate) fn read(input: &[u8]) -> Result<(Summary, Vec<u8>), &'static str> {
    if input.len() > MAX_DER {
        return Err("der-too-large");
    }
    let token = if input.starts_with(NTLMSSP) {
        Token::ntlm()
    } else {
        let mut outer = reader(whole(input, GSS_TOKEN)?)?;
        let mech = outer.tagged(OID).map_err(|_| MALFORMED)?;
        if mech == OID_SPNEGO {
            let init = outer.tagged(0xa0).map_err(|_| MALFORMED)?;
            if !outer.is_empty() {
                return Err(MALFORMED);
            }
            neg_token_init(init)?
        } else {
            krb5(input)?
        }
    };
    let summary = Summary {
        elements: 1,
        depth: 1,
        root: String::new(),
    };
    Ok((summary, token.encode()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = value.len();
        if len < 0x80 {
            out.push(u8::try_from(len).unwrap());
        } else if len < 0x100 {
            out.extend([0x81, u8::try_from(len).unwrap()]);
        } else {
            out.extend([0x82]);
            out.extend(u16::try_from(len).unwrap().to_be_bytes());
        }
        out.extend_from_slice(value);
        out
    }

    fn int(n: u8) -> Vec<u8> {
        tlv(INTEGER, &[n])
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    /// A Kerberos initial context token with an AP-REQ whose ticket is for `sname` under
    /// `etype`; the ciphertexts are filler, nothing is encrypted.
    pub(crate) fn ap_req(mech: &[u8], sname: &[&str], etype: u8, kvno: Option<u8>) -> Vec<u8> {
        let names = cat(&sname
            .iter()
            .map(|s| tlv(GENERAL_STRING, s.as_bytes()))
            .collect::<Vec<_>>());
        let principal = tlv(
            SEQUENCE,
            &cat(&[tlv(0xa0, &int(2)), tlv(0xa1, &tlv(SEQUENCE, &names))]),
        );
        let mut enc = vec![tlv(0xa0, &int(etype))];
        if let Some(k) = kvno {
            enc.push(tlv(0xa1, &int(k)));
        }
        enc.push(tlv(0xa2, &tlv(OCTET_STRING, &[0x42; 48])));
        let ticket = tlv(
            TICKET,
            &tlv(
                SEQUENCE,
                &cat(&[
                    tlv(0xa0, &int(5)),
                    tlv(0xa1, &tlv(GENERAL_STRING, b"CORP.EXAMPLE")),
                    tlv(0xa2, &principal),
                    tlv(0xa3, &tlv(SEQUENCE, &cat(&enc))),
                ]),
            ),
        );
        let authenticator = tlv(
            SEQUENCE,
            &cat(&[
                tlv(0xa0, &int(etype)),
                tlv(0xa2, &tlv(OCTET_STRING, &[0x24; 32])),
            ]),
        );
        let req = tlv(
            AP_REQ,
            &tlv(
                SEQUENCE,
                &cat(&[
                    tlv(0xa0, &int(5)),
                    tlv(0xa1, &int(14)),
                    tlv(0xa2, &tlv(BIT_STRING, &[0, 0x20, 0, 0, 0])),
                    tlv(0xa3, &ticket),
                    tlv(0xa4, &authenticator),
                ]),
            ),
        );
        tlv(GSS_TOKEN, &cat(&[tlv(OID, mech), TOK_AP_REQ.to_vec(), req]))
    }

    pub(crate) fn spnego(mechs: &[&[u8]], token: Option<&[u8]>) -> Vec<u8> {
        let types = cat(&mechs.iter().map(|m| tlv(OID, m)).collect::<Vec<_>>());
        let mut init = vec![tlv(0xa0, &tlv(SEQUENCE, &types))];
        if let Some(t) = token {
            init.push(tlv(0xa2, &tlv(OCTET_STRING, t)));
        }
        tlv(
            GSS_TOKEN,
            &cat(&[tlv(OID, OID_SPNEGO), tlv(0xa0, &tlv(SEQUENCE, &cat(&init)))]),
        )
    }

    fn summary(input: &[u8]) -> Result<Token, &'static str> {
        read(input).map(|(_, out)| Token::decode(&out).unwrap())
    }

    // IDP-17, OP-155 m.3 (o), RR-28
    #[test]
    fn a_kerberos_offer_yields_its_ticket_facts() {
        let inner = ap_req(OID_KRB5, &["HTTP", "access.corp.example"], 18, Some(3));
        let t = summary(&spnego(&[OID_MS_KRB5, OID_NTLM], Some(&inner))).unwrap();
        assert_eq!(t.mech, Mech::Kerberos);
        assert_eq!(t.spn(), "HTTP/access.corp.example@CORP.EXAMPLE");
        assert_eq!((t.etype, t.kvno), (18, Some(3)));
        assert_eq!(t.krb5, inner);
        let raw = summary(&inner).unwrap();
        assert_eq!(raw.spn(), t.spn());
        let rc4 = summary(&ap_req(
            OID_KRB5,
            &["HTTP", "access.corp.example"],
            23,
            None,
        ))
        .unwrap();
        assert_eq!((rc4.etype, rc4.kvno), (23, None));
    }

    // IDP-17
    #[test]
    fn ntlm_is_summarised_as_ntlm() {
        let mut raw = NTLMSSP.to_vec();
        raw.extend_from_slice(&[1, 0, 0, 0, 0x07, 0x82, 0x08, 0xa2]);
        assert_eq!(summary(&raw).unwrap().mech, Mech::Ntlm);
        let offered = spnego(&[OID_NTLM, OID_KRB5], None);
        assert_eq!(summary(&offered).unwrap().mech, Mech::Ntlm);
    }

    // RR-28, OP-155 m.3 (c)
    #[test]
    fn anything_else_is_refused() {
        let inner = ap_req(OID_KRB5, &["HTTP", "access.corp.example"], 18, Some(3));
        assert_eq!(summary(&spnego(&[OID_KRB5], None)), Err(MECH));
        assert_eq!(
            summary(&spnego(&[&[0x2b, 0x06, 0x01]], Some(&inner))),
            Err(MECH)
        );
        let mut trailing = spnego(&[OID_KRB5], Some(&inner));
        trailing.push(0);
        assert_eq!(summary(&trailing), Err(MALFORMED));
        let mut cut = inner.clone();
        cut.truncate(cut.len() - 3);
        assert_eq!(summary(&cut), Err(MALFORMED));
        assert_eq!(summary(&[0x60, 0x80, 0x00, 0x00]), Err(MALFORMED));
        assert_eq!(summary(&vec![0x60; MAX_DER + 1]), Err("der-too-large"));
        let five = ap_req(OID_KRB5, &["a", "b", "c", "d", "e"], 18, Some(1));
        assert_eq!(summary(&five), Err(MALFORMED));
    }
}
