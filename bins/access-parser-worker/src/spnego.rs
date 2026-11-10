//! `spnego.read` (OP-155 m.3 (o), RR-28): the Kerberos gateway's `Negotiate` token, read by
//! [`access_parse::spnego`] in this worker into its [`Token`] summary.

use access_edge_core::ipc::Summary;
use access_edge_core::spnego::{Mech, Token};
use access_parse::spnego::{Offer, SpnegoError, read as parse};

/// Reads `input`, a decoded `Negotiate` token.
///
/// # Errors
/// `der-too-large`, `spnego-malformed`, or `spnego-mech` for a mechanism other than Kerberos
/// and NTLM or a Kerberos offer without its token.
pub(crate) fn read(input: &[u8]) -> Result<(Summary, Vec<u8>), &'static str> {
    let token = match parse(input) {
        Ok(Offer::Ntlm) => Token::ntlm(),
        Ok(Offer::Kerberos(t)) => Token {
            mech: Mech::Kerberos,
            realm: t.realm,
            sname: t.sname,
            etype: t.etype,
            kvno: t.kvno,
            krb5: t.token.to_vec(),
        },
        Err(SpnegoError::TooLarge) => return Err("der-too-large"),
        Err(SpnegoError::Malformed) => return Err("spnego-malformed"),
        Err(SpnegoError::Mech) => return Err("spnego-mech"),
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

    // IDP-17, RR-28
    #[test]
    fn refusals_keep_their_codes_and_ntlm_is_summarised() {
        let (_, out) = read(b"NTLMSSP\0\x01\0\0\0").unwrap();
        assert_eq!(Token::decode(&out).unwrap().mech, Mech::Ntlm);
        assert_eq!(read(&[0x60, 0x80, 0, 0]), Err("spnego-malformed"));
        assert_eq!(read(&vec![0x60; 8 * 1024 + 1]), Err("der-too-large"));
    }
}
