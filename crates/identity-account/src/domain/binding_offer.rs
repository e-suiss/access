//! The realm-signed binding offer (OP-153 m.18 (e), m.25 (b), §12.1.1, TN-65): the proof
//! `verified_idp_subject` of a cross-realm `IdentityBinding`. Realm A states, under its own JOSE
//! key, that one of its accounts was signed in through an upstream subject; realm B, where the
//! person signed in through the same upstream subject, verifies A's signature from A's JWKS and
//! compares the subject digest. No account id crosses the realms, only a random binding id and
//! the digest of the upstream subject both realms verified.
//!
//! The offer is a compact JWS with `typ` [`TYP`] whose claims are [`BindingOffer::claims`].

use access_kernel::json::{b64url_decode, b64url_encode};
use serde_json::{Value, json};

/// The JWS `typ` of a binding offer.
pub const TYP: &str = "binding-offer+jwt";

/// The proof a binding offer carries.
pub const VERIFIED_IDP_SUBJECT: &str = "verified_idp_subject";

/// How long an offer holds (PD, as an `invite_token` offer).
pub const OFFER_TTL_S: u64 = 600;

const SUBJECT_CONTEXT: &[u8] = b"access/binding-offer-subject/v1\0";

/// The digest both realms compute of an upstream subject: its issuer and `sub`.
#[must_use]
pub fn subject_digest(upstream_issuer: &str, sub: &str) -> [u8; 32] {
    let mut m = SUBJECT_CONTEXT.to_vec();
    m.extend_from_slice(upstream_issuer.as_bytes());
    m.push(0);
    m.extend_from_slice(sub.as_bytes());
    suiss_crypto::digest::sha256(&m)
}

/// What an offer states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingOffer {
    /// The offering realm's issuer: the JWS signer.
    pub issuer: String,
    /// The realm the offer is for.
    pub audience: String,
    /// The binding id both halves share.
    pub binding: [u8; 16],
    /// [`subject_digest`] of the upstream subject realm A verified.
    pub subject: [u8; 32],
    /// Issued at, Unix seconds.
    pub issued_at: u64,
    /// Expires at, Unix seconds.
    pub expires_at: u64,
}

/// Why an offer's claims are refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OfferRefused {
    /// Not the claim set of an offer.
    #[error("not a binding offer")]
    Shape,
    /// For another realm.
    #[error("binding offer for another realm")]
    Audience,
    /// Expired, not yet valid, or longer than an offer holds.
    #[error("binding offer out of its time")]
    Time,
}

impl BindingOffer {
    /// The JWS claims.
    #[must_use]
    pub fn claims(&self) -> Value {
        json!({
            "iss": self.issuer,
            "aud": self.audience,
            "binding": b64url_encode(&self.binding),
            "proof": VERIFIED_IDP_SUBJECT,
            "idp_subject": b64url_encode(&self.subject),
            "iat": self.issued_at,
            "exp": self.expires_at,
        })
    }

    /// Reads the claims of an offer whose signature the caller verified against `issuer`'s
    /// keys, for realm `audience` at `now_s`.
    ///
    /// # Errors
    /// [`OfferRefused`].
    pub fn from_claims(c: &Value, audience: &str, now_s: u64) -> Result<Self, OfferRefused> {
        let m = c.as_object().ok_or(OfferRefused::Shape)?;
        if m.len() != 7 || m.get("proof").and_then(Value::as_str) != Some(VERIFIED_IDP_SUBJECT) {
            return Err(OfferRefused::Shape);
        }
        let text = |k: &str| m.get(k).and_then(Value::as_str).ok_or(OfferRefused::Shape);
        let num = |k: &str| m.get(k).and_then(Value::as_u64).ok_or(OfferRefused::Shape);
        let raw = |k: &str| text(k).and_then(|t| b64url_decode(t).map_err(|_| OfferRefused::Shape));
        let offer = Self {
            issuer: String::from(text("iss")?),
            audience: String::from(text("aud")?),
            binding: <[u8; 16]>::try_from(raw("binding")?.as_slice())
                .map_err(|_| OfferRefused::Shape)?,
            subject: <[u8; 32]>::try_from(raw("idp_subject")?.as_slice())
                .map_err(|_| OfferRefused::Shape)?,
            issued_at: num("iat")?,
            expires_at: num("exp")?,
        };
        if offer.audience != audience || offer.issuer == audience {
            return Err(OfferRefused::Audience);
        }
        let span = offer.expires_at.checked_sub(offer.issued_at);
        if offer.issued_at > now_s
            || now_s >= offer.expires_at
            || span.is_none_or(|s| s > OFFER_TTL_S)
        {
            return Err(OfferRefused::Time);
        }
        Ok(offer)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn offer() -> BindingOffer {
        BindingOffer {
            issuer: String::from("https://a.example/realms/a"),
            audience: String::from("https://a.example/realms/b"),
            binding: [1; 16],
            subject: subject_digest("https://accounts.google.com", "1234"),
            issued_at: 1_000,
            expires_at: 1_000 + OFFER_TTL_S,
        }
    }

    // OP-153 m.18 (e), m.25 (b), TN-65
    #[test]
    fn an_offer_reads_back_only_for_its_realm_and_time() {
        let o = offer();
        let b = "https://a.example/realms/b";
        assert_eq!(
            BindingOffer::from_claims(&o.claims(), b, 1_001),
            Ok(o.clone())
        );
        assert_eq!(
            BindingOffer::from_claims(&o.claims(), "https://a.example/realms/c", 1_001),
            Err(OfferRefused::Audience)
        );
        assert_eq!(
            BindingOffer::from_claims(&o.claims(), b, o.expires_at),
            Err(OfferRefused::Time)
        );
        let mut long = o.clone();
        long.expires_at += 1;
        assert_eq!(
            BindingOffer::from_claims(&long.claims(), b, 1_001),
            Err(OfferRefused::Time)
        );
        let mut extra = o.claims();
        extra["sub"] = json!("acct");
        assert_eq!(
            BindingOffer::from_claims(&extra, b, 1_001),
            Err(OfferRefused::Shape)
        );
        assert_ne!(
            subject_digest("https://accounts.google.com", "1234"),
            subject_digest("https://accounts.google.co", "m1234")
        );
    }
}
