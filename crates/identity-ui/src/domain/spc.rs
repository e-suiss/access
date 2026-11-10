//! Secure Payment Confirmation on the Approval Surface (W3C SPC, §9.4 G, §9.4.1, OP-156 m.3 (g)):
//! what the browser shows is derived from the canonical render the decision point produced, and
//! a `payment.get` assertion counts only when its `clientDataJSON.payment` carries exactly those
//! bytes. A render without an amount and a payee is no payment; it is approved with a passkey.

use access_kernel::json::{Json, parse};
use access_kernel::render::Render;
use serde_json::{Value, json};

/// The Approval Surface's `Permissions-Policy` once the realm decided `idp.realm.spc`: the
/// hosted login's, with `payment` opened to its own origin only.
pub const SPC_PERMISSIONS_POLICY: &str = "publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(), microphone=(), geolocation=(), payment=(self)";

/// The render field of the amount.
pub const AMOUNT: &str = "amount";
/// The render field of the payee's name.
pub const PAYEE: &str = "payee";
/// The render field of the payee's origin, when the payee has one.
pub const PAYEE_ORIGIN: &str = "payee_origin";
/// The render field of the payment instrument's name.
pub const INSTRUMENT: &str = "instrument";

/// Longest `clientDataJSON` read.
const MAX_CLIENT_DATA: usize = 4096;

/// What SPC shows, as the canonical render says it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Display {
    /// `payeeName`.
    pub payee_name: String,
    /// `payeeOrigin`.
    pub payee_origin: Option<String>,
    /// `total.currency`, ISO 4217.
    pub currency: String,
    /// `total.value`, a decimal in major units.
    pub value: String,
    /// `instrument.displayName`.
    pub instrument: String,
}

/// The minor-unit exponent of an ISO 4217 currency.
fn exponent(currency: &str) -> u32 {
    match currency {
        "BIF" | "CLP" | "DJF" | "GNF" | "ISK" | "JPY" | "KMF" | "KRW" | "PYG" | "RWF" | "UGX"
        | "UYI" | "VND" | "VUV" | "XAF" | "XOF" | "XPF" => 0,
        "BHD" | "IQD" | "JOD" | "KWD" | "LYD" | "OMR" | "TND" => 3,
        _ => 2,
    }
}

/// `"<minor units> <CURRENCY>"`, the render's amount text, as SPC's `{currency, value}`.
fn total(text: &str) -> Option<(String, String)> {
    let (minor, unit) = text.split_once(' ')?;
    let currency = unit.to_ascii_uppercase();
    if currency.len() != 3 || !currency.bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    if minor.is_empty() || !minor.bytes().all(|b| b.is_ascii_digit()) || minor.len() > 18 {
        return None;
    }
    let digits = usize::try_from(exponent(&currency)).ok()?;
    let padded = format!("{minor:0>width$}", width = digits.saturating_add(1));
    let split = padded.len().checked_sub(digits)?;
    let (major, fraction) = padded.split_at(split);
    let value = if fraction.is_empty() {
        major.to_owned()
    } else {
        format!("{major}.{fraction}")
    };
    Some((currency, value))
}

/// The SPC display of `render`, `None` when it is not a payment: no amount in a currency or no
/// payee. The instrument is the render's, or `realm_name`.
#[must_use]
pub fn display(render: &Render, realm_name: &str) -> Option<Display> {
    let field = |name: &str| {
        render
            .fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.text.clone())
    };
    let (currency, value) = total(&field(AMOUNT)?)?;
    let payee_name = field(PAYEE).filter(|p| !p.is_empty())?;
    Some(Display {
        payee_name,
        payee_origin: field(PAYEE_ORIGIN),
        currency,
        value,
        instrument: field(INSTRUMENT).unwrap_or_else(|| realm_name.to_owned()),
    })
}

impl Display {
    /// The `secure-payment-confirmation` request data the page hands the browser, without the
    /// challenge and credentials it already has.
    #[must_use]
    pub fn request(&self, icon: &str) -> Value {
        let mut v = json!({
            "payeeName": self.payee_name,
            "total": { "currency": self.currency, "value": self.value },
            "instrument": { "displayName": self.instrument, "icon": icon, "iconMustBeShown": false },
        });
        if let (Some(o), Some(m)) = (&self.payee_origin, v.as_object_mut()) {
            m.insert(String::from("payeeOrigin"), json!(o));
        }
        v
    }
}

/// Whether `client_data_json` is a `payment.get` whose `payment` member names `rp_id`, the
/// surface's own `top_origin`, and byte for byte the payee, the total and the instrument name of
/// `shown`.
#[must_use]
pub fn shown_matches(
    client_data_json: &[u8],
    shown: &Display,
    rp_id: &str,
    top_origin: &str,
) -> bool {
    let Ok(json) = parse(client_data_json, MAX_CLIENT_DATA) else {
        return false;
    };
    let text = |j: Option<&Json>| j.and_then(Json::as_str).map(str::to_owned);
    if text(json.get("type")).as_deref() != Some("payment.get") {
        return false;
    }
    let Some(p) = json.get("payment") else {
        return false;
    };
    let total = p.get("total");
    let instrument = p.get("instrument");
    text(p.get("rpId")).as_deref() == Some(rp_id)
        && text(p.get("topOrigin")).as_deref() == Some(top_origin)
        && text(p.get("payeeName")).as_deref() == Some(shown.payee_name.as_str())
        && text(p.get("payeeOrigin")) == shown.payee_origin
        && text(total.and_then(|t| t.get("currency"))).as_deref() == Some(shown.currency.as_str())
        && text(total.and_then(|t| t.get("value"))).as_deref() == Some(shown.value.as_str())
        && text(instrument.and_then(|i| i.get("displayName"))).as_deref()
            == Some(shown.instrument.as_str())
}

/// The `type` of a `clientDataJSON`, when it reads.
#[must_use]
pub fn ceremony(client_data_json: &[u8]) -> Option<String> {
    let json = parse(client_data_json, MAX_CLIENT_DATA).ok()?;
    json.get("type").and_then(Json::as_str).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use access_kernel::digest::Digest;
    use access_kernel::render::Field;

    fn render(fields: &[(&str, &str)]) -> Render {
        Render {
            schema: Digest([1; 32]),
            intent: Digest([2; 32]),
            locale: String::from("en"),
            template: None,
            fields: fields
                .iter()
                .map(|(n, t)| Field {
                    name: (*n).to_owned(),
                    text: (*t).to_owned(),
                    material: true,
                })
                .collect(),
            reversibility: None,
        }
    }

    fn client(payment: &Value) -> Vec<u8> {
        json!({
            "type": "payment.get",
            "challenge": "AA",
            "origin": "https://acme.example",
            "payment": payment,
        })
        .to_string()
        .into_bytes()
    }

    // §9.4.1, OP-156 m.3 (g)
    #[test]
    fn the_display_is_the_canonical_render_in_major_units() {
        let d = display(
            &render(&[("amount", "125050 try"), ("payee", "Kahve Evi")]),
            "Acme",
        )
        .unwrap();
        assert_eq!((d.currency.as_str(), d.value.as_str()), ("TRY", "1250.50"));
        assert_eq!(d.instrument, "Acme");
        let yen = display(&render(&[("amount", "7 jpy"), ("payee", "x")]), "A").unwrap();
        assert_eq!(yen.value, "7");
        let small = display(&render(&[("amount", "5 eur"), ("payee", "x")]), "A").unwrap();
        assert_eq!(small.value, "0.05");
        assert!(display(&render(&[("amount", "5 eur")]), "A").is_none());
        assert!(display(&render(&[("amount", "-5 eur"), ("payee", "x")]), "A").is_none());
        assert!(display(&render(&[("amount", "5 euro"), ("payee", "x")]), "A").is_none());
    }

    // §9.4.1, OP-156 m.3 (g), Ek B 5120
    #[test]
    fn a_different_amount_is_no_confirmation() {
        let d = display(
            &render(&[
                ("amount", "4200 eur"),
                ("payee", "Shop"),
                ("payee_origin", "https://shop.example"),
            ]),
            "Acme",
        )
        .unwrap();
        let shown = |value: &str| {
            json!({
                "rpId": "acme.example",
                "topOrigin": "https://acme.example",
                "payeeName": "Shop",
                "payeeOrigin": "https://shop.example",
                "total": { "currency": "EUR", "value": value },
                "instrument": { "displayName": "Acme", "icon": "" },
            })
        };
        let top = "https://acme.example";
        assert!(shown_matches(
            &client(&shown("42.00")),
            &d,
            "acme.example",
            top
        ));
        assert!(!shown_matches(
            &client(&shown("43.00")),
            &d,
            "acme.example",
            top
        ));
        assert!(!shown_matches(
            &client(&shown("42")),
            &d,
            "acme.example",
            top
        ));
        assert!(!shown_matches(
            &client(&shown("42.00")),
            &d,
            "other.example",
            top
        ));
        assert!(!shown_matches(
            &client(&shown("42.00")),
            &d,
            "acme.example",
            "https://evil.example"
        ));
        let mut no_origin = shown("42.00");
        no_origin.as_object_mut().unwrap().remove("payeeOrigin");
        assert!(!shown_matches(&client(&no_origin), &d, "acme.example", top));
        let get = json!({"type": "webauthn.get", "payment": shown("42.00")}).to_string();
        assert!(!shown_matches(get.as_bytes(), &d, "acme.example", top));
        assert_eq!(
            ceremony(&client(&shown("1"))).as_deref(),
            Some("payment.get")
        );
    }
}
