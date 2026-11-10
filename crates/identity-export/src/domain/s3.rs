//! S3 and Amazon Security Lake objects of the copy (OP-156 m.3 (s), (z)): the object key of a
//! batch and the `PUT` signed with our own AWS Signature Version 4 (`UNSIGNED-PAYLOAD` is never
//! used; the body's SHA-256 is signed). The key is fixed by the batch's first row, so a retried
//! batch overwrites the same object.
//!
//! Key layout, as Security Lake's custom sources partition:
//! `{prefix}region={region}/accountId={account}/eventDay={YYYYMMDD}/{realm}-{xid}-{id}.parquet`
//! (`accountId` only when the sink names one).

use access_identity_oauth::adapters::outbound::Target;
use serde_json::{Map, Value};

use super::collector::Request;
use super::parquet::MEDIA_TYPE;
use super::sink::{SinkSecret, SinkSpec};

/// The default key prefix.
pub const PREFIX: &str = "ext/access/";

/// `x-amz-content-sha256`'s name.
pub const CONTENT_SHA256: &str = "x-amz-content-sha256";

fn text<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}

fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// URI-encodes a key's segments for the request path and the canonical URI (RFC 3986
/// unreserved characters stay, `/` separates).
#[must_use]
pub fn encode_key(key: &str) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(key.len());
    for b in key.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The object key of the batch whose first row is `(xid, id)`, occurred at `first_ms`.
#[must_use]
pub fn key(spec: &SinkSpec, realm: &str, (xid, id): (u64, i64), first_ms: u64) -> String {
    let m = &spec.settings;
    let account = text(m, "account_id").map_or_else(String::new, |a| format!("accountId={a}/"));
    format!(
        "{}region={}/{account}eventDay={}/{realm}-{xid}-{id}.parquet",
        text(m, "prefix").unwrap_or(PREFIX),
        text(m, "region").unwrap_or_default(),
        super::syslog::day(first_ms),
    )
}

/// `YYYYMMDD'T'HHMMSS'Z'` of `ms`.
#[must_use]
pub fn amz_date(ms: u64) -> String {
    let s = super::syslog::timestamp(ms);
    let digits: String = s.chars().take(19).filter(char::is_ascii_digit).collect();
    let (date, time) = digits.split_at(digits.len().min(8));
    format!("{date}T{time}Z")
}

/// The object's URL: below the endpoint with the bucket in the path when `path_style`, else on
/// the bucket's virtual host.
#[must_use]
pub fn url(spec: &SinkSpec, key: &str) -> Option<String> {
    let m = &spec.settings;
    let bucket = text(m, "bucket")?;
    let base = spec.endpoint.trim_end_matches('/');
    let path_style = m.get("path_style").and_then(Value::as_bool) == Some(true);
    let encoded = encode_key(key);
    if path_style {
        Some(format!("{base}/{bucket}/{encoded}"))
    } else {
        let rest = base.strip_prefix("https://")?;
        Some(format!("https://{bucket}.{rest}/{encoded}"))
    }
}

/// The host header value of `url` as the outbound client sends it.
fn host(url: &str) -> Option<(String, String)> {
    let t = Target::parse(url).ok()?;
    let canonical = t.canonical();
    let rest = canonical.strip_prefix("https://")?;
    let (host, path) = rest.split_at(rest.find('/')?);
    Some((String::from(host), String::from(path)))
}

/// The signed `PUT` of `body` at `key` at time `now_ms`.
#[must_use]
pub fn put(
    spec: &SinkSpec,
    secret: &SinkSecret,
    key: &str,
    body: Vec<u8>,
    now_ms: u64,
) -> Option<Request> {
    let m = &spec.settings;
    let region = text(m, "region")?;
    let akid = text(m, "access_key_id")?;
    let url = url(spec, key)?;
    let (host, path) = host(&url)?;
    let stamp = amz_date(now_ms);
    let date = stamp.get(..8)?;
    let payload = hex(&suiss_crypto::digest::sha256(&body));
    let signed = "host;x-amz-content-sha256;x-amz-date";
    let canonical = format!(
        "PUT\n{path}\n\nhost:{host}\n{CONTENT_SHA256}:{payload}\nx-amz-date:{stamp}\n\n{signed}\n{payload}"
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&suiss_crypto::digest::sha256(canonical.as_bytes()))
    );
    let sig =
        access_crypto::sigv4::signature(secret.expose().as_bytes(), (date, region, "s3"), &to_sign);
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={signed}, Signature={}",
        hex(&sig)
    );
    Some(Request {
        method: "PUT",
        url,
        content_type: MEDIA_TYPE,
        headers: vec![
            (
                String::from(super::copy::HEADER),
                String::from(super::copy::VALUE),
            ),
            (String::from(CONTENT_SHA256), payload),
            (String::from("x-amz-date"), stamp),
            (String::from("Authorization"), authorization),
        ],
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (s)
    #[test]
    fn keys_partition_by_region_account_and_day() {
        let mut settings = Map::new();
        settings.insert("bucket".into(), "audit-lake".into());
        settings.insert("region".into(), "eu-central-1".into());
        settings.insert("account_id".into(), "123456789012".into());
        settings.insert("access_key_id".into(), "AKID".into());
        let spec = SinkSpec {
            adapter: super::super::sink::Adapter::S3Parquet,
            preset: None,
            format: None,
            endpoint: String::from("https://s3.eu-central-1.amazonaws.com"),
            settings,
        };
        let k = key(&spec, "r1", (7, 9), 1_762_772_400_123);
        assert_eq!(
            k,
            "ext/access/region=eu-central-1/accountId=123456789012/eventDay=20251110/r1-7-9.parquet"
        );
        assert_eq!(
            url(&spec, &k).unwrap(),
            "https://audit-lake.s3.eu-central-1.amazonaws.com/ext/access/region%3Deu-central-1/accountId%3D123456789012/eventDay%3D20251110/r1-7-9.parquet"
        );
        assert_eq!(amz_date(1_762_772_400_123), "20251110T110000Z");
    }
}
