use serde_json::Value;

use super::issuer::{Issuer, IssuerError, IssuerStyle, RealmBase, check_slug, with_iss};
use super::metadata::{
    Document, Endpoint, Feature, SERVED, Served, authorization_server, paths, protected_resource,
};

fn json(s: &str) -> serde_json::Map<String, Value> {
    match serde_json::from_str(s).unwrap() {
        Value::Object(m) => m,
        other => panic!("{other}"),
    }
}

// TN-10, §17.9.6: only a canonical https issuer is accepted; nothing is normalised
#[test]
fn issuers_are_canonical_https_urls() {
    for ok in [
        "https://acme.id.example",
        "https://acme.id.localhost:8443",
        "https://id.example/realms/acme",
    ] {
        assert_eq!(Issuer::parse(ok).unwrap().as_str(), ok);
    }
    for (bad, why) in [
        ("http://acme.id.example", IssuerError::Scheme),
        ("https://Acme.id.example", IssuerError::Authority),
        ("https://acme.id.example/", IssuerError::Path),
        ("https://acme.id.example//x", IssuerError::Path),
        ("https://acme.id.example/a/../b", IssuerError::Path),
        ("https://acme.id.example?x=1", IssuerError::Extra),
        ("https://u@acme.id.example", IssuerError::Extra),
        ("https://acme.id.example#f", IssuerError::Extra),
        ("https://acme.id.example:0", IssuerError::Authority),
        ("https://acme.id.example:99999", IssuerError::Authority),
        ("https://-acme.id.example", IssuerError::Authority),
        ("https://", IssuerError::Authority),
    ] {
        assert_eq!(Issuer::parse(bad), Err(why), "{bad}");
    }
    let long = format!("https://{}.example", "a".repeat(250));
    assert_eq!(Issuer::parse(&long), Err(IssuerError::Length));
}

// TN-10, TN-16: a new realm's issuer is the subdomain by default, the path form when chosen
#[test]
fn realm_issuers_are_formed_from_the_slug() {
    let base = RealmBase::parse("https://id.example").unwrap();
    let sub = base.issuer("acme", IssuerStyle::Subdomain).unwrap();
    assert_eq!(sub.as_str(), "https://acme.id.example");
    assert_eq!((sub.authority(), sub.path()), ("acme.id.example", ""));
    let path = base.issuer("acme", IssuerStyle::Path).unwrap();
    assert_eq!(path.as_str(), "https://id.example/realms/acme");
    assert_eq!(path.path(), "/realms/acme");
    let local = RealmBase::parse("https://localhost:8443").unwrap();
    assert_eq!(
        local
            .issuer("acme", IssuerStyle::Subdomain)
            .unwrap()
            .as_str(),
        "https://acme.localhost:8443"
    );
    assert_eq!(
        RealmBase::parse("https://id.example/x"),
        Err(IssuerError::Path)
    );
    for slug in ["ab", "-acme", "acme-", "Acme", "ac_me"] {
        assert_eq!(check_slug(slug), Err(IssuerError::Slug), "{slug}");
        assert!(base.issuer(slug, IssuerStyle::Subdomain).is_err());
    }
}

// §17.9.6: an issuer serves only the origin it names; the default port is the same origin
#[test]
fn an_issuer_serves_its_own_origin_only() {
    let i = Issuer::parse("https://acme.id.example").unwrap();
    assert!(i.serves("acme.id.example"));
    assert!(i.serves("ACME.id.example:443"));
    assert!(!i.serves("acme.id.example:8443"));
    assert!(!i.serves("evil.example"));
}

// RFC 9207, TN-11, AG-7: `iss` is appended byte-identical to the issuer, form-encoded
#[test]
fn the_iss_parameter_carries_the_issuer() {
    let i = Issuer::parse("https://id.example/realms/acme").unwrap();
    assert_eq!(
        with_iss("https://rp.example/cb", &i),
        "https://rp.example/cb?iss=https%3A%2F%2Fid.example%2Frealms%2Facme"
    );
    assert_eq!(
        with_iss("https://rp.example/cb?code=x&state=y", &i),
        "https://rp.example/cb?code=x&state=y&iss=https%3A%2F%2Fid.example%2Frealms%2Facme"
    );
}

// §10.4.6, §11.4.5: today only the issuer and the JWKS are declared; nothing unserved is
const NONE: Served = Served {
    endpoints: &[],
    features: &[],
};

#[test]
fn only_served_endpoints_are_declared() {
    let i = Issuer::parse("https://acme.id.example").unwrap();
    assert_eq!(SERVED, NONE);
    let m = json(&authorization_server(&i, &SERVED));
    let keys: Vec<&str> = m.keys().map(String::as_str).collect();
    assert_eq!(keys, ["issuer", "jwks_uri"]);
    assert_eq!(m["jwks_uri"], "https://acme.id.example/jwks.json");
}

// §11.4.5 Access corrections, MD-3, RFC 9207, TN-11: once served, the corrected fields appear
#[test]
fn served_endpoints_carry_the_access_corrections() {
    let all = Served {
        endpoints: &[
            Endpoint::Authorize,
            Endpoint::Token,
            Endpoint::Par,
            Endpoint::Userinfo,
            Endpoint::Revoke,
            Endpoint::Introspect,
        ],
        features: &[Feature::Dpop, Feature::ClientIdMetadataDocument],
    };
    let i = Issuer::parse("https://id.example/realms/acme").unwrap();
    let m = json(&authorization_server(&i, &all));
    assert_eq!(
        m["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert_eq!(m["authorization_response_iss_parameter_supported"], true);
    assert_eq!(m["client_id_metadata_document_supported"], true);
    assert_eq!(
        m["dpop_signing_alg_values_supported"],
        serde_json::json!(["ES256", "Ed25519"])
    );
    assert_eq!(
        m["token_endpoint_auth_signing_alg_values_supported"],
        serde_json::json!(["ES256", "RS256"])
    );
    assert_eq!(
        m["token_endpoint_auth_methods_supported"],
        serde_json::json!(["none", "private_key_jwt", "client_secret_basic"])
    );
    assert_eq!(m["response_types_supported"], serde_json::json!(["code"]));
    assert_eq!(
        m["subject_types_supported"],
        serde_json::json!(["pairwise"])
    );
    for (key, path) in [
        ("authorization_endpoint", "/authorize"),
        ("token_endpoint", "/token"),
        ("pushed_authorization_request_endpoint", "/par"),
        ("userinfo_endpoint", "/userinfo"),
        ("revocation_endpoint", "/revoke"),
        ("introspection_endpoint", "/introspect"),
    ] {
        assert_eq!(m[key], format!("https://id.example/realms/acme{path}"));
    }
    let text = authorization_server(&i, &all);
    assert!(!text.contains("EdDSA"), "{text}");
}

// RFC 9728, §9.4 A: the realm's resource names the realm as its authorization server
#[test]
fn protected_resource_metadata_names_the_realm() {
    let i = Issuer::parse("https://acme.id.example").unwrap();
    let m = json(&protected_resource(&i, &SERVED));
    assert_eq!(m["resource"], "https://acme.id.example");
    assert_eq!(
        m["authorization_servers"],
        serde_json::json!(["https://acme.id.example"])
    );
    assert!(!m.contains_key("dpop_signing_alg_values_supported"));
}

// TN-10, §11.4.5: a path issuer serves both OIDC well-known variants and the inserted RFC 8414 and
// RFC 9728 paths; a host issuer serves one path each
#[test]
fn path_issuers_serve_every_well_known_variant() {
    let p = Issuer::parse("https://id.example/realms/acme").unwrap();
    assert_eq!(
        paths(&p, Document::OpenIdConfiguration),
        [
            "/.well-known/openid-configuration/realms/acme",
            "/realms/acme/.well-known/openid-configuration"
        ]
    );
    assert_eq!(
        paths(&p, Document::AuthorizationServer),
        ["/.well-known/oauth-authorization-server/realms/acme"]
    );
    assert_eq!(
        paths(&p, Document::ProtectedResource),
        ["/.well-known/oauth-protected-resource/realms/acme"]
    );
    assert_eq!(paths(&p, Document::Jwks), ["/realms/acme/jwks.json"]);
    let h = Issuer::parse("https://acme.id.example").unwrap();
    assert_eq!(
        paths(&h, Document::OpenIdConfiguration),
        ["/.well-known/openid-configuration"]
    );
    assert_eq!(paths(&h, Document::Jwks), ["/jwks.json"]);
}
