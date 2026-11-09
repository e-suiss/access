//! OP-72 instruction counts of what an agent's token refresh costs in pure code (AG-22,
//! §11.9.4, OP-154 m.3 (h)): the DPoP proof the token endpoint verifies on every refresh, the
//! proof a resource server verifies with the token, and the `projection.issue` decision.
//!
//! Load profile (§17): an agent Instance's bounds token lives at most 15 minutes, so N live
//! Instances refresh at N / 900 s, each refresh one `projection.issue` commit. Against the
//! sustained commit target of 2,000/s per domain, one domain carries 1.8 million Instances at
//! the 15-minute horizon and 600,000 at 5 minutes; these counts are the per-refresh CPU side
//! of that budget, and a regression above the gate moves it.

#![allow(
    missing_docs,
    reason = "gungraun macros generate undocumented public items in this bench binary"
)]

#[cfg(target_os = "linux")]
#[path = "support/fixtures.rs"]
#[expect(dead_code, reason = "the agent benches use only the decision input")]
mod fixtures;

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::hint::black_box;

#[cfg(target_os = "linux")]
use access_kernel::combinator::codec::OwnedInput;
#[cfg(target_os = "linux")]
use access_kernel::combinator::{Fuel, evaluate};
#[cfg(target_os = "linux")]
use access_kernel::json::b64url_encode;
#[cfg(target_os = "linux")]
use access_kernel::verify::PureBackend;
#[cfg(target_os = "linux")]
use access_kernel::verify::cose::Algorithm;
#[cfg(target_os = "linux")]
use access_kernel::verify::dpop::{ProofRules, ath, verify_proof};
#[cfg(target_os = "linux")]
use gungraun::{library_benchmark, library_benchmark_group, main};

#[cfg(target_os = "linux")]
const NOW: u64 = 1_800_000_000_000;
#[cfg(target_os = "linux")]
const TOKEN_URI: &str = "https://access.example/realms/acme/token";
#[cfg(target_os = "linux")]
const MCP_URI: &str = "https://mcp.example/mcp";
#[cfg(target_os = "linux")]
const TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.c2lnbmF0dXJl";

/// One refresh's inputs: the proof, the URI it is for, the access token it carries, and the
/// key thumbprint its refresh family is bound to.
#[cfg(target_os = "linux")]
struct Refresh {
    proof: String,
    uri: &'static str,
    token: Option<&'static str>,
    bound: [u8; 32],
}

#[cfg(target_os = "linux")]
fn proof(uri: &'static str, token: Option<&'static str>) -> Refresh {
    use ed25519_dalek::Signer as _;
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let x = b64url_encode(&key.verifying_key().to_bytes());
    let header = format!(
        r#"{{"typ":"dpop+jwt","alg":"Ed25519","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}}}"#
    );
    let ath = token.map_or_else(String::new, |t| format!(r#","ath":"{}""#, ath(t)));
    let payload = format!(
        r#"{{"jti":"refresh-1","htm":"POST","htu":"{uri}","iat":{}{ath}}}"#,
        NOW / 1000
    );
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = key.sign(input.as_bytes()).to_bytes();
    let proof = format!("{input}.{}", b64url_encode(&sig));
    let allowed = allowed();
    let bound = verify_proof(&PureBackend, &proof, &rules(uri, token, &allowed, None))
        .map(|p| p.jkt)
        .unwrap_or_default();
    Refresh {
        proof,
        uri,
        token,
        bound,
    }
}

#[cfg(target_os = "linux")]
fn allowed() -> BTreeSet<Algorithm> {
    [Algorithm::Es256, Algorithm::Ed25519].into_iter().collect()
}

#[cfg(target_os = "linux")]
fn rules<'a>(
    uri: &'a str,
    token: Option<&'a str>,
    allowed: &'a BTreeSet<Algorithm>,
    bound: Option<&'a [u8; 32]>,
) -> ProofRules<'a> {
    ProofRules {
        method: "POST",
        uri,
        allowed,
        now: NOW,
        lifetime_ms: 60_000,
        skew_ms: 5_000,
        access_token: token,
        bound_jkt: bound,
    }
}

#[cfg(target_os = "linux")]
fn release<T>(out: (bool, T)) {
    black_box(out.0);
    drop(out.1);
}

#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::token_endpoint(args = (proof(TOKEN_URI, None)), teardown = release)]
#[bench::resource_server(args = (proof(MCP_URI, Some(TOKEN))), teardown = release)]
fn dpop_proof(r: Refresh) -> (bool, Refresh) {
    let allowed = allowed();
    let ok = verify_proof(
        &PureBackend,
        black_box(&r.proof),
        &rules(r.uri, r.token, &allowed, Some(&r.bound)),
    )
    .is_ok();
    (ok, r)
}

#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::allow(args = (fixtures::decision_input("allow")), teardown = release)]
fn projection_decision(input: Option<OwnedInput>) -> (bool, Option<OwnedInput>) {
    let ok = input
        .as_ref()
        .is_some_and(|i| evaluate(black_box(&i.input()), &mut Fuel(10_000)).is_ok());
    (ok, input)
}

#[cfg(target_os = "linux")]
library_benchmark_group!(
    name = agent_tokens,
    benchmarks = [dpop_proof, projection_decision]
);

#[cfg(target_os = "linux")]
main!(library_benchmark_groups = agent_tokens);

#[cfg(not(target_os = "linux"))]
fn main() {}
