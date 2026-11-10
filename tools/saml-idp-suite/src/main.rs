//! `saml-idp-suite`: run the suite's checks on files an IdP produced.
//!
//! ```text
//! saml-idp-suite response <response.xml> --idp <entity> --sp <entity> --acs <url>
//!                [--request-id <id>] [--profile <name>] [--now <unix seconds>]
//! saml-idp-suite metadata <metadata.xml> --idp <entity>
//! saml-idp-suite corpus <signed-request.xml> <out-dir> [--unsigned-refused] [--size-limit <bytes>]
//! saml-idp-suite profiles
//! ```
//!
//! `response` accepts the XML or its base64 (`SAMLResponse`) form. Exit status 1 means a check
//! failed, 2 a usage or input error.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool reports to the terminal"
)]

use std::path::Path;
use std::process::ExitCode;

use saml_idp_suite::encode::b64_decode;
use saml_idp_suite::profiles::{PROFILES, check_profile, profile};
use saml_idp_suite::request::{Options, corpus_of};
use saml_idp_suite::response::{Expectations, Finding, check_metadata, check_response};
use saml_idp_suite::{report, time};

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i.saturating_add(1)))
        .map(String::as_str)
}

fn usage() -> ExitCode {
    eprintln!("usage: saml-idp-suite response|metadata|corpus|profiles … (see the crate README)");
    ExitCode::from(2)
}

fn read(path: &str) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let t = raw.trim();
    if t.starts_with('<') {
        return Ok(raw);
    }
    b64_decode(t)
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| format!("{path}: neither XML nor base64 XML"))
}

fn finish(findings: &[Finding]) -> ExitCode {
    let (text, failed) = report(findings.iter().map(|f| (f.rule, f.ok, f.detail.as_str())));
    print!("{text}");
    println!("{} checks, {failed} failed", findings.len());
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn response(args: &[String]) -> Result<ExitCode, String> {
    let path = args.first().ok_or("missing response file")?;
    let xml = read(path)?;
    let need = |n: &str| {
        flag(args, n)
            .map(str::to_owned)
            .ok_or(format!("missing {n}"))
    };
    let e = Expectations {
        idp_entity: need("--idp")?,
        sp_entity: need("--sp")?,
        acs: need("--acs")?,
        request_id: flag(args, "--request-id").map(str::to_owned),
        now: match flag(args, "--now") {
            Some(n) => n.parse().map_err(|_| "--now is not a number")?,
            None => time::now(),
        },
        skew: 180,
        max_validity: 600,
    };
    let mut findings = check_response(&xml, &e);
    if let Some(name) = flag(args, "--profile") {
        let p = profile(name).ok_or(format!("unknown profile {name}"))?;
        findings.extend(check_profile(p, &xml));
    }
    Ok(finish(&findings))
}

fn metadata(args: &[String]) -> Result<ExitCode, String> {
    let path = args.first().ok_or("missing metadata file")?;
    let idp = flag(args, "--idp").ok_or("missing --idp")?;
    Ok(finish(&check_metadata(&read(path)?, idp)))
}

fn corpus(args: &[String]) -> Result<ExitCode, String> {
    let path = args.first().ok_or("missing signed request file")?;
    let out = Path::new(args.get(1).ok_or("missing output directory")?);
    let signed = read(path)?;
    let opts = Options {
        issuer: String::new(),
        acs: String::new(),
        destination: String::new(),
        signature_required: args.iter().any(|a| a == "--unsigned-refused"),
        replay: false,
        size_limit: match flag(args, "--size-limit") {
            Some(n) => Some(n.parse().map_err(|_| "--size-limit is not a number")?),
            None => None,
        },
    };
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let cases = corpus_of(&signed, &opts).map_err(|e| e.to_string())?;
    for (name, class, xml) in &cases {
        std::fs::write(out.join(format!("{name}.xml")), xml).map_err(|e| e.to_string())?;
        println!("{class}\t{name}.xml");
    }
    println!(
        "{} cases written; every one must be refused or answered for the signed values only",
        cases.len()
    );
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    let run = match args.first().map(String::as_str) {
        Some("response") => response(rest),
        Some("metadata") => metadata(rest),
        Some("corpus") => corpus(rest),
        Some("profiles") => {
            for p in PROFILES {
                println!("{}\t{}\t{}", p.name, p.counterpart, p.source);
            }
            Ok(ExitCode::SUCCESS)
        }
        _ => return usage(),
    };
    run.unwrap_or_else(|e| {
        eprintln!("saml-idp-suite: {e}");
        ExitCode::from(2)
    })
}
