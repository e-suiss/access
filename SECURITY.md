# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository.

Do not open a public issue, pull request or discussion for a suspected vulnerability.

Please include:
- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected versions or components, if known.

A running server publishes the same contact at `/.well-known/security.txt` (RFC 9116). The project's own copy is [`security/security.txt`](security/security.txt).

## Coordinated disclosure

- We acknowledge your report, keep you informed while we investigate and agree a disclosure date with you.
- Every confirmed vulnerability gets a CVSS v4 score and an advisory.
- We credit reporters in the advisory unless they ask otherwise.
- Paid support never buys a fix. It covers early notice inside the embargo and help applying fixes; the fix itself ships to everyone at the same time.

## Supported versions

Every major version receives security fixes for at least 5 years from its first release. Within a major, the 2 newest minor versions receive fixes. A fix for an older supported minor is released from its maintenance branch, `release/v<major>.<minor>`. Versions before 1.0 form major 0.

| Version | Released | Security fixes until | Status |
|---|---|---|---|
| 0.7 | 2026-11-13 | 2031-10-29 | supported |
| 0.4 | 2026-11-09 | 2031-10-29 | supported |
| 0.3 | 2026-11-06 | 2026-11-13 | end-of-life |
| 0.2 | 2026-10-30 | 2026-11-09 | end-of-life |
| 0.1 | 2026-10-29 | 2026-11-06 | end-of-life |

## Fix times

We acknowledge a report within 3 days and assess it with a CVSS v4 score within 10 days. Disclosure is coordinated, with a default embargo of 90 days that is shortened when a vulnerability is actively exploited. The target time from a confirmed report to a released fix:

| Severity | CVSS v4 score | Fix released within |
|---|---|---|
| Critical | 9.0-10.0 | 14 days |
| High | 7.0-8.9 | 30 days |
| Medium | 4.0-6.9 | 60 days |
| Low | 0.1-3.9 | 90 days |

## Security fixes are released in the open

Every security fix is released from this public repository, from `main` or from the maintenance branch of a supported minor, under the same license as the rest of the code. A release is tagged only when its commit is on one of those branches and its CI run passed. Release binaries come with a software bill of materials, a VEX document, build provenance and Sigstore signatures, free of charge.

## Advisories

- **GitHub Security Advisories** on this repository are the primary channel. CVE IDs are requested through GitHub's CNA.
- **RustSec**: advisories for the published crates are also filed with the RustSec advisory database, after the fix is released.
- **npm**: advisories for the JavaScript packages reach npm through the GitHub Advisory Database.
- **OSV records**: every advisory is kept in [`security/advisories/`](security/advisories) as an [OSV](https://ossf.github.io/osv-schema/) record with its CVSS v4 vector.

## Incident reporting

For an actively exploited vulnerability or a severe incident that affects a release, we send an early warning within 24 hours of becoming aware of it, a notification within 72 hours, and a final report 14 days after a fix is available (vulnerability) or one month after the notification (incident), as the EU Cyber Resilience Act Article 14 sets out. `cargo xtask psirt deadlines --aware-at <time>` prints the dates for a given moment.

## Scope

In scope:
- the server, its signers, witness and policy solver, and the command-line tools,
- the published crates and the JavaScript SDKs,
- the hosted login, account and console web apps,
- the protocol text, CDDL and conformance vectors in `protocol/` and `conformance/`,
- the release pipeline: builds, signatures, SBOMs and provenance.

Not covered by this policy:
- volumetric denial of service and load testing against systems you do not run,
- social engineering, phishing of maintainers and physical attacks,
- findings that need an already compromised host, operator account or signing key, unless they cross a boundary the [security model](conformance/SECURITY-MODEL.md) says holds,
- the declared limits listed in the security model,
- third-party services and dependencies, which have their own reporting channels.

## Safe harbor

We will not pursue legal action against research that is done in good faith and within this policy: you test only against systems you own or are allowed to test, avoid privacy violations and data destruction, stop and report as soon as you find a vulnerability, and give us reasonable time to fix it before disclosure. If in doubt, ask first through the private reporting channel.

## Audits and assurance

- Independent security review reports are published unedited in [`security/audits/`](security/audits), with the commit they reviewed and the fixes that followed.
- The [security model](conformance/SECURITY-MODEL.md) states what the system holds, the declared limits and the residual risks.
- The [formal verification manifest](conformance/formal/manifest.toml) lists every machine-checked property with its tool and scope.
