# Compliance mappings

One file per framework, `<framework>.toml`, maps each control to the guarantee rows and tests
that already back it. A mapping adds no claim of its own: every row it cites is in
[`catalog/`](../catalog), every test it names exists, and a control marked `met` names at least
one row and one test. Statutory conformity is not guaranteed by any mapping; whether a
deployment meets a regulation is the operator's own assessment.

| Field | Meaning |
|---|---|
| `control` | the framework's control identifier |
| `status` | `met`, `partial`, `not-claimed` or `n/a` |
| `rules` | catalog rows that back it |
| `tests` | tests that exercise it |
| `note` | the scope of the mapping, or what is missing |

The shape is [`compliance-map.schema.json`](../schemas/compliance-map.schema.json).
`cargo xtask check` (`compliance-map`) checks every file here, and `cargo xtask compliance-map`
writes this page from them.

## Frameworks

| Framework | File | Met | Partial | Not claimed | n/a |
|---|---|---|---|---|---|
| DORA (Regulation (EU) 2022/2554) | [`dora.toml`](dora.toml) | 5 | 4 | 1 | 0 |
| eIDAS 2.0 (Regulation (EU) 2024/1183, relying party) | [`eidas-2.toml`](eidas-2.toml) | 4 | 1 | 0 | 1 |
| EUDI Wallet ARF (Architecture and Reference Framework 1.x, relying party) | [`eudi-arf.toml`](eudi-arf.toml) | 6 | 0 | 1 | 1 |
| HIPAA Security Rule (45 CFR 164.312, technical safeguards) | [`hipaa-security.toml`](hipaa-security.toml) | 9 | 0 | 1 | 0 |
| ISO/IEC 27001 (2022, Annex A) | [`iso-27001.toml`](iso-27001.toml) | 8 | 3 | 0 | 1 |
| NIS2 (Directive (EU) 2022/2555) | [`nis2.toml`](nis2.toml) | 6 | 4 | 0 | 1 |
| NIST SP 800-53 (Rev. 5, FedRAMP baseline source) | [`nist-800-53.toml`](nist-800-53.toml) | 13 | 3 | 0 | 0 |
| NIST SP 800-63-4 (800-63A-4, 800-63B-4 and 800-63C-4 (2025)) | [`nist-800-63-4.toml`](nist-800-63-4.toml) | 11 | 2 | 0 | 0 |
| OMB M-22-09 (January 2022, Identity) | [`omb-m-22-09.toml`](omb-m-22-09.toml) | 5 | 1 | 0 | 0 |
| OWASP ASVS (5.0.0, chapter level; target L3 identity plane, L2 other components) | [`owasp-asvs-5.toml`](owasp-asvs-5.toml) | 15 | 2 | 0 | 1 |
| PCI DSS (4.0.1, Requirements 8 and 10) | [`pci-dss-4.toml`](pci-dss-4.toml) | 15 | 6 | 2 | 1 |
| PSD2 SCA (Delegated Regulation (EU) 2018/389) | [`psd2-sca.toml`](psd2-sca.toml) | 3 | 1 | 2 | 0 |
| Data residency (Access placement and residency settings) | [`residency.toml`](residency.toml) | 2 | 1 | 1 | 0 |
| SOC 2 (Trust Services Criteria 2017 (rev. 2022)) | [`soc2.toml`](soc2.toml) | 10 | 3 | 0 | 0 |
| TR ÖHY ve BS Tebliği GKD (6493 sayılı Kanun, Tebliğ in force 1 December 2021, amended 4 September 2026 (RG 33360)) | [`tr-payments.toml`](tr-payments.toml) | 4 | 2 | 2 | 0 |
| WCAG (2.2, level AA) | [`wcag-2-2.toml`](wcag-2-2.toml) | 0 | 5 | 1 | 0 |

## DORA

Edition: Regulation (EU) 2022/2554. Source: [`dora.toml`](dora.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| Art. 6 ICT risk management framework | partial | SEC1 | 1 | The security model and its declared limits are inputs; the framework is the financial entity's. |
| Art. 9 protection and prevention | met | G16, SEC10, U58 | 3 | Per-request access decisions, MFA, and personal data sealed under per-subject keys. |
| Art. 9(4)(d) cryptographic controls | partial | SEC4, TNI-2 | 1 | Key rotation and HSM-held keys; the hybrid receipt carrier waits on lane J2c, realm post-quantum keys and the FIPS profile on lane J3. |
| Art. 10 detection | met | U52, U70 | 2 | Tamper-evident audit records streamed to the entity's SIEM. |
| Art. 11 response and recovery | met | U24, U10, SEC21 | 1 | Forced recovery from witnesses and exported records, without the provider. |
| Art. 12 backup and restoration | met | U24 | 1 | The restore drill runs its nine items on a point-in-time restore. |
| Art. 17 to 19 incident management and reporting | partial |  | 1 | The product's own vulnerability deadlines are tooled; classifying and reporting a major ICT incident is the entity's. |
| Art. 24 to 27 resilience testing | partial | U56 | 1 | The test layers, red-team suites and fault injection run in CI; threat-led penetration testing is the entity's. |
| Art. 28(8) exit strategy | met | U24, G28 | 2 | A full export streams whole, and a domain moves to a second install with the old provider fenced off. |
| Art. 30 contractual provisions | not-claimed |  | 0 | Service levels and contract terms are commercial; the evidence pack carries only the declared SLOs. |

## eIDAS 2.0

Edition: Regulation (EU) 2024/1183, relying party. Source: [`eidas-2.toml`](eidas-2.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| Art. 5b relying party registration | partial |  | 1 | The verifier identifies itself with its request-signing certificate; registration with a member state is the operator's. |
| Art. 5b(9) data minimisation | met | IDI-9, G37 | 2 | The verifier asks only the claims it names and refuses a response that discloses more. |
| Art. 8 assurance levels | met | IDI-3, IDI-9 | 2 | Level high comes only from a PID presented by a listed PID provider. |
| Art. 22 trusted lists | met | IDI-9 | 2 | Issuers must chain to a granted service of a signed, current trusted list. |
| Validity and revocation of attestations | met | G4 | 2 | A credential whose status is not valid, or whose status list cannot be read, is refused. |
| Wallet and qualified trust services | n/a |  | 0 | Access is a relying party; it is neither a wallet nor a qualified trust service provider. |

## EUDI Wallet ARF

Edition: Architecture and Reference Framework 1.x, relying party. Source: [`eudi-arf.toml`](eudi-arf.toml).

- 2026-12-31: Member states make a wallet available (Regulation (EU) 2024/1183).
- 2027-12-31: Relying parties required to use strong user authentication accept the wallet (Regulation (EU) 2024/1183).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| RP presentation protocol (OpenID4VP, HAIP) | met | IDI-9 | 2 | Signed request objects, direct_post.jwt responses, same-device and cross-device flows. |
| RP credential formats (SD-JWT VC, mdoc) | met | IDI-9 | 2 | Both PID formats are verified with holder binding. |
| RP minimum disclosure | met | G37 | 1 | A response that discloses more than asked is refused. |
| RP trust in issuers | met | IDI-9 | 1 | Issuers chain to the EU list of trusted lists. |
| RP revocation checks | met | G4 | 1 | Token status lists and bitstring status lists are read before ingestion. |
| Presentation creates no authority | met | IDI-3, IDI-9 | 1 | A presentation's Claims stay quarantined until a domain's Acceptance names the verifier. |
| RP registration certificates and access certificates | not-claimed |  | 0 | Relying party registration with a member state and its access certificate are the operator's; the request-signing certificate is configured, not issued by Access. |
| Wallet-side requirements | n/a |  | 0 | Access is not a wallet. |

## HIPAA Security Rule

Edition: 45 CFR 164.312, technical safeguards. Source: [`hipaa-security.toml`](hipaa-security.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| 164.312(a)(1) access control | met | G16, G48, TNI-3 | 2 | Access is decided per request, errors never allow, and tenant rows are separated by forced row-level security. |
| 164.312(a)(2)(i) unique user identification | met | IDI-2 | 1 | Each login identifier names one account of one realm. |
| 164.312(a)(2)(ii) emergency access | met | G53, TNI-13 | 2 | Break-glass access is a recorded, time-bounded grant, not an impersonation. |
| 164.312(a)(2)(iii) automatic logoff | met | G57 | 1 | Sessions end at their idle and absolute limits. |
| 164.312(a)(2)(iv) encryption and decryption | met | U58 | 1 | Personal data is sealed under per-subject keys; destroying a key makes the data unreadable. |
| 164.312(b) audit controls | met | U52, U53, U70 | 2 | Every security change and every audit read is recorded in a tamper-evident log. |
| 164.312(c)(1) integrity | met | G34, U70 | 1 | Records are committed into Merkle trees with signed checkpoints. |
| 164.312(d) person or entity authentication | met | SEC10, IDI-7 | 2 | Users authenticate with the factors the realm requires. |
| 164.312(e)(1) transmission security | met | SEC4 | 1 | Every listener serves TLS. |
| Business associate agreement | not-claimed |  | 0 | A commercial decision, outside this stage (§14.9). |

## ISO/IEC 27001

Edition: 2022, Annex A. Source: [`iso-27001.toml`](iso-27001.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| A.5.15 access control | met | G16, G48 | 1 | Access is decided per request against the domain's authority; errors never allow. |
| A.5.16 identity management | met | IDI-2 | 1 | Identities are created, changed and offboarded through recorded steps. |
| A.5.17 authentication information | met | U69, SAI-8 | 2 | Passwords are screened and hashed; secrets never print. |
| A.5.18 access rights | met | G4, G28 | 1 | Grants and revocations are Exercises; revocation denies every later commit. |
| A.5.24 to A.5.28 incident management | partial | SEC21 | 1 | Advisory and deadline tooling is in the repository; the incident process is the organization's. |
| A.8.2 privileged access rights | met | G53, TNI-13 | 2 | Privileged and support access are grants, never impersonation. |
| A.8.5 secure authentication | met | SEC10, HL-23 | 2 | Phishing-resistant passkeys, MFA as the realm requires, and throttled failures. |
| A.8.15 logging | met | U52, U53 | 1 | A tamper-evident audit log, never sampled. |
| A.8.16 monitoring activities | partial | U53 | 1 | The product streams its records; monitoring them is the organization's. |
| A.8.24 use of cryptography | partial | SEC4, TNI-2 | 1 | Classical algorithms and HSM-held keys; the post-quantum receipt carrier waits on lane J2c, realm post-quantum keys and the FIPS profile on lane J3. |
| A.8.25 to A.8.29 secure development | met | U56, OP-3-G3 | 2 | Gated test layers, pinned dependencies and actions, and releases only after vectors and proofs pass. |
| ISMS certification | n/a |  | 0 | Certification applies to an organization's management system, not to a product. |

## NIS2

Edition: Directive (EU) 2022/2555. Source: [`nis2.toml`](nis2.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| Art. 21(2)(a) risk analysis and security policies | met | SEC1, SEC3 | 2 | The published security model names the declared limits, residual risks with owners and signals, and the trust boundary of every component. |
| Art. 21(2)(b) incident handling | partial | SEC21 | 2 | Advisory records and reporting deadlines are tooled; the entity's incident process and its CSIRT contact are its own. |
| Art. 21(2)(c) business continuity and backup | met | U24, U10, SEC27 | 2 | Point-in-time restore drills and forced recovery from witnesses and exported records. |
| Art. 21(2)(d) supply chain security | met | OP-3-G3, N-44, N-47 | 2 | Dependencies are vetted and denied by policy, actions pinned by digest; publisher identity and dependency bugs stay declared limits (N-44, N-47). |
| Art. 21(2)(e) secure development and vulnerability handling | met | U56, OP-70 | 3 | Gated test layers, a published security.txt and disclosure policy, and five years of security fixes per major. |
| Art. 21(2)(f) effectiveness assessment | partial | SEC1 | 1 | Formal and test evidence is published with its scope; the crystal-box audit by an external firm waits on Adem. |
| Art. 21(2)(g) cyber hygiene and training | n/a |  | 0 | Training is the entity's own measure. |
| Art. 21(2)(h) cryptography | partial | SEC4, TNI-2 | 2 | Classical cryptography with HSM-held keys and a post-quantum re-anchor; the hybrid receipt carrier waits on lane J2c, realm post-quantum keys and the FIPS profile on lane J3. |
| Art. 21(2)(i) access control and asset management | met | G16, TNI-3 | 1 | Access is decided per request; tenant rows are separated by forced row-level security. |
| Art. 21(2)(j) multi-factor authentication | met | SEC10, HL-23 | 2 | MFA as the realm requires, with phishing-resistant passkeys. |
| Art. 23 reporting obligations | partial |  | 1 | The 24-hour, 72-hour and one-month deadlines are computed by the PSIRT tool; the report to the national CSIRT is the entity's. |

## NIST SP 800-53

Edition: Rev. 5, FedRAMP baseline source. Source: [`nist-800-53.toml`](nist-800-53.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| AU-2 | met | U53, OPI-6 | 1 | The audit taxonomy names every event written; security changes and their records share one transaction. |
| AU-3 | met | G14 | 1 | Each record names its actor, action, target, outcome and time in a pinned OCSF schema. |
| AU-6 | partial | U53 | 1 | The stream is readable and exportable to a SIEM; review and analysis are the operator's. |
| AU-9 | met | U52, U70, N-56 | 2 | Audit rows are in signed checkpoints and streamed to separate sinks; a database change before a checkpoint is not detected (N-56). |
| AU-10 | met | G14, U52 | 2 | Each event has an inclusion proof in its realm's tree, and actions are attributed by the actor's signed statement. |
| AU-11 | partial | U52 | 2 | Records are kept: 12 months by default, then a verified cold archive (OP-73); longer hot windows are a realm's audit tier. |
| AU-12 | met | U53 | 1 | Records are generated by the product itself, including reads of the audit log. |
| IA-2 | met | SEC10, IDI-7 | 2 | Users sign in with one or more factors as the realm requires. |
| IA-2(8) | met | G57 | 1 | One-time codes and WebAuthn challenges are single-use. |
| IA-5(1) | met | U69 | 2 | Passwords are screened, hashed with Argon2id and rehashed when parameters rise. |
| AC-7 | met | U46 | 1 | Consecutive failures wait longer each time and lock at 100. |
| AC-12 | met | G57 | 1 | Sessions end at their idle and absolute limits. |
| SC-8 | met | SEC4 | 1 | Every listener serves TLS. |
| SC-12 | met | TNI-2, U42 | 2 | Signing keys live in the signer process or an HSM and rotate without gaps. |
| SC-13 | partial | SEC4 | 1 | Classical algorithms through aws-lc-rs and PKCS#11; the FIPS 140-3 build profile waits on lane J3 and its image builds on CI only. |
| SC-28 | met | U58, U69 | 2 | Personal data is sealed under per-subject keys wrapped by a KEK; destroying the key makes it unreadable. |

## NIST SP 800-63-4

Edition: 800-63A-4, 800-63B-4 and 800-63C-4 (2025). Source: [`nist-800-63-4.toml`](nist-800-63-4.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| 63B AAL1 | met | IDI-7 | 1 | A password alone is AAL1 and meets no consequence tier. |
| 63B AAL2 | met | SEC10 | 2 | Two factors are AAL2; restricted authenticators reach AAL2 and no consequence tier. |
| 63B AAL3 | met | SEC10, SEC17 | 2 | A device-bound passkey with user verification is AAL3; a software key never is. |
| 63B 3.1.1 passwords | met | U69 | 2 | At least 8 characters after NFKC, up to 128, no composition rules, no rotation, breached passwords refused. |
| 63B 3.2.2 rate limiting | met | U46, U47 | 2 | At most 100 consecutive failures per account; hashing load sheds instead of starving other endpoints. |
| 63B 3.2.5 phishing resistance | met | HL-23, N-41, N-45 | 3 | Only origin-bound authenticators count as phishing-resistant; codes do not resist a reverse proxy (N-45) and passkeys do not stop session theft after sign-in (N-41). |
| 63B 3.2.9 restricted authenticators | met | N-45 | 2 | SMS codes are a second step only, six digits, five minutes and three tries, and off unless the realm turns them on. |
| 63B 5 session management | met | G57, U35 | 2 | Sessions carry idle and absolute lifetimes and end with their epoch; no token is issued after the end. |
| 63A IAL1 | met | IDI-2 | 1 | Self-asserted attributes with a verified e-mail address; sign-up hides whether an address has an account. |
| 63A IAL2 and IAL3 | partial | IDI-3, IDI-9 | 2 | Remote proofing through a PID presentation from a listed provider is in the product; supervised proofing and document checks are not. |
| 63C FAL1 | met | IDI-7 | 2 | Assertions are signed, single-audience and time-bounded, and the relying side checks issuer, audience and nonce. |
| 63C FAL2 | met | G58 | 2 | The back-channel code flow with PKCE protects against assertion injection; DPoP binds tokens to a key. |
| 63C FAL3 | partial | G58 | 1 | Holder-of-key tokens (DPoP, mutual TLS) are in the product; a bound authenticator at the relying party is the relying party's part. |

## OMB M-22-09

Edition: January 2022, Identity. Source: [`omb-m-22-09.toml`](omb-m-22-09.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| Identity 1 centralized identity management | met | IDI-2, TNI-1 | 1 | One realm signs users into its applications through OpenID Connect and SAML. |
| Identity 2 phishing-resistant MFA | met | SEC10, HL-23 | 2 | A passkey-only realm with MFA required and no SMS, voice or push factor is a realm setting the realm check reports. |
| Identity 2 no SMS or voice | met | N-45 | 2 | SMS codes are off by default and there is no voice factor; the realm check fails a realm that turns SMS on. |
| Identity 3 password policies | met | U69 | 2 | No special-character rules and no periodic rotation; breached passwords are refused. |
| Identity 4 authorization per request | met | G16, G48 | 1 | Every consequential action is decided on its own request, and no error state yields ALLOW. |
| Identity 5 device signals | partial | IDI-3 | 1 | Risk and device signals narrow sessions; an inventory of agency devices is the agency's. |

## OWASP ASVS

Edition: 5.0.0, chapter level; target L3 identity plane, L2 other components. Source: [`owasp-asvs-5.toml`](owasp-asvs-5.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| V1 encoding and sanitization | met | SA-21 | 3 | Pages escape what they render; parsers run in an isolated worker. |
| V2 validation and business logic | met | G16, G48 | 2 | Input size and depth are bounded before parsing; decisions never allow on error. |
| V3 web frontend security | met | SA-21 | 3 | Pages cannot be framed, carry a content security policy, and writes need the origin and the session's CSRF token. |
| V4 API and web service | met | SEC28 | 2 | Rate limits refuse before the body is read; problems are RFC 9457 documents. |
| V5 file handling | met | U22 | 2 | Uploads are text only, redacted, bounded by the realm's limit and read under their own grant. |
| V6 authentication | met | SEC10, U69, U46, SAI-5 | 3 | NIST-aligned passwords, MFA, throttling, phishing-resistant passkeys, and answers that do not reveal accounts. |
| V7 session management | met | G57, U35 | 2 | Idle and absolute limits, epochs that end every token, and back-channel logout. |
| V8 authorization | met | G16, G48, U59 | 2 | Every consequential action is decided by the Kernel; unscoped queries return nothing. |
| V9 self-contained tokens | met | G46, G61 | 2 | Tokens are sender-constrained and signed only with published keys. |
| V10 OAuth and OIDC | met | G58 | 3 | PKCE for every client, exact redirect URIs, DPoP, and refresh rotation with reuse detection. |
| V11 cryptography | partial | SEC4, U45, SAI-42 | 2 | Vetted primitives and constant-time comparisons by design; the hybrid receipt carrier waits on lane J2c, realm post-quantum keys and the FIPS profile on lane J3, and the timing measurements run on the bench runner. |
| V12 secure communication | met | SEC4 | 2 | TLS on every listener; outbound calls are HTTPS only. |
| V13 configuration | met | OP-49, OP-3-G3 | 2 | No secrets in the repository, a sandboxed process, and distroless images. |
| V14 data protection | met | U58, SAI-8 | 2 | Per-subject keys for personal data, redacted support artefacts, and secrets that never print. |
| V15 secure coding and architecture | met | SA-21, OP-93 | 2 | Enforced dependency direction, no request-path panics, and hardened builds. |
| V16 security logging and error handling | met | U53, OPI-6, SAI-3 | 2 | Audit records share the change's transaction, are never sampled, and failures never allow. |
| V17 WebRTC | n/a |  | 0 | Access serves no WebRTC. |
| Requirement-level mapping | partial |  | 0 | Each ASVS 5.0 requirement still needs its test or a reasoned n/a (SA-55); the chapters above are the first pass. |

## PCI DSS

Edition: 4.0.1, Requirements 8 and 10. Source: [`pci-dss-4.toml`](pci-dss-4.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| 8.2.1 | met | IDI-2 | 1 | Each login identifier belongs to one account of one realm; a taken identifier creates nothing. |
| 8.2.2 | not-claimed |  | 0 | Whether people share an account is an operator practice the product does not observe. |
| 8.2.5 | met | G57, OPI-6 | 2 | Deactivating an account ends its sessions in the same transaction. |
| 8.2.6 | partial | G57 | 1 | Deactivation is in the product; finding accounts idle for 90 days is the operator's access review. |
| 8.2.8 | met | G57 | 3 | Console sessions end after at most 15 idle minutes; the realm check reports the realm's idle setting. |
| 8.3.1 | met | IDI-7 | 2 | Every sign-in presents a password, a passkey or a federated assertion before a session exists. |
| 8.3.2 | met | U69, SAI-8 | 2 | Passwords are stored as Argon2id hashes and client secrets as digests; secrets travel only over TLS. |
| 8.3.4 | partial | U46 | 2 | Failures wait longer each time and lock at 100 (SA-30), not 10; a realm without password sign-in passes, which the realm check reports. |
| 8.3.5 | n/a |  | 0 | No first-use password is issued: accounts are created by registration or an invitation link. |
| 8.3.6 | partial | U69 | 2 | The product minimum is 8 characters (NIST SP 800-63B-4), not 12; a passkey-only realm passes, which the realm check reports. |
| 8.3.7 | not-claimed |  | 0 | No password history is kept; NIST SP 800-63B-4 asks for no rotation. |
| 8.3.9 | partial | U69 | 1 | No periodic change; a password is screened against breach corpora when it is set (IDP-3). |
| 8.4.1 | met | SEC10, TNI-12 | 2 | A realm that requires MFA signs nobody in with one factor; administrative actions of CT2 and above need a phishing-resistant step. |
| 8.4.2 | met | SEC10 | 2 | MFA on every sign-in is a realm setting the realm check reports. |
| 8.5.1 | met | SEC10, N-45, HL-23 | 3 | Codes are single-use and the second step cannot be skipped; TOTP, push and SMS do not resist a reverse proxy (N-45), passkeys do. |
| 8.6.1 | partial | G14 | 1 | Directory app passwords are scoped and revocable; whether a system account is used interactively is the operator's control. |
| 10.2.1 | met | U53, OPI-6 | 2 | Every security change is written with its audit record in one transaction; audit records are never sampled. |
| 10.2.1.2 | met | G28, OPI-6 | 1 | Administrative changes are Exercises with their audit records. |
| 10.2.1.3 | met | U53 | 1 | Each read of the audit log is itself one audit row. |
| 10.3.2 | met | U52, U70 | 2 | Audit rows go into a Merkle tree whose signed checkpoints cannot fork or change. |
| 10.3.3 | met | U52 | 1 | The streamed export copies every row to every configured sink and keeps rows for a sink that is down. |
| 10.3.4 | met | U70, N-56 | 1 | A change to the log after a published checkpoint is detected; a database change before the checkpoint is not (N-56). |
| 10.5.1 | partial | U52 | 2 | The base window is 12 months (OP-158 m.3 (w)); three months immediately available needs a hot window of at least 90 days in the realm's audit tier, which may be a paid tier. |
| 10.6.1 | met | SEC22 | 1 | Commits stop when the clock disagrees with the witness; host time synchronisation is the operator's. |

## PSD2 SCA

Edition: Delegated Regulation (EU) 2018/389. Source: [`psd2-sca.toml`](psd2-sca.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| Art. 4 authentication code | met | U62, SEC10 | 1 | A payment under the template needs a fresh authentication with two independent factors. |
| Art. 5 dynamic linking | met | U62, G13 | 3 | The authentication is bound to the payment's own intent; a different amount or payee is no confirmation. |
| Art. 6 to 8 independent elements | met | SEC10 | 1 | Two elements of different categories, each checked on its own. |
| Art. 9 independence of elements | partial | N-45, HL-23 | 1 | The approval surface separates the elements; the security of a customer's device is outside the product. |
| Art. 10 to 18 exemptions | not-claimed |  | 0 | Exemption analysis (low value, trusted beneficiaries, TRA) is the payment service provider's. |
| Regulatory conformity | not-claimed | N-52 | 0 | Applying the template's rules is the product's part; whether they meet the regulation is not guaranteed (N-52). |

## Data residency

Edition: Access placement and residency settings. Source: [`residency.toml`](residency.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| Declared region | met | TNI-3 | 1 | A realm declares residency only in its cell's region and reads it back. |
| Dedicated placement | met | HL-17, U54 | 2 | A silo move takes a tenant to a dedicated cell; the durability read shows shared hosting until dedicated is declared. |
| Cross-region copies | partial | HL-17 | 1 | Export sinks, witnesses and replicas the operator configures may sit in other regions; choosing them is the operator's. |
| Restore scope | not-claimed | N-58 | 0 | Restores are whole-database; restoring one tenant or realm alone is not offered (N-58, HL-32). |

## SOC 2

Edition: Trust Services Criteria 2017 (rev. 2022). Source: [`soc2.toml`](soc2.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| CC6.1 logical access | met | G16, TNI-3, U59 | 2 | Queries without a tenant scope return nothing, and access is decided per request. |
| CC6.2 registration and authorization of users | met | IDI-2, G28 | 1 | Joiners, movers and leavers move through rule-shaped authority and recorded offboarding. |
| CC6.3 role and attribute changes | met | G4, G28 | 1 | A change of access is an Exercise; deactivation ends sessions in the same transaction. |
| CC6.6 boundary protection | met | SEC4 | 2 | Outbound calls reach only declared public targets; inbound requests are rate limited before their bodies are read. |
| CC6.7 data in transit | met | SEC4 | 1 | Every listener serves TLS. |
| CC6.8 unauthorized software | met | OP-3-G3, OP-49 | 2 | Dependencies are vetted and pinned, actions are pinned by digest, and images are distroless. |
| CC7.1 detection of configuration changes | met | OPI-6, U70 | 1 | Every configuration change is an audited Exercise in a tamper-evident log. |
| CC7.2 monitoring | partial | U53 | 1 | Audit and telemetry stream to the operator's SIEM; watching them is the operator's. |
| CC7.3 and CC7.4 incident response | partial | SEC21 | 2 | Advisories and the reporting deadlines are tooled; the PSIRT itself is people and process. |
| CC8.1 change management | met | U56, OP-70 | 1 | Every change passes the gated test layers before merge, and releases ship only after vectors and proofs pass. |
| A1.2 recovery | met | U24, U10 | 1 | The restore drill runs on a point-in-time restore; forced recovery is possible without the provider. |
| C1.1 confidentiality | met | U58, SAI-8 | 1 | Secret types never print, and personal data is sealed under per-subject keys. |
| Type II attestation | partial |  | 0 | The report of an external auditor; the firm and the audit period are Adem's (D6, MD-16). The evidence pack is its input. |

## TR ÖHY ve BS Tebliği GKD

Edition: 6493 sayılı Kanun, Tebliğ in force 1 December 2021, amended 4 September 2026 (RG 33360). Source: [`tr-payments.toml`](tr-payments.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| m.10 two elements of different categories | met | U62, SEC10 | 2 | A passkey and the app-controlled factor; neither alone meets CT2. |
| m.10 platform biometrics alone | met | U62 | 2 | Platform biometrics alone never count as an element. |
| m.10 SMS only for set-up and activation | met | U62, N-45 | 2 | SMS codes activate the app-controlled factor and are refused at sign-in and after a recent SIM change. |
| m.10 dynamic linking of the transaction code | met | U62, G13 | 2 | A payment needs an authentication bound to its own intent, signed by the customer's own key. |
| m.22/7 documentation | partial |  | 1 | A documentation template ships with the realm template (deploy/realm-templates/tr-gkd/); keeping it is the institution's. |
| m.22/6 two tests a year | partial |  | 1 | A test report template ships with the realm template; running the tests is the institution's. |
| SPK VII-128.10 | not-claimed |  | 0 | Capital markets rules apply on their own and are not mapped here. |
| Regulatory conformity | not-claimed | N-52 | 0 | Regulatory conformity is NOT GUARANTEED; the legal assessment is the institution's. |

## WCAG

Edition: 2.2, level AA. Source: [`wcag-2-2.toml`](wcag-2-2.toml).

| Control | Status | Rows | Tests | Note |
|---|---|---|---|---|
| 3.3.8 Accessible Authentication (Minimum) | partial |  | 3 | Passkeys need no cognitive test, codes can be pasted into one field, and fields carry autocomplete; no catalog row states it yet. |
| 3.3.7 Redundant Entry | partial |  | 1 | The identifier and e-mail fields carry autocomplete and are not asked twice; no catalog row states it yet. |
| Level AA, login and hosted pages | partial |  | 1 | Every login step and hosted page has no axe WCAG 2.2 AA violation in each locale; automated checks cover part of the criteria. |
| Level AA, account pages | partial |  | 1 | The account settings pages and their open forms pass axe; automated checks cover part of the criteria. |
| Level AA, console | partial |  | 1 | Sign-in, every signed-in screen and every section screen pass axe; automated checks cover part of the criteria. |
| Manual audit | not-claimed |  | 0 | A manual audit with assistive technology has not been done. |
