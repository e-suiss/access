# access-identity-saml

The SAML 2.0 identity provider and WS-Federation passive requestor of Access, written without I/O.
It never parses XML: the parser worker reads and verifies every incoming message and hands back
its facts. This crate decides on those facts, writes canonical Responses, assertions, metadata and
WS-Federation tokens, and has them signed by the identity signer's `saml` key.

## How a sign-in flows

1. access-server receives the browser on `/saml/sso` (or `/saml/sso/{sp}`, `/saml/ecp`, `/wsfed`),
   keeps the cookies, opens a flow and forwards the raw binding values to the SAML gateway with a
   one-use attestation handle.
2. The gateway has the parser worker read the message, asks access-server (`session_attest`, `sp`)
   for the service provider's pinned certificates, and has the worker verify the signature.
3. The gateway calls `session_attest` (`issue`) with the handle and the verified facts.
   access-server checks the handle against its flow, decides, signs and keeps the outcome. A
   forged handle is refused by the edge channel, so no signed Response exists without a completed
   authentication.
4. access-server renders the outcome: an auto-submitting HTTP-POST page, a login redirect, or an
   error page. An ACS that does not match the registration exactly is shown to the user and nothing
   is sent to the service provider.

## Rules

| Area | Rule |
|---|---|
| Response | Issuer, Signature, Subject, Conditions, AuthnStatement order; `Destination`, `InResponseTo` and `Issuer` always; audience is the entity ID (or the template's value); one bearer `SubjectConfirmation` with `Recipient`, `NotOnOrAfter` and `InResponseTo`, never `NotBefore`; `SessionIndex` is the assertion ID; `SessionNotOnOrAfter` 8 h |
| Signatures | Enveloped, one `Reference`, exclusive c14n. Assertion first, then Response; both by default, at least one always. RSA-SHA256 with RSA-3072 by default, RSA-SHA384/512 or ECDSA-SHA256 by registration. SHA-1, PSS and Ed25519 are never produced |
| Encryption | Sign, then encrypt: AES-256-GCM and RSA-OAEP (SHA-256, MGF1 SHA-256), key inline. No `rsa-1_5`, no `EncryptedAttribute` |
| NameID | Persistent by default: 32 random bytes, kept per subject and service provider (or affiliation). Transient: new each time. E-mail: only when the template asks. Unspecified: legacy |
| Attributes | `NameFormat` URI by default, per-registration override; `FriendlyName` is written, never matched |
| Time | `NotBefore` −60 s, `NotOnOrAfter` +5 min (IdP-initiated: 2 min), request skew ±3 min, UTC `Z`, `OneTimeUse` off |
| Requests | `IsPassive` wins over `ForceAuthn`; `NoPassive` when the user would have to interact; `InvalidNameIDPolicy` when the policy cannot be met; signed requests when `AuthnRequestsSigned`; request IDs kept 10 min against replay |
| IdP-initiated | Off unless the registration opts in; only the `isDefault` ACS; `RelayState` must carry the realm's MAC |
| Metadata | `validUntil` +14 days, `cacheDuration` PT6H, re-signed each time it is served, every published certificate listed; PEM download and SSO URL for manual setup |

## Interop profiles

`profiles/*.toml` holds one divergence profile per profiled service provider: AWS, AWS IAM SAML,
AWS IAM Identity Center, Entra/M365, Google Workspace, Salesforce, ServiceNow, Workday, Slack,
Zoom and Atlassian. A profile can only describe format differences. A rule that would relax
signature verification, time checks, audience or recipient checks, parser isolation or a limit
does not exist, so a profile naming one is refused at load, as is SHA-1 or turning a signature
off. Each tolerance names the test that pins it.

## The 21-action plan

From the profiles of §10.6.1; actions 1 to 16 come first, 17 to 21 next. Each has a test.

| # | Action | Test |
|---|---|---|
| 1 | Sign both Response and Assertion by default | `assertion::tests::a_response_follows_the_ten_rules_and_both_signatures_verify` |
| 2 | Per-registration `sign_response`/`sign_assertion`, never neither | `sp::tests::registrations_are_checked` |
| 3 | RSA-SHA256 by default, RSA-3072 key | `sp::tests::a_minimal_registration_has_the_safe_defaults` |
| 4 | No SHA-1 anywhere | `alg::tests::sha1_is_never_an_algorithm_and_sha384_has_the_right_uri` |
| 5 | NameID format from the template; persistent and pairwise by default | `profile::tests::entra_takes_persistent_and_idp_email` |
| 6 | E-mail NameID only when the template asks | `profile::tests::identity_center_takes_email_and_no_encryption` |
| 7 | Transient NameID new for every assertion | `assertion::tests::the_class_comes_from_the_assurance_vector` |
| 8 | Fixed, case-sensitive attribute names per template; multi-valued attributes | `profile::tests::aws_requires_role_and_session_name` |
| 9 | `NameFormat` URI by default, override per SP; `FriendlyName` never matched | `sp::tests::registrations_are_checked` |
| 10 | Exact ACS match; mismatch shown to the user | `request::tests::the_acs_matches_the_registration_exactly` |
| 11 | HTTP-POST always available for the Response | `binding::tests::the_post_page_escapes_and_carries_the_nonce` |
| 12 | Short `NotOnOrAfter`, ±3 min skew, unique IDs | `time::tests::request_windows` |
| 13 | Audience is the entity ID, or the template's value (Salesforce) | `profile::tests::salesforce_requires_the_assertion_signature_and_its_audience` |
| 14 | `Recipient` is the ACS; exactly one bearer `SubjectConfirmation` | `assertion::tests::a_response_follows_the_ten_rules_and_both_signatures_verify` |
| 15 | Optional encryption per SP; never `EncryptedAttribute` | `assertion::tests::an_encrypted_assertion_round_trips_against_the_sp_key` |
| 16 | IdP-initiated only by per-SP opt-in (AWS) | `profile::tests::idp_initiated_stays_opt_in_per_registration` |
| 17 | Metadata lists every published certificate for rotation | `metadata::tests::metadata_lists_every_certificate_and_its_windows` |
| 18 | PEM download and SSO URL for manual setup (Slack, Workday, Atlassian) | `metadata::tests::metadata_lists_every_certificate_and_its_windows` |
| 19 | SLO optional per SP (none for Slack); `PartialLogout` | `profile::tests::slack_requires_the_response_signature_and_no_logout` |
| 20 | Metadata within 75 000 characters, UTF-8 without BOM | `metadata::tests::metadata_lists_every_certificate_and_its_windows` |
| 21 | Profiles cannot relax security | `profile::tests::a_profile_that_relaxes_security_is_refused_at_load` |

## Certificate rotation

Rotation has two phases under the realm's policy (`idp.saml.cert_policy`). At T0 a new key and
certificate are added and published in metadata next to the current one. After at least 14 days,
at T1, signing switches to the new key. At T1 + 14 days the old certificate is removed. The
scheduled steps and the metadata re-signing are operational; an emergency replacement is
`idp.saml.cert_emergency`.

### Entra ID (manual procedure)

Entra reads no metadata, so each phase is done by hand in the Entra admin center:

1. At T0, download the new certificate (PEM) from the realm's SAML settings.
2. In Entra, open the federation settings of the domain and add the new certificate as the
   *next* signing certificate (`NextSigningCertificate` with the Graph or MSOnline tools).
3. At T1, when Access switches, Entra promotes the next certificate; check one sign-in.
4. After T1 + 14 days, remove the old certificate from Entra.

## License

[Apache License 2.0](../../LICENSE).
