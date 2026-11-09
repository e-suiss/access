# access-identity-attest

Workload identity and hardware attestation checks of the Access identity plane, with no I/O.
What a workload or a device proves becomes a Claim; it never becomes authority.

## Workload identifiers

`spiffe://<trust-domain>/<path>` and `wimse://<trust-domain>/<path>`: lower-case trust domain,
non-empty path segments of `[A-Za-z0-9._-]`, no query, fragment, user info or port, at most
2048 bytes, compared as exact strings.

A selector is either one identifier or everything below a path, written `…/*` and matched on
whole segments (`spiffe://acme.example/agent/*` selects `…/agent/a1` but not `…/agent1`). A
selector with a wildcard anywhere else matches nothing. A selector names who a registration
admits; it grants nothing.

## SPIFFE bundles and SVIDs

| | Rule |
|---|---|
| Bundle | a JWKS; `jwt-svid` keys verify JWT-SVIDs, `x509-svid` certificates are the X.509-SVID roots, other keys are ignored, private key material refuses the bundle |
| Refresh | after `spiffe_refresh_hint`, kept within 5 minutes and 24 hours; `spiffe_sequence` never goes back |
| Stale | a bundle older than twice its refresh interval verifies no SVID |
| JWT-SVID | ES256 under the `kid` of one `jwt-svid` key, `sub` a SPIFFE ID of the bundle's trust domain, `aud` the verifier alone, `exp` required |
| X.509-SVID | chain to the bundle roots for client authentication, leaf not a CA, `digitalSignature`, exactly one SPIFFE ID as URI SAN |

## Hardware attestation

| Format | Checklist |
|---|---|
| Android key attestation | chain to the Google roots; `KeyDescription` only on the leaf; the issued challenge; TEE or StrongBox for both levels; key generated in hardware; `RootOfTrust` with verified boot and a locked bootloader when required |
| Apple App Attest | chain to the Apple App Attestation root; nonce `SHA-256(authData ‖ clientDataHash)`; key id is the key's `SHA-256`; `rpIdHash` of the App ID; counter 0; production or development AAGUID |
| TPM 2.0 | `TPMS_ATTEST` certify with the issued challenge; the key's name over its `pubArea`, resident in the TPM; attestation key certificate of version 3 with empty subject, critical SAN, `tcg-kp-AIKCertificate`; chain to the manufacturer roots |

The roots are embedded from `data/`, where `SOURCES` names each file's origin and `SHA256SUMS`
pins it; nothing is fetched at build or run time.

A verified attestation names a runtime class whose digest is the `attestation_runtime` Claim's
value, bound to the attested Instance. Device integrity verdicts only narrow: the strongest one
is a compliant posture, a failed one a non-compliant posture, anything between says nothing. An
Instance, its current key binding and its attestations are kept as three separate records.

A realm takes evidence at `POST /v1/workloads/attestations`. The challenge is
`SHA-256("access/attestation-challenge/v1" ‖ 0x00 ‖ issuer ‖ 0x00 ‖ instance ‖ at)`, where `at`
(milliseconds) must be within five minutes of the realm's clock. The attested key must be the
Instance's own current P-256 key. Android evidence counts only from a verified, locked device. An
App Attest key is never an Instance's own key, so App Attest evidence is refused there. What
passes becomes the realm issuer's `attestation_runtime` Claim, bound to the Instance.
