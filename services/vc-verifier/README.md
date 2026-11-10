# access-vc-verifier

The verifier for digital identity wallets. It asks a wallet for a presentation over OpenID for Verifiable Presentations under the HAIP profile (SD-JWT VC and ISO 18013-5 mdoc, ES256, `direct_post.jwt`), checks the credential against the EU trusted lists, and sends what it verified to Access as Claims signed with its own key. A presentation changes nothing by itself: its Claims are quarantined until a domain's Acceptance names this verifier as their issuer.

It is its own process with its own database, uses public crates only, holds no authority and writes none.

## What it checks

- **Request.** A signed request object (`client_id` with the `x509_hash` prefix of the request-signing certificate), `response_mode=direct_post.jwt`, a fresh nonce and state, and the request's own encryption key. The same `openid4vp://` link opens the wallet on the same device or, as a QR code, from another device.
- **Minimum disclosure.** The DCQL query names exactly the claims asked for; `credential_sets`, claim values and queries without claims are refused. A response that discloses anything else, or misses an asked claim, is refused and nothing reaches Access.
- **SD-JWT VC.** `typ` `dc+sd-jwt`, ES256, every disclosure referenced once, holder binding with a key binding JWT over the request's nonce and `client_id`.
- **mdoc.** `issuerAuth` over the Mobile Security Object, every item against its digest, validity, and the device signature over the OID4VP session transcript.
- **Issuer trust.** The issuer's certificate chain must reach a granted service of the loaded trusted lists, which must be signed and before their next update; an SD-JWT VC's `iss` must match the certificate. Issuers configured outside the lists are resolved by `did:web`, `did:jwk` or JWT VC issuer metadata; other DID methods are refused.
- **Status.** Token Status List and W3C Bitstring Status List (secured as VC-JOSE; Data Integrity proofs are refused). Anything but "valid", or a list that cannot be read, refuses the credential.
- **Assurance.** `loa_eidas` high comes only from a PID presented by a granted PID provider; never from an attestation provider, a configured issuer or any method of Access's own.

## What it sends

A PID becomes an `identity_binding_person` Claim whose evidence is the digest of what was verified; a boolean or integer claim becomes a `vc_<name>` attribute Claim. Text values never leave the verifier. Each Claim is issued by the verifier's operator Party, bound to and signed by the verifier Instance, and sent to Claim Ingest on Access's public listener with the verifier's client certificate.

## Routes

The contract is [`sdks/openapi/vc-verifier-v1.json`](../../sdks/openapi/vc-verifier-v1.json), generated from `src/contract.rs` (`just vc-verifier-contract`).

| Route | What it does |
|---|---|
| `POST /vc-verifier/v1/presentations` | Starts a presentation request for a domain and subject (caller key as `Authorization: Bearer`). |
| `GET /vc-verifier/v1/requests/{request}` | The signed request object the wallet fetches by `request_uri`. |
| `POST /vc-verifier/v1/responses/{request}` | The wallet's encrypted `direct_post.jwt` response; a same-device wallet is sent back with a one-time `response_code`. |
| `GET /vc-verifier/v1/presentations/{request}` | The outcome for the caller that started the request; never the disclosed values. |
| `GET /vc-verifier/v1/trusted-lists` | The trusted lists the verifier loaded and whether they are usable. |

## Running it

`access-vc-verifier` reads its configuration from the environment; see `src/main.rs` for the variables. Requests, outcomes and trusted list snapshots are only ever appended.

## License

Apache-2.0.
