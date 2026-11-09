# access-vc-verifier

The verifier for digital identity wallets. It asks a wallet for a presentation over OpenID for Verifiable Presentations under the HAIP profile (SD-JWT VC and mdoc, ES256, `direct_post.jwt`), checks the credential against the trusted lists, and sends what it verified to Access as a Claim signed with its own key. A presentation changes nothing by itself: it counts only where a domain has accepted this verifier.

It uses public crates only, holds no authority and writes none.

## Routes

The contract is [`sdks/openapi/vc-verifier-v1.json`](../../sdks/openapi/vc-verifier-v1.json), generated from `src/contract.rs` (`just vc-verifier-contract`). Every route is declared now and answers `501 not-yet-served` until it is served.

| Route | What it does |
|---|---|
| `POST /vc-verifier/v1/presentations` | Starts a presentation request: the DCQL query, the nonce and the response mode. |
| `GET /vc-verifier/v1/requests/{request}` | The signed request object the wallet fetches by `request_uri`. |
| `POST /vc-verifier/v1/responses/{request}` | The wallet's encrypted `direct_post.jwt` response. |
| `GET /vc-verifier/v1/presentations/{request}` | The outcome for the caller that started the request; never the disclosed values. |
| `GET /vc-verifier/v1/trusted-lists` | The trusted lists the verifier loaded and whether their signatures verified. |

## License

Apache-2.0.
