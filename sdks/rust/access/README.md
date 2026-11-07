# esuiss-access-sdk

The Access SDK for Rust: one package with the identity side (`auth`) and the enforcement side of an Access decision (`authorize`, `resource`). A service asks Access before an effect and applies the answer before the effect; a resource server verifies an authority token before it serves. Anything other than a verified ALLOW for this intent, this audience and this actor is a DENY. There is no fail-open setting, and none can be added without changing the SDK's types.

It builds on the open [`esuiss-access-kernel`](https://crates.io/crates/esuiss-access-kernel) and [`esuiss-crypto`](https://crates.io/crates/esuiss-crypto) only, is `no_std` + `alloc`, and does no I/O of its own.

## Modules

- **`auth`.** An OpenID Connect relying party without I/O: `discovery::parse` pins the issuer (RFC 8414 §3.3) and refuses a server without PKCE `S256`; `request::authorize` builds the authorization request with fresh `state`, `nonce`, verifier and `dpop_jkt`; `Pending::callback` accepts only this state, this issuer (RFC 9207) and a code; `token::parse_response` refuses a `Bearer` token where DPoP was asked; `token::validate_id_token` verifies the ID token through the Kernel's JWS check against the realm JWKS and returns a `Subject` scoped to the client, because `sub` may be pairwise. `dpop::proof` builds DPoP proofs through a `ProofKey` port, so the key can stay in a platform key store. With the `std` feature, `refresh::Refresher` runs one refresh for every concurrent caller (refresh tokens rotate and a reused one ends the family), and `replay::MemoryReplay` is a bounded in-memory DPoP replay store for one resource server process: when it is full it refuses rather than accept unrecorded. SAML SP and MCP helpers come with their protocol stages.
- **`reason`.** The ten blocker classes of a refusal and the subcodes this SDK knows; an unknown subcode is read as its parent class, and an unknown class makes the answer malformed. OAuth error codes follow the same rule (`auth::OAuthClass::Refused`).
- **`authorize`.** The policy enforcement point. `Pep::authorize` builds an Exercise Request for one intent with the actor Instance's own signed statement, sends it through your decision port, verifies the signed Decision Receipt under the domain's operational key (domain, audience = you, intent digest, the Exercise of your nonce, time), and returns `Authorized<R, A>`: a value that only exists after that check, is typed by resource and action, carries the ExerciseID, the intent digest and the position the decision reflects, and is consumed by the one effect it authorizes. `Authorized::apply` compares the digest of the body about to run with the approved intent first.
- **`resource`.** The resource server. `ResourceServer::verify` takes an RFC 9068 access token whose authority is in RAR `authorization_details`, checks the DPoP proof (or mTLS thumbprint) with your replay and nonce ports, the signing key against the domain's binding-signed Domain Metadata within the `key_epoch` window (only an operational key declared for `token` and live at the token's `iat`; a realm JWKS key never verifies an authority token), the Kernel token profile (one `aud` = you, this issuer, this domain, `cnf`), the ValidityContract view, the Token Status List entry within Δ, locally known revocations, introspection under the strict profile, and exact-intent single use. It returns the same `Authorized<R, A>` plus what the token proved. The verified value holds no token: nothing can be passed through.
- **`transport`.** The `Answer`/`Response`/`Fault` types your I/O hands back, and the `Clock` port.

## Ports

Every I/O is a trait you implement over your HTTP client, cache and clock. The SDK decides; the port only reports.

| Port | Module | What it does |
|---|---|---|
| `Random` | `auth` | A CSPRNG for `state`, `nonce`, PKCE and `jti`; a failure builds nothing |
| `ProofKey` | `auth::dpop` | The DPoP public key and a signature over the JWS signing input |
| `Clock` | `transport` | Trusted time in Unix milliseconds; `None` means no trusted time, which is a DENY |
| `AskDecision` | `authorize` | Sends one Exercise Request (`adp_body` renders the AuthZEN body) and returns the raw answer |
| `KeySource` | `resource` | The domain's signed Domain Metadata (`/.well-known/access-domain-metadata/{DomainID}`), fetched now or as cached with its fetch time; verified against the binding keys of the metadata you pin in `Config` |
| `ReplayStore` | `resource` | Records a fixed-length key until a time; `Seen` refuses, `Unavailable` refuses |
| `NonceSource` | `resource` | Whether the proof's DPoP nonce is one you accept now |
| `StatusSource` | `resource` | Fetches the Token Status List the token names (CWT or JWT form) |
| `Introspector` | `resource` | `POST /introspect` for one token |
| `Revocations` | `resource` | Families you learned were ended from events; `false` means nothing known |

## The fail-closed guarantee

Every outcome that is not a verified ALLOW is a `Denied` value, never an `Ok`:

- a DENY or REQUIRE_ACTION from Access;
- no response, a timeout, any status other than 200, an unparsable body;
- an ALLOW without a receipt, or a receipt for another intent, audience, domain, nonce or time;
- a token for another audience, issuer or domain, without `cnf`, over 8 KiB, with a replayed or unbound DPoP proof, signed by a key the domain's metadata does not declare for `token` at its `iat`, with missing or stale Domain Metadata, with a set, stale or unreachable status list, an inactive or unreachable introspection, or presented a second time when exact-intent;
- a decision or projection older than the position the protected content was written at.

`Denied::class()` and `Denied::is_decision()` tell an explicit refusal from an unknown state, so your logs can; your effect cannot tell them apart, because neither produces an `Authorized`.

## Profiles

`Profile::Strict` introspects every request; `Profile::Fast` accepts a JWT whose horizon is at most 5 minutes with its status list. Neither skips the signature, audience, confirmation, contract or status checks. The profile is a type, not a flag.

## Pushing a request with a pre-signed contribution

When Access answers `REQUIRE_ACTION` with an unmet `approve` contribution, your product pushes the typed authority request to the realm's Approval Surface (`POST /v1/approve/requests`, the `approval_requests` endpoint of the realm's `/.well-known/suiss-configuration`; OP-149 m.9, m.29 (b)) together with the contribution the approver's device has already signed. The contribution is one more Exercise, and its intent is fixed by the Kernel so that the device, the surface and the authority plane sign and check the same bytes:

```rust
use access_kernel::ais::Statement;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::contribution::contribute_intent;
use access_kernel::intent::intent_digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Window;

// `target` is the intent digest the REQUIRE_ACTION names (`require_action.intent`);
// `holding` is the approver Party's holding of its Grant over `access/contribute`.
let intent = contribute_intent(target, "approve", Window { from, until }).ok_or(Encode)?;
let statement = Statement {
    domain,
    nonce: nonce.to_vec(),            // 16 random bytes; the AAS `exercise_ref`
    intent: intent_digest(&intent)?,
    mode: Mode::Commit,
    pep: String::from("access-identity"),
    capacity: Capacity::Own,
    basis: ExerciseBasis::Holding(holding),
    iat: now_ms,
    exercise: None,
};
// the approver's device Instance key signs the statement as a tagged COSE_Sign1 (the AIS)
```

`contribute_intent(target, class, validity)` is `access/contribute` on `access.contribution:[class]`, incarnation 0, with the `contribute` payload digest in `opaque["payload"]` and nothing else (L0-META-30). `conformance/cddl/examples/contribute-intent.json` holds the committed bytes for one target, and `kernel.cddl` `intent-envelope` is its schema. The push body is:

```json
{
  "request": { "...": "the typed authority request (authority-request.cddl)" },
  "contribution": {
    "nonce": "<base64url, the statement's nonce>",
    "class": "approve",
    "basis": { "grant": "<GrantID>", "holder": "<PartyID>", "since": 0 },
    "valid_from": "<RFC 3339, the intent's validity.from>",
    "valid_until": "<RFC 3339, the intent's validity.until>",
    "ais": "<base64url COSE_Sign1 over the statement>"
  }
}
```

The surface builds the Approval Act Statement from the render the decision point kept and the approver's Instance, takes one passkey assertion over H(AAS) and commits exactly this intent as PEP; the browser comes back to your `redirect_uri` with `exercise` (the contribution's ExerciseID), `render_digest`, `claim` (the approver's `authentication` Claim, bound to H(AAS) and to the approver's Instance) and `state`. Your product then commits the original intent again with `{"contribution": "<exercise>"}` among its proofs, and `{"claim_ref": "<claim>"}` too when the `REQUIRE_ACTION` also left an `authentication` term unmet (a step-up, §13.7.3).

## Versions and support

The crate version is the Access release it was built with and follows SemVer. The last two minor versions receive security fixes.

| `esuiss-access-sdk` | Access server | Kernel | Security fixes |
|---|---|---|---|
| 0.3.x | 0.3.x | 0.3.x | yes |

## Conformance

The repository's `access-pep-conformance` harness runs this SDK as an adapter against every fault case, and must see no effect on any of them.

## License

[Apache License 2.0](../../../LICENSE).
