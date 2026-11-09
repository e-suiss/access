# esuiss-access-sdk

The Access SDK for Rust: one package with the identity side (`auth`) and the enforcement side of an Access decision (`authorize`, `resource`). A service asks Access before an effect and applies the answer before the effect; a resource server verifies an authority token before it serves. Anything other than a verified ALLOW for this intent, this audience and this actor is a DENY. There is no fail-open setting, and none can be added without changing the SDK's types.

It builds on the open [`esuiss-access-kernel`](https://crates.io/crates/esuiss-access-kernel) and [`esuiss-crypto`](https://crates.io/crates/esuiss-crypto) only, is `no_std` + `alloc`, and does no I/O of its own.

## Modules

- **`auth`.** An OpenID Connect relying party without I/O: `discovery::parse` pins the issuer (RFC 8414 §3.3) and refuses a server without PKCE `S256`; `request::authorize` builds the authorization request with fresh `state`, `nonce`, verifier and `dpop_jkt`; `Pending::callback` accepts only this state, this issuer (RFC 9207) and a code; `token::parse_response` refuses a `Bearer` token where DPoP was asked; `token::validate_id_token` verifies the ID token through the Kernel's JWS check against the realm JWKS and returns a `Subject` scoped to the client, because `sub` may be pairwise. `dpop::proof` builds DPoP proofs through a `ProofKey` port, so the key can stay in a platform key store. With the `std` feature, `refresh::Refresher` runs one refresh for every concurrent caller (refresh tokens rotate and a reused one ends the family), and `replay::MemoryReplay` is a bounded in-memory DPoP replay store for one resource server process: when it is full it refuses rather than accept unrecorded. SAML SP helpers come with their protocol stage; the MCP client helpers are in `mcp::client`.
- **`reason`.** The ten blocker classes of a refusal and the subcodes this SDK knows; an unknown subcode is read as its parent class, and an unknown class makes the answer malformed. OAuth error codes follow the same rule (`auth::OAuthClass::Refused`).
- **`authorize`.** The policy enforcement point. `Pep::authorize` builds an Exercise Request for one intent with the actor Instance's own signed statement, sends it through your decision port, verifies the signed Decision Receipt under the domain's operational key (domain, audience = you, intent digest, the Exercise of your nonce, time), and returns `Authorized<R, A>`: a value that only exists after that check, is typed by resource and action, carries the ExerciseID, the intent digest and the position the decision reflects, and is consumed by the one effect it authorizes. `Authorized::apply` compares the digest of the body about to run with the approved intent first.
- **`resource`.** The resource server. `ResourceServer::verify` takes an RFC 9068 access token whose authority is in RAR `authorization_details`, checks the DPoP proof (or mTLS thumbprint) with your replay and nonce ports, the signing key against the domain's binding-signed Domain Metadata within the `key_epoch` window (only an operational key declared for `token` and live at the token's `iat`; a realm JWKS key never verifies an authority token), the Kernel token profile (one `aud` = you, this issuer, this domain, `cnf`), a bounds token's resource scope, parameters, recipient and purpose against your intent with the Kernel's `covers` (pass the intent with its envelope; what cannot be evaluated is refused), the contract's local requirements against those you satisfied (`Presented::satisfied`; when the only unmet ones are the user's authentication strength or freshness the refusal is `Denied::StepUp`, and `Denied::www_authenticate` gives the RFC 9470 `insufficient_user_authentication` challenge with `max_age` and `acr_values` to answer with 401), the ValidityContract view, the Token Status List entry within Δ, locally known revocations, introspection under the strict profile, and exact-intent single use. It returns the same `Authorized<R, A>` plus what the token proved. The verified value holds no token: nothing can be passed through.
- **`transport`.** The `Answer`/`Response`/`Fault` types your I/O hands back, and the `Clock` port.
- **`mcp`** (feature `mcp`). An MCP server as an OAuth resource server and the domain's PEP. See [MCP resource server](#mcp-resource-server).

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

## MCP resource server

With the `mcp` feature, `mcp::server::McpServer::handle` takes one HTTP request as received and answers it, or hands you a value to act on. The mapping is fixed:

- the MCP client is the agent's Instance;
- a tool is an `ActionRef` on a resource (`mcp::tool::ToolDef`), and a call is the intent of that action with the call's arguments as parameters (`mcp::tool::intent`, the same function the client signs over);
- `tools/call` is one decision for that exact intent, a list is a disclosure to this viewer, and the access token is an Access projection;
- an elicitation is never an approval, and a handle or `requestState` is a name, not a capability.

What it does on every request:

- **Metadata.** `mcp::prm::ProtectedResource` serves RFC 9728 metadata at the path-aware well-known URI with `Cache-Control: max-age=300`. It always carries `authorization_servers`, a minimal `scopes_supported` (`offline_access` is refused), `bearer_methods_supported: ["header"]`, and `dpop_bound_access_tokens_required: true` with the DPoP algorithms (or `tls_client_certificate_bound_access_tokens: true`). `resource_name` can be given per BCP 47 tag. `signed_metadata` is added only when you call `signed` with a PEP key. The document configures your PEP; it is not a source of trust in the authorization server.
- **Before the token.** Only `POST` on the MCP path is served; `GET` and `DELETE` answer 405. A header with CR or LF is 400. An `Origin` that is present and not allowed is 403, and so is a `Host` you do not serve (DNS rebinding). A local server binds to `127.0.0.1` only (`wire::local_bind`). `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` must equal the body after the base64 sentinel is decoded, or the answer is 400 with `-32020`; a parameter declared secret is refused in a header. `Mcp-Session-Id` is ignored and never written. `clientInfo`, `clientCapabilities` and `serverInfo` are dropped when the body is parsed, so nothing can decide on them.
- **The token.** Every request presents its own DPoP- or mTLS-bound token, verified by `resource::ResourceServer` for this audience only; nothing from an earlier request is reused. No credentials answer 401 with `WWW-Authenticate: Bearer resource_metadata="…"` and a `DPoP algs="…"` challenge. A bad token, or one for another audience, answers 401 `invalid_token`. A token whose bounds do not cover the call answers 403 `insufficient_scope` with every scope of the operation in one challenge. A step-up answers 401 `insufficient_user_authentication`. A `REQUIRE_ACTION` answers 403 `insufficient_authorization`, never `insufficient_scope`.
- **`tools/list`.** Each tool is shown when the token's authority names its action, or when an anonymous check under the domain's Public Grant allows it. The result is `cacheScope: "public"` only when every tool's visibility came from a Public Grant; anything else, a check that did not answer included, is `private`. `mcp::cache::ListCache` keeps a private result under `(Instance, capacity, aud, applied_pos)` and the token's projection. A cached list never authorizes a call. `ttlMs` is never negative, and the tools come back in name order.
- **`tools/call`.** With the actor's statement in `_meta` (`io.suiss.access/ais`, and `io.suiss.access/validity` for the window it signed), the server asks Access with `authorize::Pep` as the PEP and gets a verified receipt. Without one, the token must be an exact-intent token for this intent, or a bounds token covering it. You get a `server::Call` and run the tool with `Call::run`, which consumes the proof. When Access answers `REQUIRE_ACTION`, the server answers MRTR `input_required`. Its only input request is a URL elicitation carrying your Approval Surface address. Its `requestState` is AES-256-GCM, valid for 120 s and opened once. It is bound to the Instance, capacity, audience and intent, and carries only the nonce of the required action. The retry must repeat that nonce in its own statement and is decided anew; the earlier answer is never reused. A moved, expired or replayed state is refused before any decision.
- **`subscriptions/listen`.** The stream opens on one decision, and `mcp::listen::Listen` closes it at `min(token exp, horizon)`. The server never refreshes the token on the stream. Halfway to the close, `McpServer::checkpoint` asks `continue` with the statement the client signed in advance (`io.suiss.access/continue`). A DENY, an unknown answer or a missing statement closes the stream at once, and a signal asks the same question again. `Listen::deliver` hands nothing back after the close. Send `Stream::headers()`, which include `X-Accel-Buffering: no`.

`mcp::client` is the client side: the canonical resource URI (RFC 8707), the order to look for metadata in, challenge parsing, the check that the metadata names the resource you asked for, the `resource` member of the token request, and the `_meta` of a call. DPoP proofs come from `auth::dpop::proof`.

There is no gateway mode. An MCP server that is not built on this module goes behind the Access Proxy's MCP mode instead.

### Reference server

`examples/mcp_reference.rs` is a complete MCP resource server on axum over this module. It reads its configuration from the environment (see the file header) and fails to start when anything is missing. It binds `127.0.0.1` when it listens locally, and reaches Access over TLS 1.3 with its own client certificate as its PEP identity.

```sh
cargo run -p esuiss-access-sdk --features mcp --example mcp_reference
```

### Conformance statement

A resource server built on `McpServer` meets the MCP resource server profile as follows. Declare this in the server's Verifier Profile.

| Behaviour | Met by |
|---|---|
| `POST` on the MCP path; metadata at the well-known URI; `GET`/`DELETE` 405 | `McpServer::handle` |
| 401 with `resource_metadata`, `scope`, and the DPoP challenge | `challenge::www_authenticate` |
| Signature and `iss` against the domain's Domain Metadata keys; `exp`/`nbf` and the contract horizon; `aud` is this server | `resource::ResourceServer` |
| 403 `insufficient_scope` with every scope at once; `offline_access` never asked for; scope is a label and the authority is the RAR detail | `challenge::Challenge::of`, `scope_param` |
| No token passthrough; the verified value holds no token | `resource::Verified`, `server::Call` |
| No context from earlier requests; `Mcp-Session-Id` ignored; `clientInfo`/`clientCapabilities` never decide | `wire::parse` |
| Handles and `requestState` bound to the Instance, sealed, short-lived, single use | `state::StateKey` |
| `cacheScope: "private"` for lists that vary by token; the same scope on every page; `ttlMs` ≥ 0; per-primitive checks | `cache::scope_of`, `McpServer::handle` |
| `Origin` 403; local bind `127.0.0.1` only | `wire::Origins`, `wire::local_bind` |
| Header/body mismatch 400 `-32020`; no CR/LF; no secrets in `Mcp-Param-*` | `wire::hygiene`, `wire::consistent` |
| Metadata answers in under 5 s | served from memory, no upstream call |
| SSE with `X-Accel-Buffering: no`; the stream closes at the earlier of token expiry and horizon | `listen::Listen`, `server::Stream` |

The guarantees that lists are labelled `public` only when every item comes from a Public Grant, and that a stream carries no event after its horizon, hold for a server built on this module that passes the conformance vectors. They do not hold for a server that writes its own enforcement code.

## Versions and support

The crate version is the Access release it was built with and follows SemVer. The last two minor versions receive security fixes.

| `esuiss-access-sdk` | Access server | Kernel | Security fixes |
|---|---|---|---|
| 0.3.x | 0.3.x | 0.3.x | yes |

## Conformance

The repository's `access-pep-conformance` harness runs this SDK as an adapter against every fault case, and must see no effect on any of them.

## License

[Apache License 2.0](../../../LICENSE).
