# @esuiss/access

The Access SDK for TypeScript, for browsers and Node. One package, two modules kept apart:

- **`auth`**: the identity side. Authorization server metadata with issuer pinning, the authorization request with PKCE `S256`, `state` and `nonce`, the callback check (state, RFC 9207 `iss`), token responses, DPoP proofs with a non-extractable WebCrypto key, a token store interface with an in-memory default, and a refresh single-flight.
- **`authorize`**: the enforcement side. `authorize()` asks the decision point and returns `{ allowed: true }` only for a verified ALLOW: a receipt the Kernel verifies for this domain, audience, intent and time, naming the Exercise of this request's nonce. Every other outcome is a denial with a class (`decision`, `unverified`, `unknown`) and, for a refusal, its reasons. `statusValid()` reads a Token Status List entry and treats an unreadable list as invalid.

- **`agent`**: the agent's side of a decision, the same contract as the Rust SDK's `agent` module, passing the same vectors (`conformance/vectors/agent/1`). `Exercise` refuses a plan without a capacity or a basis, keeps an ALLOW to its envelope, closes a nonce on DENY, and waits on the same nonce for a recorded proof. Every unmet requirement carries a route. A requirement the agent cannot meet goes to its principal and is never `interaction_required`. `handoff` builds the coordinator's `authority-request`, with the agent's words only as the requester's note. `Continuation` handles long-running work, `Refusals` stops an agent from splitting a refused amount, and `check` answers are advisory only. `a2a` has the `urn:suiss:access:a2a:authority:v1` members, the task-state mapping, Agent Card verification under accepted keys, and `securitySchemes` from the realm's discovery document.

Kernel semantics come from the Access Kernel compiled to WebAssembly (`loadKernel()`); no CBOR is written or read in TypeScript. Types for the HTTP APIs are generated from the OpenAPI contracts with `openapi-typescript` (`npm run gen`) and exported as `AccessApi`, `AdminApi`, `FrontendApi` and `LoginApi`; CI fails when they drift from the contracts.

```ts
import { auth, authorize, loadKernel } from "@esuiss/access";

const meta = auth.parseMetadata(await (await fetch(auth.wellKnown(issuer))).json(), issuer);
const key = await auth.generateDpopKey();
const { url, pending } = await auth.authorizationRequest(meta, client, key.jkt);
// … after the redirect:
const code = auth.callbackCode(pending, location.search);

const refresher = new auth.Refresher<auth.Tokens>();
const tokens = await refresher.refresh(() => refreshTokens()); // concurrent callers share one call

const kernel = await loadKernel();
const result = await authorize.authorize(kernel, fetch, ask);
if (!result.allowed) throw new Error(result.code);
```

Unknown reason subcodes and unknown OAuth error codes are read as their parent class, so a newer Access never makes an older SDK misread a refusal.

## Versions and support

The package version is the Access release it was built with; it follows SemVer. The last two minor versions receive security fixes.

| `@esuiss/access` | Access server | Kernel | Security fixes |
| ---------------- | ------------- | ------ | -------------- |
| 0.3.x            | 0.3.x         | 0.3.x  | yes            |

Releases are published from CI with npm trusted publishing and provenance; no npm token exists.

## License

[Apache License 2.0](../../LICENSE).
