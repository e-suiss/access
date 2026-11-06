# esuiss-access-sdk

The Access SDK for Rust: the enforcement side of an Access decision. A service asks Access before an effect and applies the answer before the effect; a resource server verifies an authority token before it serves. Anything other than a verified ALLOW for this intent, this audience and this actor is a DENY. There is no fail-open setting, and none can be added without changing the SDK's types.

It builds on the open [`esuiss-access-kernel`](https://crates.io/crates/esuiss-access-kernel) and [`esuiss-crypto`](https://crates.io/crates/esuiss-crypto) only, is `no_std` + `alloc`, and does no I/O of its own.

## Modules

- **`authorize`.** The policy enforcement point. `Pep::authorize` builds an Exercise Request for one intent with the actor Instance's own signed statement, sends it through your decision port, verifies the signed Decision Receipt under the domain's operational key (domain, audience = you, intent digest, the Exercise of your nonce, time), and returns `Authorized<R, A>`: a value that only exists after that check, is typed by resource and action, carries the ExerciseID, the intent digest and the position the decision reflects, and is consumed by the one effect it authorizes. `Authorized::apply` compares the digest of the body about to run with the approved intent first.
- **`resource`.** The resource server. `ResourceServer::verify` takes an RFC 9068 access token whose authority is in RAR `authorization_details`, checks the DPoP proof (or mTLS thumbprint) with your replay and nonce ports, the realm JWKS within the `key_epoch` window, the Kernel token profile (one `aud` = you, this issuer, this domain, `cnf`), the ValidityContract view, the Token Status List entry within Δ, locally known revocations, introspection under the strict profile, and exact-intent single use. It returns the same `Authorized<R, A>` plus what the token proved. The verified value holds no token: nothing can be passed through.
- **`transport`.** The `Answer`/`Response`/`Fault` types your I/O hands back, and the `Clock` port.

## Ports

Every I/O is a trait you implement over your HTTP client, cache and clock. The SDK decides; the port only reports.

| Port | Module | What it does |
|---|---|---|
| `Clock` | `transport` | Trusted time in Unix milliseconds; `None` means no trusted time, which is a DENY |
| `AskDecision` | `authorize` | Sends one Exercise Request (`adp_body` renders the AuthZEN body) and returns the raw answer |
| `KeySource` | `resource` | The realm JWKS, fetched now or as cached with its fetch time |
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
- a token for another audience, issuer or domain, without `cnf`, over 8 KiB, with a replayed or unbound DPoP proof, with a missing or stale JWKS, with a set, stale or unreachable status list, an inactive or unreachable introspection, or presented a second time when exact-intent;
- a decision or projection older than the position the protected content was written at.

`Denied::class()` and `Denied::is_decision()` tell an explicit refusal from an unknown state, so your logs can; your effect cannot tell them apart, because neither produces an `Authorized`.

## Profiles

`Profile::Strict` introspects every request; `Profile::Fast` accepts a JWT whose horizon is at most 5 minutes with its status list. Neither skips the signature, audience, confirmation, contract or status checks. The profile is a type, not a flag.

## Conformance

The repository's `access-pep-conformance` harness runs this SDK as an adapter against every fault case, and must see no effect on any of them.

## License

[Apache License 2.0](../../../LICENSE).
