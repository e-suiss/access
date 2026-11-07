# PEP conformance

A policy enforcement point (PEP) guards an effect: it asks Access, or checks a token, and
performs the effect only on a verified ALLOW. This harness checks that no upstream fault turns
into an effect. It is language independent: the PEP under test is wrapped in a small adapter
that speaks JSON lines on stdin and stdout.

```sh
just pep-conformance                       # self-test: reference and the Rust SDK pass, negative control is flagged
just pep-conformance "node my-adapter.js"  # your adapter
```

or directly:

```sh
cargo run -p access-pep-conformance -- --sut "<command>" [--cases conformance/pep/cases] \
  [--deadline-ms 500] [--grace-ms 2000] [--json report.json]
```

Exit status: `0` every case passed, `1` at least one case failed, `2` the run itself failed
(adapter did not start, broke the protocol, bad case file).

## How a run works

1. The runner generates a domain for the run (binding key, operational keys for receipts,
   tokens and status lists, the holder key tokens are bound to) and starts fake upstreams on
   `127.0.0.1`: an ADP (AuthZEN evaluation), an OAuth introspection endpoint, a JWKS, a Token
   Status List and the protected resource. Receipts are signed per request for the nonce the
   PEP sent; tokens are real `at+jwt` projections with `cnf`, `authorization_details`,
   `access_contract`, `family` and `status`.
2. It starts the adapter with `sh -c "<command>"` and exchanges one line per case.
3. For each case the adapter makes its PEP enforce one request against that case's upstreams,
   `repeat` times when the case says so. If the PEP allows, the adapter performs the effect by
   calling the resource. The resource counts effects, so the verdict does not depend on what
   the adapter claims.

## Cases

`cases/*.json`, one fault per file. The file name is the case ID.

| Field | Meaning |
|---|---|
| `id` | Case ID, equal to the file name |
| `rules` | Spec rule IDs the case checks |
| `description` | One sentence |
| `mode` | `decision` (ADP with signed receipt), `introspection` (opaque token, RFC 7662) or `jwt` (JWT access token with JWKS and Token Status List) |
| `audience`, `intent` | Override the PEP audience or the intent digest (hex of its CBOR) |
| `adp`, `introspection`, `jwks`, `status_list` | How that upstream answers; healthy when absent |
| `kind` | `intent` (default) or `bounds`: the token's RAR kind (`introspection`, `jwt`) |
| `dpop` | `fresh` (default), `replayed` (the same proof every time), `missing` (a bearer presentation) or `other-key` (a proof not of the token's `cnf.jkt`) |
| `token` | `oversized` (padded past 8 KiB) or `other-audience` (issued for another resource server) |
| `repeat` | How many times the same token is presented (default 1); the effect may happen at most once |
| `expect` | `effect`, `deny` or `no-effect` |

Upstream answers (`kind`):

| `kind` | Fields | Answer |
|---|---|---|
| `status` | `status` | That status with an RFC 9457 problem body |
| `raw` | `status`, `body` | A literal body, not necessarily JSON |
| `json` | `status`, `body` | A literal JSON body |
| `hang` | | Accepts the request and never answers |
| `decision` | `decision`, `receipt` | ADP only: AuthZEN answer, with or without `context.receipt` |
| `keys` | | JWKS only: the token and status list signing keys. The same case reply also governs `upstream.metadata`, which serves the binding-signed Domain Metadata when healthy |
| `list` | `stale`, `revoked` | Status list only: a signed list, expired or not, the token's bit set or not |

Expected effects:

| `expect` | Passes when |
|---|---|
| `effect` | The adapter answers `allow` and the resource saw exactly one effect. One control case per mode makes sure the adapter really talks to the upstreams. With `repeat`, a second effect is a leak: a replayed proof or a reused exact-intent token got through. |
| `deny` | The adapter answers `deny` and the resource saw no effect. Used for negative evidence: a DENY decision, a missing or mismatched receipt, an inactive or revoked token. |
| `no-effect` | The adapter answers `deny` or `error` and the resource saw no effect. Used for unknown states: 5xx, timeouts, malformed bodies, stale status lists. |

Any effect, or an `allow` answer, on a `deny` or `no-effect` case is reported as `LEAK`.

## Adapter protocol `access-pep-conformance/1`

One JSON object per line. The runner writes to the adapter's stdin and reads its stdout;
stderr is passed through for logs.

Handshake:

```json
{"type":"hello","protocol":"access-pep-conformance/1"}
{"type":"ready","protocol":"access-pep-conformance/1","name":"my PEP 1.2.0"}
```

Each case:

```json
{"type":"case","case":"adp-503","now":37800000,"deadline_ms":500,
 "pep":{"audience":"pep.example","domain":"822f5820…","metadata":"a966…","issuer":"http://127.0.0.1:53111/adp-503"},
 "upstream":{"adp":"http://127.0.0.1:53111/adp-503/access/v1/evaluation",
             "introspection":"http://127.0.0.1:53111/adp-503/introspect",
             "jwks":"http://127.0.0.1:53111/adp-503/jwks",
             "metadata":"http://127.0.0.1:53111/adp-503/metadata",
             "effect":"http://127.0.0.1:53111/adp-503/effect"},
 "request":{"mode":"decision","intent":"822f5820…","evaluation":{"subject":{…},"action":{…},"resource":{…},"context":{…}}}}
```

| Field | Meaning |
|---|---|
| `now` | Trusted time in Unix milliseconds. The adapter uses it instead of its own clock, so runs are deterministic. |
| `deadline_ms` | Upstream calls of this case give up after this long. The runner waits `deadline_ms` plus a grace period for the result. |
| `pep.audience` | The PEP's own audience identifier |
| `pep.domain`, `pep.metadata` | The pinned domain ID and verified Domain Metadata (hex CBOR), as the PEP would be configured |
| `pep.issuer` | The expected `iss` of JWT access tokens |
| `request.mode` | Which upstreams protect the effect |
| `request.intent` | The intent digest (hex CBOR) the effect applies; a receipt must be bound to it |
| `request.evaluation` | The AuthZEN evaluation body to send to `upstream.adp` |
| `request.token` | The access token in `introspection` and `jwt` modes. A JWT carries `status.status_list.{idx,uri}`; the status list is fetched from that `uri`. |
| `request.method`, `request.uri` | The request the token is presented with, as the resource server sees it: what the `DPoP` proof's `htm` and `htu` must match |
| `request.proofs` | The `DPoP` proofs, one per presentation, in order; empty when the request carries none |
| `request.repeat` | How many times to present the token (default 1); each presentation uses the proof at its index |

What the PEP does per mode:

- `decision`: `POST upstream.adp` with `request.evaluation`, whose `context.nonce` is the
  request nonce. Allow only on `decision: true` with `context.receipt` (`sign1`, `excerpt`,
  base64url) that verifies with the Kernel against the pinned Domain Metadata for this
  domain, audience, intent and `now`, and names the Exercise of that nonce.
- `introspection`: `POST upstream.introspection` (`application/x-www-form-urlencoded`,
  `token=…`). Allow only on `active: true`, `aud` naming the PEP and `exp` after `now`; a
  resource server SDK also checks `cnf` against the `DPoP` proof and reads
  `authorization_details` and `as_of`.
- `jwt`: get the token key, verify the token (`alg` `Ed25519`, `kid` the key's thumbprint,
  `typ` `at+jwt`, `iss`, one `aud`, `exp`, `iat`, `cnf.jkt` = the proof's key, 8 KiB ceiling),
  check the `DPoP` proof of this presentation against replay, refuse a second presentation of
  an exact-intent token, then `GET` the status list (`typ` `statuslist+jwt`, signed by the
  domain's status list key), which must not be expired, and check the token's bit. A plain
  PEP may read the keys from `GET upstream.jwks`; an Access SDK resolves them from
  `GET upstream.metadata` (`application/access-domain-metadata+cbor`, signed by a binding key
  of the pinned metadata), taking only a key declared for `token` (or `status-list`) whose
  window holds the artefact's `iat`.

The effect is `POST upstream.effect`. Then the adapter answers:

```json
{"type":"result","case":"adp-503","outcome":"error","detail":"upstream answered 503"}
```

`outcome` is `allow` (effect performed), `deny` or `error` (no effect). `detail` is free text
for the report. After the last case the runner sends `{"type":"bye"}` and stops the process.

## Self-test

The runner ships three adapters:

- `pep-reference` is a small fail-closed PEP and passes every case.
- `pep-sdk` is the Rust PEP SDK (`esuiss-access-sdk`) with its ports bound to blocking HTTP;
  it passes every case.
- `pep-reference-leaky` is a negative control: it treats upstream faults as permission,
  ignores receipts, proofs and status list freshness. The runner must flag it.

`just pep-conformance` with no argument runs all three. The crate's tests run the reference
cases in process with paused time, so timeouts end exactly at the deadline, and the three
adapters as child processes.
