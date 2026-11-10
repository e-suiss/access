# access-identity-events

Event delivery of the Access identity plane: the Security Event Token (SET) transmitter, the
Shared Signals Framework (SSF) receiver, and the Suiss webhook profile.

Events are signals, not security. A receiver re-queries after an event; a lost, late or
reordered event never widens anything, and decisions rest on declared validity windows.

## Transmitter

- **Sources.** The identity outbox (tenant, organization, API client events and the identity
  plane's own security signals) and each authority domain's outbox (Access semantic events such
  as `authority-revoked` or `acceptance-changed`).
- **Channels.** One per stream: SSF push (RFC 8935), SSF poll (RFC 8936), or the webhook profile
  (CloudEvents 1.0 structured JSON signed per Standard Webhooks).
- **SET rules.** Exactly one event per SET, `sub_id` per RFC 9493, `txn`, `typ: secevent+jwt`, no
  top-level `sub`, no `exp`. Event ids are keyed or random, never a hash of the subject.
- **Algorithm.** A stream may ask for `alg`; ES256 is the default. RS256 is refused with
  `unsupported_alg` until a realm can hold an RSA signing key.

### CAEP and RISC events

| Event | Raised when |
|---|---|
| CAEP `session-revoked` | sign-out, a `session_epoch` step, an inbound `session-revoked` |
| CAEP `credential-change` | a password, passkey or TOTP is added, replaced or removed |
| CAEP `assurance-level-change` | a step-up reaches a level |
| CAEP `token-claims-change` | a claim mapper changes, for every subject with a live grant |
| CAEP `device-compliance-change` | a device Instance ends |
| CAEP `risk-level-change` | the SL2 risk signals report a level through `RiskLevels` |
| CAEP `session-established` | a login session starts |
| CAEP `session-presented` | a client redeems a code against a login session |
| RISC `account-disabled` | an account can no longer sign in |
| RISC `account-purged` | an account is crypto-shredded (the erasure flow is not built yet) |
| RISC `identifier-recycled` | an identifier moves to another account (identifier release is not built yet) |
| RISC `credential-compromise` | a realm signing key is dropped as compromised (realm-wide) |

A subject is named by the receiver's own pairwise `sub` (`iss_sub`), and only when the receiver
already has one: a receiver never learns of a subject it was not given. Each receiver's copy has
its own `jti` and `txn`, so receivers cannot link their copies.

### Access events and their CAEP counterparts

| Access event | CAEP type | Note |
|---|---|---|
| `instance-terminated` | `session-revoked` | approximate |
| `authority-narrowed` | `token-claims-change` | approximate |
| `revalidation-required` | `assurance-level-change` | approximate |
| `authority-revoked` | none | Access namespace only |

A stream's `profile` decides how an Access event with a counterpart is sent: `both` (default)
sends both, `caep` sends the counterpart instead, `access` sends the Access event alone. The
table lives in `domain::mapping`.

## Receiver

An upstream transmitter is declared with `idp.upstream.register` (issuer, JWKS URI, expected
audience, event types, optional RFC 8936 poll endpoint and credential, expected interval).

- **Push** to `POST /ssf/inbound/{stream}` with `application/secevent+jwt`: verified under the
  transmitter's keys (ES256 or RS256), `iss`, `aud`, `iat` within five minutes, one declared
  event; `202` on accept, an RFC 8935 error body otherwise. A `jti` is taken once.
- **Poll** for transmitters that only offer RFC 8936, with acknowledgements on the next request.
- **Effects.** An inbound event is a Claim: `session-revoked` ends the linked subject's sessions
  and steps its `session_epoch`; credential, risk and device events become narrowing
  `risk_signal` Claims; `account-disabled` an `account_status` Claim. No inbound event revokes a
  Grant, and an event about a subject the realm cannot link does nothing.
- **Delay.** A transmitter silent past its expected interval is reported as delayed:
  "Signals from *Provider* delayed since 14:02 UTC — decisions use declared validity windows".

## Acknowledgements

Delivery (a push `2xx` or a poll `ack`), semantic (`POST /ssf/ack` with `{"jti", "state":
"applied" | "ignored"}`) and authority-state acknowledgements are recorded apart and counted for
the staleness view.

## Webhooks

A realm's administrator registers a webhook (an HTTPS URL and the events it wants) through the
management API's `webhooks` resource, as an `idp.webhook.register` decision. Access then
delivers every matching event to that URL.

### What a delivery looks like

Each delivery is a `POST` with a [CloudEvents 1.0](https://cloudevents.io) structured JSON body
(`application/cloudevents+json`) and the [Standard Webhooks](https://www.standardwebhooks.com)
headers:

```http
POST /access-events HTTP/1.1
Content-Type: application/cloudevents+json; charset=utf-8
webhook-id: AQMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
webhook-timestamp: 1793750400
webhook-signature: v1a,fldxM4gAKugP6nnt1hdz3sgGfZ6d99nzrMFnZOELIxbzEHoVmAb2ADpkJK7zgPePmPsle0zV9jSeGlHFG2NVAw==

{"specversion":"1.0","id":"AQMx…","source":"urn:suiss:access:realm:…",
 "type":"urn:suiss:access:event:account.created","time":"2026-11-04T00:00:00.000Z",
 "data":{"iss":"https://id.example/realms/shop","jti":"AQMx…",
         "events":{"urn:suiss:access:event:account.created":{"realm":"…","account":"usr_…","at":1793750400000}}}}
```

- `id` equals `webhook-id` and the event's `jti`: deduplicate by it.
- `data` carries ids only (`usr_…`, `tnt_…`, UUIDs), never an e-mail address, a name or a secret.
- The schema of every event is in [`sdks/openapi/events`](../../sdks/openapi/events), with an
  example under `examples/`.

### Verifying a delivery

The signature covers `webhook-id + "." + webhook-timestamp + "." + body`.

- `v1a` (default): Ed25519. Registration shows the public key once as `whpk_<base64>`; verify with
  it. Access never holds a secret the receiver needs.
- `v1` (compatibility): HMAC-SHA-256. Registration shows the secret once as `whsec_<base64>`.

Any Standard Webhooks library verifies `v1`; for `v1a` verify the Ed25519 signature over the same
content. Reject a timestamp more than five minutes from your clock. A header may carry several
space-separated signatures: during a key rotation the old key keeps signing next to the new one
for 24 hours, so accept a delivery when any signature verifies with a key you hold. The same
profile is used by Relay, so one verifier accepts both products. Test vectors:
[`conformance/vectors/webhook/1/signature.json`](../../conformance/vectors/webhook/1/signature.json).

### Delivery guarantees

- **At least once.** Answer `2xx` within 10 seconds. Anything else, or no answer, is retried:
  after 1 minute, then doubling up to 24 hours between attempts, for 7 days. After that the
  delivery is `exhausted`.
- **No ordering.** A later event can arrive before an earlier one. Order by the CloudEvent
  `time`, deduplicate by `webhook-id`.
- **Isolation.** One failing endpoint never delays another endpoint's deliveries.
- **A notification, not a decision.** A lost or late delivery changes no Access decision:
  suspending an account ends its sessions at once whether or not the webhook arrives. To act on
  current state, ask Access.
- Each attempt is logged with its status and latency; request and response bodies are not kept.

### Events

| Event | When |
|---|---|
| `account.created` | an account is created |
| `account.updated` | an account's status moves otherwise (for example unlocked) |
| `account.suspended` | an administrator suspends an account |
| `account.reactivated` | a suspended or deprovisioned account is active again |
| `account.deleted` | an account is deprovisioned |
| `session.revoked` | every session of an account ended |
| `credential.changed` | a password, passkey or second factor is added, replaced or removed |
| `membership.added`, `membership.removed` | an account joins or leaves an organization |
| `preference.changed` | an account's preferences change (topics only, never values) |
| `document.accepted` | an account accepts a version of a document |
| `agent.suspended` | an agent is suspended |
| `agent.sponsor_assigned` | a person becomes an agent's sponsor |
| `login.failed_surge` | failed sign-ins in a realm rise above the surge threshold |
| `scim.provisioned` | a SCIM client creates, changes or reactivates a user, group or device |
| `scim.deprovisioned` | a SCIM client deletes or deactivates one; the account is kept as a tombstone |
| `org.sso_enforced` | an organization starts signing in only through its own identity provider |
| `hr.record_due` | a future-dated HR start or end reaches its date |
| `proxy.registered` | a proxy becomes a policy enforcement point of the realm |
| `ssh.certificate_issued` | the realm's SSH certificate authority issues a certificate |
| `export.sink_failed` | an export sink stops accepting the audit copy |

The tenant, organization and API client events of the catalogue (`tenant.created`,
`organization.*`, `api_client.*`) and the authority events reach subscribers through streams.

`organization.created` and `membership.*` are raised by organization creation, membership
removal and invitation acceptance. `agent.suspended` and `agent.sponsor_assigned` have a schema
but no producer yet; a webhook or stream that names them is refused (`invalid-webhook-events`,
`unsupported-event`) until the agent registry raises them.

`scim.provisioned`, `scim.deprovisioned` and `org.sso_enforced` are catalogued and refused the
same way until the SCIM server and SSO enforcement raise them.

`ssh.certificate_issued` is raised by the realm's SSH certificate authority for each
certificate it issues, and `export.sink_failed` by the export pass once a sink has refused three
batches in a row. `hr.record_due` and `proxy.registered` are catalogued and refused the same
way until the HR job and proxy registration raise them. `preference.changed` may carry an `iys` member naming
the commercial message channels a change touched, for realms that record consent with İYS.
