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
