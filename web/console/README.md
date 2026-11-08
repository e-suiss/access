# Access Console

The administration console of Access: a React and TypeScript single-page app, served by the
console's Backend-for-Frontend (BFF) at `/console` on the management listener, an origin of
its own, apart from every realm's sign-in pages.

## Architecture

```
browser                                  management listener (access-server)
┌──────────────────────────────┐         ┌──────────────────────────────────────────┐
│ console (this package)       │ cookie  │ /console/api/*   BFF (crates/http/console)│
│  Kernel (WebAssembly)        │───────▶ │   session, CSRF, own profile & sign-ins  │
│  device key (WebCrypto,      │ + AIS   │   /proxy/admin/* ──▶ /admin/v1/*          │
│  non-extractable, IndexedDB) │         │   /proxy/adp/*   ──▶ /access/v1/*         │
└──────────────────────────────┘         └──────────────────────────────────────────┘
```

- **Sign-in.** The console sends you to your realm's hosted login and the BFF opens a console
  session when you come back.
- **Session.** One cookie, `__Host-access-console`: `Secure`, `HttpOnly`, `SameSite=Strict`,
  host-only. A console session lasts at most 12 hours, ends after 15 minutes without use, and is
  bound to the network you signed in from (your autonomous system when a GeoIP source is
  configured, otherwise your /24 or /48; your exact address when the realm asks for it).
  The session row keeps a slot for a Device Bound Session Credentials key; until DBSC is
  implemented its endpoints answer `501`.
- **Device key.** On first use the console asks you to register this browser. It generates a
  P-256 key that cannot be exported, keeps it in IndexedDB, and registers it as your sign-in's
  device Instance through the device's own `instance_create` Exercise.
- **Signing.** Statements are encoded by the Kernel compiled to WebAssembly (no CBOR is written
  in TypeScript) and signed by WebCrypto. Before anything is signed for a change, the signature
  screen shows what the Kernel decoded from the very bytes about to be signed.

## What the cookie can and cannot do

| With the cookie alone                  | Needs this browser's device key                  |
| -------------------------------------- | ------------------------------------------------ |
| Navigate the console                   | Every change (an AIS the management API turns    |
|                                        | into an Exercise)                                |
| Read your own profile                  | Every authority read (a `check` AIS bound to the |
|                                        | request)                                         |
| List your sign-ins and end one of them | The Admin, Developer and Audit sections          |

A stolen cookie in another browser has no key: the admin proxy refuses it, and what the ADP
proxy forwards carries no credential of the BFF, so it reads as an anonymous reader and sees
public data only.

The BFF never holds an authority key. For reads it presents a management read token issued to
your device Instance, valid for at most 60 minutes, limited to read scopes and bound to a DPoP
key the BFF keeps for your session; it presents that token only after your browser has signed a
read proof for the exact request.

## Screens

Admin, Developer and Audit, and every screen inside them, appear only when the eligibility check
says you can exercise one of the screen's actions (IA-5); there are no disabled placeholders.
Authority reads go to ADP as your own `check`, signed in this browser; changes are drafted, shown
on the signature screen as the Kernel decoded them, and sent as one Exercise.

The BFF drafts every intent the console signs (`POST /console/api/intents`, a read that needs a
read proof): only an action of the server's catalogue, with its pinned schema digest, on your
realm's resources, or, for the decision lab's Check, an action your domain accepted, with the
schema digest the domain pinned, on a resource of its own namespace. A `check` draft also names
the eligibility check it belongs to (the domain, the root that covers the action's family as
basis, and capacity), and a screen appears when the eligibility check, run by the decision point
for your own Party, answers yes; a meta-action is asked without its payload and answered by
coverage alone. When you hold authority only by delegation, the console also asks on each of your
own holdings (the `holdings` search), so a delegated admin sees the screens its delegations cover.

Changes to authority are ADP Exercises. For a role version, a delegation's amend or revoke, a
departure, an Acceptance amend, a policy or an Instance end, the screen names the payload in its
JSON form; the BFF drafts the intent with the payload's digest and answers the payload bytes, the
Kernel decodes the drafted intent for the signature screen, and only then is the `commit` signed
in this browser and sent. A bulk change, such as moving role delegations to a new version, is one
Exercise per delegation, all shown on one signature screen, using the amend payloads the
change-impact preview lists. The BFF forwards `evaluation` and `audit/export` only when your
device key signed that commit, and never signs anything itself. Publishing a schema version is a
statement, not a change: it is sent with a `check` signed in this browser, and there is no accept
control anywhere — each domain accepts only by its own protected change.

| Section   | Screen                          | Reads and changes                                                         | Spec                       |
| --------- | ------------------------------- | ------------------------------------------------------------------------- | -------------------------- |
| Admin     | Roles & templates               | role editor that saves versions; preview and bulk move; admin delegation  | §8.17.9.2, X20, E11        |
| Admin     | People & agents                 | accounts (suspend, reactivate); own holdings; running copies' impact      | X31, §8.17.7.4, OP-142     |
| Admin     | Sources                         | uses of a source; `schema-publications` waiting here, no accept control   | §8.17.9.3, §8.17.10.2, X21 |
| Admin     | Restrictions & requirements     | what restrictions and requirements are; no stop-all control               | §8.17.7.5                  |
| Admin     | Protected actions & break-glass | protected actions, emergency access as a delegation                       | §8.17.9.4                  |
| Admin     | Offboarding                     | keep or revoke for each delegation, no default; end running copies        | §8.17.9.6, E6              |
| Admin     | Domain                          | constitution, provider, partner authority ceilings                        | §8.17.9.7, §5.13           |
| Admin     | Changes                         | what changed, at your depth; information only                             | IA-2                       |
| Admin     | History                         | every recorded change, grouped by the record that made it                 | §8.17.9.1                  |
| Admin     | Organizations                   | roots, members by membership source, domains, owner handovers, drafts     | §8.5 S7, §12.3.8           |
| Admin     | Sign-in settings                | settings, branding, RP ID, apps, upstreams, keys, signals, analytics      | E34, TN-17, TN-111, §8.13  |
| Developer | Namespaces & schemas            | publish a version; "Pending acceptance in: …"; no accept control          | §8.17.10.2, E10–E12, X21   |
| Developer | Integrations                    | apps, hooks, webhooks                                                     | §8.11                      |
| Developer | Decision lab                    | advisory Check and Explain; sandbox domains listed as domains             | §8.17.10.4, E-2, D7        |
| Developer | Logs                            | a recorded event at viewer depth; audit-only chain link warning           | §8.17.10.3, §9.9.2         |
| Audit     | Records                         | a record at audit depth (`reason_admin`, StateBasis, `basis_ref`); search | OP-151 m.8 (d), (e), (g)   |
| Audit     | Replay                          | a recorded decision evaluated again; match or mismatch                    | INV-27                     |
| Audit     | Revocation impact               | `revocation-impact`: subtree, exposure, aftermath, where it took effect   | §5.4, §8.17.7.3, §9.12.3   |
| Audit     | Unknown outcomes                | `compromise-impact`: uses in a window, "Result unknown"                   | RR-13, EI-22               |
| Audit     | Containment                     | each step (end a running copy, revoke) its own signed change              | §8.6, §8.13                |
| Audit     | Export                          | an `access.audit_export` Exercise, signed here                            | OP-151 m.8 (b)             |

Explanations show a reason by its class and what is needed (§8.17.8); policy content, thresholds
and statement bodies are never rendered, deeper identities stay pseudonymous, and an unknown
subcode reads as its class.

## Security headers

Every page, asset and API answer carries a strict Content Security Policy (`default-src 'none'`,
scripts and styles from the console itself, `'wasm-unsafe-eval'` for the Kernel only, Trusted
Types enforced, no framing), `Referrer-Policy: no-referrer`, cross-origin isolation and a minimal
`Permissions-Policy`. Strings a tenant controls (realm and display names, client names) are
rendered as text only; ESLint and `cargo xtask check` (`ui-text-nodes`) refuse HTML sinks, and
`forbidden-ui-terms` keeps words the console must never use out of its strings.

## Development

```sh
just wasm                    # the Kernel's WebAssembly build for @esuiss/access
npm ci
npm run lint && npm run typecheck
npm run e2e                  # Playwright: shell, signing, stolen cookie, security, WCAG 2.2 AA
npm run e2e:live             # @live: against the local deployment's management listener
```

The end-to-end tests run against a mock of the BFF that applies the BFF's rules; the BFF itself
is tested in `crates/http/tests/console.rs`. Strings live in `src/i18n/en.ts`, with the same keys
in `src/i18n/tr.ts`.
