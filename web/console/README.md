# Access Console

The administration console of Access: a React and TypeScript single-page app, served by the
console's Backend-for-Frontend (BFF) under `/console/` on the management listener, an origin of
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

| With the cookie alone                         | Needs this browser's device key                  |
| --------------------------------------------- | ------------------------------------------------ |
| Navigate the console                          | Every change (an AIS the management API turns    |
|                                               | into an Exercise)                                |
| Read your own profile                         | Every authority read (a `check` AIS bound to the |
|                                               | request)                                         |
| List your sign-ins and end one of them        | The Admin, Developer and Audit sections          |

A stolen cookie in another browser has no key: the admin proxy refuses it, and what the ADP
proxy forwards carries no credential of the BFF, so it reads as an anonymous reader and sees
public data only.

The BFF never holds an authority key. For reads it presents a management read token issued to
your device Instance, valid for at most 60 minutes, limited to read scopes and bound to a DPoP
key the BFF keeps for your session; it presents that token only after your browser has signed a
read proof for the exact request.

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
```

The end-to-end tests run against a mock of the BFF that applies the BFF's rules; the BFF itself
is tested in `crates/http/tests/console.rs`. Strings live in `src/i18n/en.ts`, with the same keys
in `src/i18n/tr.ts`.
