# Account pages

The realm's own account pages, served by Access at `/account` on the realm's public address (or `/realms/<slug>/account` for a path issuer). They carry the realm's name, not a Suiss shell, and they reuse the hosted sign-in session.

## Sections

- **Account** — privacy (what the realm may contact you about, the documents you accepted, your security history, a scheduled deletion and your data requests). These screens use the session cookie only and never touch authority. Sign-in methods and sessions live in `src/account` and `src/signins`.
- **Authority** — _Your authority_, _Acting for you_, _Shared from you_, _Activity_ and _Changes_, with **Why?** and **Revoke** on every row you can act on. A role your HR source selects you for says "Sync from HR".
- **Merchants that can charge you** — every merchant holding a payment delegation from you, a merchant's agent shown as "AI agent · acting for _M_", the limit as Access recorded it, and **Stop charges**, which revokes the delegation. Payment agreements are Pay's and are cancelled in Pay, as a separate step.
- **Save my card** (`/account/save-card`) — opened from a merchant's request: "Let _M_ charge your card: up to 500 TRY per order, until …, only for orders you place", read from the exact Grant the request asks for. Saving it is your own delegation to the merchant from your own account, never passed on; a request without a per-order limit or an end is refused.
- **One-time payment** (`/account/payment`) — opened from a merchant's request: it shows "Pay 300 TRY to _M_ once" exactly as the request's bytes say and sends your own payment, never a delegation. A request that would let the merchant charge you again is refused.

## How the Authority screens stay honest

- **This device signs.** Setting up the device creates a key in the browser that cannot be exported; the page shows the decoded request before anything is signed. A cookie on its own reads and changes nothing.
- **Owner and time on every row.** Rows say who recorded them and when they were read. A place that does not answer is "Current status unknown", never empty.
- **Two steps to revoke.** Revoke opens what it changes and the request to sign; Revoke again sends it.
- **Done only when recorded.** The page shows "Submitted" until Access answers, "Not confirmed — checking" when the answer is lost, and retries with the very same signed request. It never shows an unknown outcome as done or as not recorded.
- **Changes are information.** Nothing in Changes asks you to act.
- **Two limits, two rows.** A limit Access records and a limit your bank or Pay sets are separate rows, each with its owner; neither is worked out from the other.
- **Degraded states are said plainly.** When notifications are delayed the page says so and what you changed still reads as done; when Access can't be reached it says authority can't be changed right now and that the runtime can still be asked to stop.

Texts come from Access's Fluent catalogs in `locales/`, with the realm's overrides where allowed.

## Develop

```sh
npm ci
npm run lint && npm run typecheck && npm run format:check
npm run e2e        # against a mocked BFF
npm run e2e:live   # @live: against a running local deployment
```

`npm run e2e:live` expects the local deployment on `https://access-server:8443` (`ACCESS_LIVE_ORIGIN`) and the bootstrap test user's password in `ACCESS_LOCAL_TEST_PASSWORD`.

## License

Apache-2.0.
