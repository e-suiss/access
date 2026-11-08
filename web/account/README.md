# Account pages

The realm's own account pages, served by Access at `/account` on the realm's public address (or `/realms/<slug>/account` for a path issuer). They carry the realm's name, not a Suiss shell, and they reuse the hosted sign-in session.

## Sections

- **Account** — privacy (what the realm may contact you about, the documents you accepted, your security history, a scheduled deletion and your data requests). These screens use the session cookie only and never touch authority. Sign-in methods and sessions live in `src/account` and `src/signins`.
- **Authority** — _Your authority_, _Acting for you_, _Shared from you_, _Activity_ and _Changes_, with **Why?** and **Revoke** on every row you can act on.

## How the Authority screens stay honest

- **This device signs.** Setting up the device creates a key in the browser that cannot be exported; the page shows the decoded request before anything is signed. A cookie on its own reads and changes nothing.
- **Owner and time on every row.** Rows say who recorded them and when they were read. A place that does not answer is "Current status unknown", never empty.
- **Two steps to revoke.** Revoke opens what it changes and the request to sign; Revoke again sends it.
- **Done only when recorded.** The page shows "Submitted" until Access answers, "Not confirmed — checking" when the answer is lost, and retries with the very same signed request. It never shows an unknown outcome as done or as not recorded.
- **Changes are information.** Nothing in Changes asks you to act.

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
