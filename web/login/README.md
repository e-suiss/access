# Hosted sign-in pages

The realm's own sign-in pages, served by Access at `/login` on the realm's public address (or `/realms/<slug>/login` for a path issuer). They draw what the server's node contract sends and nothing else: no template, no script from the realm, no third-party code.

## Pages

- **Sign in** — identifier first, passkey offered next to it, password or e-mail code or link when the realm allows them; "Keep me signed in on this device" and "Don't ask for a second step on this device for 30 days" are step options; the realm's social providers are buttons.
- **Create an account** — `/login?reason=create`.
- **Get back into your account** — `/login/recovery`, with the waiting period's end date when recovery cools down.
- **Sign-in link** — `/login/link`: opening the link changes nothing until you confirm.
- **Invitation** — `/login/invitation/<code>`: the organization's name is shown as plain text.
- **Share with an app** — `/login?reason=share`: lists the profile details the app asks for; "Don't share" goes back to the app.
- **Error** — `/login/error`: says who can fix the problem and shows a short reference, never a raw error code.

## Branding and security

The realm's name, logo and colours come from its theme record: the logo is an image from an origin the record lists, the colours arrive as a generated style sheet. Every page carries a strict Content Security Policy with `frame-ancestors 'none'`, and violation reports go to the realm's `/csp-reports`.

## Accessibility

WCAG 2.2 AA: paste and autofill always work, codes go into one field, status and errors are announced, focus follows the step, and the pages work right to left (`?ui_locales=ar-XB`). Every page runs axe in the end-to-end tests.

## Develop

```sh
npm ci
npm run lint && npm run typecheck && npm run format:check
npm run e2e        # against a mocked server
npm run e2e:live   # @live: against a running local deployment (ACCESS_LIVE_ORIGIN)
```

## License

Apache-2.0.
