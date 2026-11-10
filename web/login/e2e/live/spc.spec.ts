// §9.4.1, OP-156 m.3 (g), OP-153 m.3 (gg): Secure Payment Confirmation against the running local
// deployment through its real router, with Chromium's virtual authenticator; nothing is mocked.
// The surface refuses a payment.get assertion without a started flow and keeps payment closed on
// the sign-in pages.
import { expect, test } from "@playwright/test";

const REALM = process.env["ACCESS_LIVE_REALM"] ?? "/realms/acme";
// The local deployment's realms do not decide idp.realm.spc.
const NO_SPC_REALM = process.env["ACCESS_LIVE_NO_SPC_REALM"] ?? REALM;

test.describe("@live secure payment confirmation", () => {
  test("@live the approval surface takes a payment.get assertion only for a started flow", async ({
    page,
  }) => {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    });
    const login = await page.goto(`${REALM}/login`);
    expect(login?.status()).toBe(200);
    expect(login?.headers()["permissions-policy"]).toContain("payment=()");
    const origin = new URL(page.url()).origin;
    // OP-156 m.3 (g): a realm without idp.realm.spc keeps payment closed on its payment page too
    const pay = await page.goto(
      `${NO_SPC_REALM}/login?reason=pay&request=urn:x&redirect_uri=x&state=s`,
    );
    expect(pay?.status()).toBe(200);
    expect(pay?.headers()["permissions-policy"]).toContain("payment=()");
    const start = await page.request.post(`${REALM}/v1/approve/flows`, {
      data: { request: "urn:x", redirect_uri: "https://shop.example/a", state: "s" },
      headers: { origin, "idempotency-key": crypto.randomUUID() },
    });
    expect(start.status()).not.toBe(501);
    expect(start.status()).toBeGreaterThanOrEqual(400);
    const finish = await page.request.post(`${REALM}/v1/approve/flows/AAAAAAAAAAAAAAAAAAAAAA`, {
      data: { credential: {}, redirect_uri: "https://shop.example/a", state: "s" },
      headers: { origin, "idempotency-key": crypto.randomUUID() },
    });
    expect(finish.status()).toBeGreaterThanOrEqual(400);
  });
});
