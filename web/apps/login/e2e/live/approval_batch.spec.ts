// §13.7.3, §8.17.6.3, SEC26, OP-157 m.3 (m), Ek B 5478, 5632: the batch routes against the
// running local deployment through its real router; nothing is mocked.
import { expect, test } from "@playwright/test";

const REALM = process.env["ACCESS_LIVE_REALM"] ?? "/realms/acme";

test.describe("@live batch approval", () => {
  test("@live a batch without a session is refused and the route is served", async ({ page }) => {
    const login = await page.goto(`${REALM}/login`);
    expect(login?.status()).toBe(200);
    const origin = new URL(page.url()).origin;
    const started = await page.request.post(`${REALM}/v1/approve/batch`, {
      data: {
        requests: ["urn:ietf:params:oauth:request_uri:unknown"],
        redirect_uri: "https://shop.example/a",
        state: "s",
      },
      headers: {
        origin,
        "sec-fetch-site": "same-origin",
        "idempotency-key": crypto.randomUUID(),
      },
    });
    expect(started.status()).not.toBe(501);
    expect([401, 403, 422]).toContain(started.status());
    const eleven = await page.request.post(`${REALM}/v1/approve/batch`, {
      data: {
        requests: Array.from({ length: 11 }, (_, n) => `urn:x:${String(n)}`),
        redirect_uri: "https://shop.example/a",
        state: "s",
      },
      headers: {
        origin,
        "sec-fetch-site": "same-origin",
        "idempotency-key": crypto.randomUUID(),
      },
    });
    expect(eleven.status()).toBe(422);
    expect(((await eleven.json()) as { code: string }).code).toBe("approval-batch-invalid");
  });
});
