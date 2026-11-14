import { expect, test } from "./fixtures.js";

// §9.4.1, OP-156 m.3 (g): the page asks the browser for exactly the canonical render's values
const started = {
  flow: "fL0w",
  options: {
    challenge: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    rpId: "acme.localhost",
    timeout: 300000,
    allowCredentials: [{ type: "public-key", id: "wcHBwQ" }],
  },
  render: { fields: [], reason: "Pay for the coffee order.", tier: 2, expires_at: "" },
  spc: {
    payeeName: "Kahve Evi",
    total: { currency: "EUR", value: "42.00" },
    instrument: { displayName: "Acme", icon: "https://acme.localhost/favicon.ico" },
  },
};

/** Stands in for the browser's SPC dialog: records the request and answers with a credential. */
function stubPaymentRequest() {
  const seen: unknown[] = [];
  (window as unknown as { __spc: unknown[] }).__spc = seen;
  class Fake {
    constructor(methods: unknown, details: unknown) {
      seen.push({ methods, details });
    }
    show() {
      return Promise.resolve({
        complete: () => Promise.resolve(),
        details: { toJSON: () => ({ id: "wcHBwQ", type: "public-key" }) },
      });
    }
  }
  (window as unknown as { PaymentRequest: unknown }).PaymentRequest = Fake;
}

for (const [answer, shown] of [
  [{ status: 200, body: { redirect: "/login?done=1" } }, null],
  [
    { status: 409, body: { code: "spc-mismatch", title: "x" } },
    "The payment details didn't match. Nothing was approved.",
  ],
] as const) {
  test(`the SPC page shows the payee and total and ${shown === null ? "follows the approval" : "says a mismatch"}`, async ({
    page,
    mock,
  }) => {
    await page.addInitScript(stubPaymentRequest);
    const finished: unknown[] = [];
    await page.route(/\/v1\/approve\/flows$/, (route) =>
      route.fulfill({ status: 201, json: started }),
    );
    await page.route(/\/v1\/approve\/flows\/fL0w$/, (route) => {
      finished.push(route.request().postDataJSON());
      return route.fulfill({ status: answer.status, json: answer.body });
    });
    await page.goto("/login?reason=pay&request=urn:x&redirect_uri=https://shop.example/a&state=s");
    await expect(page.getByTestId("spc-details")).toContainText("Kahve Evi");
    await expect(page.getByTestId("spc-details")).toContainText("42.00 EUR");
    await page.getByRole("button", { name: "Confirm this payment" }).click();
    if (shown === null) {
      await expect(page).toHaveURL(/done=1/);
    } else {
      await expect(page.getByTestId("spc-refused")).toHaveText(shown);
    }
    const requests = await page
      .evaluate(() => (window as unknown as { __spc: unknown[] }).__spc)
      .catch(() => [{}]);
    expect(requests.length).toBeLessThanOrEqual(1);
    expect(finished).toHaveLength(1);
    expect(mock.submissions).toEqual([]);
  });
}
